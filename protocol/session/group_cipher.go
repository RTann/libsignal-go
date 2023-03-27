package session

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/golang/glog"

	"github.com/RTann/libsignal-go/protocol/crypto"
	"github.com/RTann/libsignal-go/protocol/distribution"
	"github.com/RTann/libsignal-go/protocol/message"
	"github.com/RTann/libsignal-go/protocol/perrors"
	"github.com/RTann/libsignal-go/protocol/senderkey"
)

func (g *GroupSession) EncryptMessage(ctx context.Context, random io.Reader, plaintext []byte) (*message.SenderKey, error) {
	record, exists, err := g.SenderKeyStore.Load(ctx, g.Sender, g.LocalDistID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("no sender key state for distribution ID %s", g.LocalDistID.String())
	}

	state, err := record.State()
	if err != nil {
		return nil, err
	}

	senderChainKey := state.SenderChainKey()
	messageKeys, err := senderChainKey.MessageKeys()
	if err != nil {
		return nil, err
	}

	ciphertext, err := crypto.AESCBCEncrypt(messageKeys.CipherKey(), messageKeys.IV(), plaintext)
	if err != nil {
		return nil, err
	}

	signingKey, err := state.PrivateSigningKey()
	if err != nil {
		return nil, err
	}

	msg, err := message.NewSenderKey(random, message.SenderKeyConfig{
		Version:      uint8(state.Version()),
		DistID:       g.LocalDistID,
		ChainID:      state.ChainID(),
		Iteration:    messageKeys.Iteration(),
		Ciphertext:   ciphertext,
		SignatureKey: signingKey,
	})
	if err != nil {
		return nil, err
	}

	state.SetSenderChainKey(senderChainKey.Next())

	err = g.SenderKeyStore.Store(ctx, g.Sender, g.LocalDistID, record)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

func (g *GroupSession) DecryptMessage(ctx context.Context, ciphertext *message.SenderKey) ([]byte, error) {
	distributionID := ciphertext.DistributionID()
	chainID := ciphertext.ChainID()

	record, exists, err := g.SenderKeyStore.Load(ctx, g.Sender, distributionID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("no sender key state for distribution ID %s", distributionID.String())
	}

	state := record.StateForChainID(chainID)
	if state == nil {
		return nil, fmt.Errorf("no sender key state for distribution ID %s", distributionID.String())
	}

	messageVersion := ciphertext.Version()
	if uint32(messageVersion) != state.Version() {
		return nil, fmt.Errorf("unrecognized message version: %d", messageVersion)
	}

	signingKey, err := state.PublicSigningKey()
	if err != nil {
		return nil, err
	}

	valid, err := ciphertext.VerifySignature(signingKey)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, errors.New("signature verification failed")
	}

	messageKeys, err := g.messageKeys(state, ciphertext.Iteration(), ciphertext.DistributionID())
	if err != nil {
		return nil, err
	}

	plaintext, err := crypto.AESCBCDecrypt(messageKeys.CipherKey(), messageKeys.IV(), ciphertext.Message())
	if err != nil {
		return nil, err
	}

	err = g.SenderKeyStore.Store(ctx, g.Sender, g.LocalDistID, record)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (g *GroupSession) messageKeys(state *GroupState, iteration uint32, distributionID distribution.ID) (senderkey.MessageKeys, error) {
	chainKey := state.SenderChainKey()
	currentIteration := chainKey.Iteration()

	if currentIteration > iteration {
		keys, ok, err := state.RemoveMessageKeys(iteration)
		if err != nil {
			return senderkey.MessageKeys{}, err
		}
		if !ok {
			glog.Warningf("SenderKey distribution %s Duplicate message for iteration: %d", distributionID, iteration)
			return senderkey.MessageKeys{}, perrors.ErrDuplicateMessage
		}

		return keys, nil
	}

	jump := iteration - currentIteration
	if jump > MaxJumps {
		glog.Errorf("Sender distribution %s Exceeded future message limit: %d, iteration: %d", distributionID, MaxJumps, iteration)
		return senderkey.MessageKeys{}, errors.New("message from too far in the future")
	}

	for chainKey.Iteration() < iteration {
		keys, err := chainKey.MessageKeys()
		if err != nil {
			return senderkey.MessageKeys{}, err
		}
		state.AddMessageKeys(keys)
		chainKey = chainKey.Next()
	}

	state.SetSenderChainKey(chainKey.Next())

	messageKeys, err := chainKey.MessageKeys()
	if err != nil {
		return senderkey.MessageKeys{}, err
	}

	return messageKeys, nil
}
