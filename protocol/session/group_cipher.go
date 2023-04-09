package session

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/golang/glog"

	"github.com/RTann/libsignal-go/protocol/crypto/aes"
	"github.com/RTann/libsignal-go/protocol/distribution"
	"github.com/RTann/libsignal-go/protocol/message"
	"github.com/RTann/libsignal-go/protocol/perrors"
	"github.com/RTann/libsignal-go/protocol/senderkey"
)

func (g *GroupSession) EncryptMessage(ctx context.Context, random io.Reader, plaintext []byte) (*message.SenderKey, error) {
	record, exists, err := g.SenderKeyStore.Load(ctx, g.SenderAddress, g.DistID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("no sender key state for distribution ID %s", g.DistID.String())
	}

	state, err := record.State()
	if err != nil {
		return nil, err
	}

	senderChainKey := state.SenderChainKey()
	messageKey, err := senderChainKey.MessageKey()
	if err != nil {
		return nil, err
	}

	ciphertext, err := aes.CBCEncrypt(messageKey.CipherKey(), messageKey.IV(), plaintext)
	if err != nil {
		return nil, err
	}

	signingKey, err := state.PrivateSigningKey()
	if err != nil {
		return nil, err
	}

	msg, err := message.NewSenderKey(random, message.SenderKeyConfig{
		Version:      uint8(state.Version()),
		DistID:       g.DistID,
		ChainID:      state.ChainID(),
		Iteration:    messageKey.Iteration(),
		Ciphertext:   ciphertext,
		SignatureKey: signingKey,
	})
	if err != nil {
		return nil, err
	}

	state.SetSenderChainKey(senderChainKey.Next())

	err = g.SenderKeyStore.Store(ctx, g.SenderAddress, g.DistID, record)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

func (g *GroupSession) DecryptMessage(ctx context.Context, ciphertext *message.SenderKey) ([]byte, error) {
	distributionID := ciphertext.DistributionID()
	chainID := ciphertext.ChainID()

	record, exists, err := g.SenderKeyStore.Load(ctx, g.SenderAddress, distributionID)
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

	messageKey, err := g.messageKey(state, ciphertext.Iteration(), ciphertext.DistributionID())
	if err != nil {
		return nil, err
	}

	plaintext, err := aes.CBCDecrypt(messageKey.CipherKey(), messageKey.IV(), ciphertext.Message())
	if err != nil {
		return nil, err
	}

	err = g.SenderKeyStore.Store(ctx, g.SenderAddress, ciphertext.DistributionID(), record)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (g *GroupSession) messageKey(state *GroupState, iteration uint32, distributionID distribution.ID) (senderkey.MessageKey, error) {
	chainKey := state.SenderChainKey()
	currentIteration := chainKey.Iteration()

	if currentIteration > iteration {
		keys, ok, err := state.RemoveMessageKeys(iteration)
		if err != nil {
			return senderkey.MessageKey{}, err
		}
		if !ok {
			glog.Warningf("SenderKey distribution %s Duplicate message for iteration: %d", distributionID, iteration)
			return senderkey.MessageKey{}, perrors.ErrDuplicateMessage
		}

		return keys, nil
	}

	jump := iteration - currentIteration
	if jump > MaxJumps {
		glog.Errorf("Sender distribution %s Exceeded future message limit: %d, iteration: %d", distributionID, MaxJumps, iteration)
		return senderkey.MessageKey{}, errors.New("message from too far in the future")
	}

	for chainKey.Iteration() < iteration {
		keys, err := chainKey.MessageKey()
		if err != nil {
			return senderkey.MessageKey{}, err
		}
		state.AddMessageKey(keys)
		chainKey = chainKey.Next()
	}

	state.SetSenderChainKey(chainKey.Next())

	messageKeys, err := chainKey.MessageKey()
	if err != nil {
		return senderkey.MessageKey{}, err
	}

	return messageKeys, nil
}
