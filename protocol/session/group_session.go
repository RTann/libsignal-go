package session

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/golang/glog"

	"github.com/RTann/libsignal-go/protocol/address"
	"github.com/RTann/libsignal-go/protocol/curve"
	"github.com/RTann/libsignal-go/protocol/distribution"
	"github.com/RTann/libsignal-go/protocol/message"
)

type GroupSession struct {
	// SenderAddress is the address of the user sending the message.
	//
	// It is meant to be populated by both the sender and the receiver.
	SenderAddress address.Address
	// LocalDistID is the distribution ID of the sender.
	//
	// It is meant to be populated by the sender, only.
	LocalDistID    distribution.ID
	SenderKeyStore GroupStore
}

func (g *GroupSession) ProcessSenderKeyDistribution(ctx context.Context, message *message.SenderKeyDistribution) error {
	glog.Infof("%s Processing SenderKey distribution %s with chain ID %s", g.SenderAddress, message.DistributionID(), message.ChainID())

	record, exists, err := g.SenderKeyStore.Load(ctx, g.SenderAddress, message.DistributionID())
	if err != nil {
		return err
	}
	if !exists {
		record = NewGroupRecord()
	}

	state := NewGroupState(GroupStateConfig{
		MessageVersion: message.Version(),
		ChainID:        message.ChainID(),
		Iteration:      message.Iteration(),
		ChainKey:       message.ChainKey(),
		SignatureKey:   message.SigningKey(),
	})
	err = record.AddState(state)
	if err != nil {
		return err
	}

	err = g.SenderKeyStore.Store(ctx, g.SenderAddress, message.DistributionID(), record)
	return err
}

func (g *GroupSession) NewSenderKeyDistribution(ctx context.Context, random io.Reader) (*message.SenderKeyDistribution, error) {
	record, exists, err := g.SenderKeyStore.Load(ctx, g.SenderAddress, g.LocalDistID)
	if err != nil {
		return nil, err
	}
	if !exists {
		chainID, err := randomUint32()
		if err != nil {
			return nil, err
		}
		glog.Infof("Creating SenderKey for distribution %s with chain ID %d", g.LocalDistID, chainID)

		senderKey := make([]byte, 32)
		_, err = io.ReadFull(random, senderKey)
		if err != nil {
			return nil, err
		}

		signingKey, err := curve.GenerateKeyPair(random)
		if err != nil {
			return nil, err
		}

		record = NewGroupRecord()
		state := NewGroupState(GroupStateConfig{
			MessageVersion:      message.SenderKeyVersion,
			ChainID:             chainID,
			Iteration:           0,
			ChainKey:            senderKey,
			SignatureKey:        signingKey.PublicKey(),
			SignaturePrivateKey: signingKey.PrivateKey(),
		})
		err = record.AddState(state)
		if err != nil {
			return nil, err
		}

		err = g.SenderKeyStore.Store(ctx, g.SenderAddress, g.LocalDistID, record)
		if err != nil {
			return nil, err
		}
	}

	state, err := record.State()
	if err != nil {
		return nil, err
	}

	senderChainKey := state.SenderChainKey()

	signingKey, err := state.PublicSigningKey()
	if err != nil {
		return nil, err
	}

	return message.NewSenderKeyDistribution(message.SenderKeyDistConfig{
		Version:    uint8(state.Version()),
		DistID:     g.LocalDistID,
		ChainID:    state.ChainID(),
		Iteration:  senderChainKey.Iteration(),
		ChainKey:   senderChainKey.Seed(),
		SigningKey: signingKey,
	})
}

func randomUint32() (uint32, error) {
	bytes := make([]byte, 4)
	_, err := io.ReadFull(rand.Reader, bytes)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint32(bytes), nil
}
