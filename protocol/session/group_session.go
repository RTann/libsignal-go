package session

import (
	"context"
	"encoding/binary"
	"io"

	"github.com/golang/glog"

	"github.com/RTann/libsignal-go/protocol/address"
	"github.com/RTann/libsignal-go/protocol/curve"
	"github.com/RTann/libsignal-go/protocol/distribution"
	"github.com/RTann/libsignal-go/protocol/message"
)

type GroupSession struct {
	Sender         address.Address
	LocalDistID    distribution.ID
	SenderKeyStore GroupStore
}

func (g *GroupSession) ProcessDistributionMessage(ctx context.Context, message *message.SenderKeyDistribution) error {
	glog.Infof("%s Processing SenderKey distribution %s with chain ID %s", g.Sender, message.DistributionID(), message.ChainID())

	record, exists, err := g.SenderKeyStore.Load(ctx, g.Sender, message.DistributionID())
	if err != nil {
		return err
	}
	if !exists {
		record = NewGroupRecord()
	}

	state := NewGroupState(
		message.Version(),
		message.ChainID(),
		message.Iteration(),
		message.ChainKey(),
		message.SigningKey(),
		nil,
	)
	record.AddState(state)

	err = g.SenderKeyStore.Store(ctx, g.Sender, message.DistributionID(), record)
	return err
}

func (g *GroupSession) NewSenderKeyDistributionMessage(ctx context.Context, random io.Reader) (*message.SenderKeyDistribution, error) {
	record, exists, err := g.SenderKeyStore.Load(ctx, g.Sender, g.LocalDistID)
	if err != nil {
		return nil, err
	}
	if !exists {
		chainIDBytes := make([]byte, 32)
		_, err := io.ReadFull(random, chainIDBytes)
		if err != nil {
			return nil, err
		}
		chainID := binary.BigEndian.Uint32(chainIDBytes)
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
		state := NewGroupState(
			message.SenderKeyVersion,
			chainID,
			0,
			senderKey,
			signingKey.PublicKey(),
			signingKey.PrivateKey(),
		)
		err = record.AddState(state)
		if err != nil {
			return nil, err
		}

		err = g.SenderKeyStore.Store(ctx, g.Sender, g.LocalDistID, record)
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

	return message.NewSenderKeyDistribution(
		uint8(state.Version()),
		g.LocalDistID,
		state.ChainID(),
		senderChainKey.Iteration(),
		senderChainKey.Seed(),
		signingKey,
	)
}
