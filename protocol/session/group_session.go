package session

import (
	"context"

	"github.com/golang/glog"

	"github.com/RTann/libsignal-go/protocol/address"
	"github.com/RTann/libsignal-go/protocol/message"
)

type GroupSession struct {
	Sender         address.Address
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
