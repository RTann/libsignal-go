package session

import (
	"context"

	"github.com/RTann/libsignal-go/protocol/address"
	"github.com/RTann/libsignal-go/protocol/distribution"
)

// Store defines a session store.
type Store interface {
	Load(ctx context.Context, address address.Address) (*Record, bool, error)
	Store(ctx context.Context, address address.Address, record *Record) error
}

type GroupStore interface {
	Load(ctx context.Context, sender address.Address, distributionID distribution.ID) (*GroupRecord, bool, error)
	Store(ctx context.Context, sender address.Address, distributionID distribution.ID, record *GroupRecord) error
}
