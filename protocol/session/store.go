package session

import (
	"context"

	"github.com/google/uuid"

	"github.com/RTann/libsignal-go/protocol/address"
)

// Store defines a session store.
type Store interface {
	Load(ctx context.Context, address address.Address) (*Record, bool, error)
	Store(ctx context.Context, address address.Address, record *Record) error
}

type GroupStore interface {
	Load(ctx context.Context, sender address.Address, distributionID uuid.UUID) (*GroupRecord, bool, error)
	Store(ctx context.Context, sender address.Address, distributionID uuid.UUID, record *GroupRecord) error
}
