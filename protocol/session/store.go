package session

import (
	"context"

	"github.com/RTann/libsignal-go/protocol/address"
)

// Store defines a session store.
type Store interface {
	Load(ctx context.Context, address address.Address) (*Record, bool, error)
	Store(ctx context.Context, address address.Address, record *Record) error
}
