package session

import (
	"context"

	"github.com/RTann/libsignal-go/protocol/address"
)

var _ Store = (*inMemStore)(nil)

// inMemStore represents an in-memory session store.
type inMemStore struct {
	sessions map[address.Address]*Record
}

// NewInMemStore creates a new in-memory session store.
func NewInMemStore() Store {
	return &inMemStore{
		sessions: make(map[address.Address]*Record),
	}
}

func (i *inMemStore) Load(_ context.Context, address address.Address) (*Record, bool, error) {
	record, exists := i.sessions[address]
	return record, exists, nil
}

func (i *inMemStore) Store(_ context.Context, address address.Address, record *Record) error {
	i.sessions[address] = record
	return nil
}
