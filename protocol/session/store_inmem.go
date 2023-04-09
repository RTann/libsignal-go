package session

import (
	"context"

	"github.com/RTann/libsignal-go/protocol/address"
	"github.com/RTann/libsignal-go/protocol/distribution"
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

type key struct {
	address address.Address
	id      distribution.ID
}

type inMemGroupStore struct {
	senderKeys map[key]*GroupRecord
}

func NewInMemGroupStore() GroupStore {
	return &inMemGroupStore{
		senderKeys: make(map[key]*GroupRecord),
	}
}

func (i *inMemGroupStore) Load(_ context.Context, sender address.Address, distributionID distribution.ID) (*GroupRecord, bool, error) {
	record, exists := i.senderKeys[key{
		address: sender,
		id:      distributionID,
	}]
	return record, exists, nil
}

func (i *inMemGroupStore) Store(_ context.Context, sender address.Address, distributionID distribution.ID, record *GroupRecord) error {
	i.senderKeys[key{
		address: sender,
		id:      distributionID,
	}] = record
	return nil
}
