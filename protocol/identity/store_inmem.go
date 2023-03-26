package identity

import (
	"context"

	"github.com/RTann/libsignal-go/protocol/address"
	"github.com/RTann/libsignal-go/protocol/direction"
)

var _ Store = (*inMemStore)(nil)

// inMemStore represents an in-memory identity key store.
type inMemStore struct {
	keyPair        KeyPair
	registrationID uint32
	knownKeys      map[address.Address]Key
}

// NewInMemStore creates a new in-memory identity key store.
func NewInMemStore(keyPair KeyPair, registrationID uint32) Store {
	return &inMemStore{
		keyPair:        keyPair,
		registrationID: registrationID,
		knownKeys:      make(map[address.Address]Key),
	}
}

func (i *inMemStore) KeyPair(_ context.Context) KeyPair {
	return i.keyPair
}

func (i *inMemStore) LocalRegistrationID(_ context.Context) uint32 {
	return i.registrationID
}

func (i *inMemStore) Load(_ context.Context, address address.Address) (Key, bool, error) {
	key, exists := i.knownKeys[address]
	return key, exists, nil
}

func (i *inMemStore) Store(_ context.Context, address address.Address, identity Key) (bool, error) {
	knownIdentity, exists := i.knownKeys[address]
	i.knownKeys[address] = identity

	return exists && identity != knownIdentity, nil
}

func (i *inMemStore) Clear() error {
	tmp := i.knownKeys
	i.knownKeys = make(map[address.Address]Key)

	go func() {
		for k := range tmp {
			delete(tmp, k)
		}
	}()

	return nil
}

func (i *inMemStore) IsTrustedIdentity(_ context.Context, address address.Address, identity Key, _ direction.Direction) (bool, error) {
	knownIdentity, exists := i.knownKeys[address]
	if !exists {
		return true, nil
	}

	return identity.Equal(knownIdentity), nil
}
