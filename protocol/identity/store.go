package identity

import (
	"context"

	"github.com/RTann/libsignal-go/protocol/address"
	"github.com/RTann/libsignal-go/protocol/direction"
)

// Store defines an identity key store.
//
// An identity key store is associated with a local identity key pair and registration ID.
type Store interface {
	// KeyPair returns the associated identity key pair.
	KeyPair(ctx context.Context) KeyPair
	// LocalRegistrationID returns the associated registration ID.
	LocalRegistrationID(ctx context.Context) uint32
	// Load loads the identity key associated with the remote address.
	Load(ctx context.Context, address address.Address) (Key, bool, error)
	// Store stores the identity key associated with the remote address and returns
	// "true" if there is already an entry for the address which is overwritten
	// with a new identity key.
	//
	// Storing the identity key for the remote address implies the identity key
	// is trusted for the given address.
	Store(ctx context.Context, address address.Address, identity Key) (bool, error)
	// Clear removes all items from the store.
	Clear() error
	// IsTrustedIdentity returns "true" if the given identity key for the given address is already trusted.
	//
	// If there is no entry for the given address, the given identity key is trusted.
	IsTrustedIdentity(ctx context.Context, address address.Address, identity Key, direction direction.Direction) (bool, error)
}
