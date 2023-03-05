package prekey

import "context"

// Store defines a pre-key store.
type Store interface {
	// Load fetches the pre-key associated with the id from the store.
	Load(ctx context.Context, id ID) (*PreKey, bool, error)
	// Store stores the pre-key associated with the given ID in the store.
	Store(ctx context.Context, id ID, preKey *PreKey) error
	// Delete removes the pre-key entry identified by the given ID from the store.
	Delete(ctx context.Context, id ID) error
}

// SignedStore defines a signed pre-key store.
type SignedStore interface {
	// Load fetches the signed pre-key associated with the id from the store.
	Load(ctx context.Context, id ID) (*SignedPreKey, bool, error)
	// Store stores the signed pre-key associated with the given ID in the store.
	Store(ctx context.Context, id ID, record *SignedPreKey) error
}
