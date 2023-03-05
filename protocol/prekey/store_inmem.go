package prekey

import "context"

var _ Store = (*inMemStore)(nil)

// inMemStore represents an in-memory pre-key store.
type inMemStore struct {
	preKeys map[ID]*PreKey
}

// NewInMemStore creates a new in-memory pre-key store.
func NewInMemStore() Store {
	return &inMemStore{
		preKeys: make(map[ID]*PreKey),
	}
}

func (i *inMemStore) Load(_ context.Context, id ID) (*PreKey, bool, error) {
	record, exists := i.preKeys[id]
	return record, exists, nil
}

func (i *inMemStore) Store(_ context.Context, id ID, record *PreKey) error {
	i.preKeys[id] = record
	return nil
}

func (i *inMemStore) Delete(_ context.Context, id ID) error {
	delete(i.preKeys, id)
	return nil
}

var _ SignedStore = (*inMemSignedStore)(nil)

// inMemSignedStore represents an in-memory signed pre-key store.
type inMemSignedStore struct {
	signedPreKeys map[ID]*SignedPreKey
}

// NewInMemSignedStore creates a new in-memory signed pre-key store.
func NewInMemSignedStore() SignedStore {
	return &inMemSignedStore{
		signedPreKeys: make(map[ID]*SignedPreKey),
	}
}

func (i *inMemSignedStore) Load(_ context.Context, id ID) (*SignedPreKey, bool, error) {
	record, exists := i.signedPreKeys[id]
	return record, exists, nil
}

func (i *inMemSignedStore) Store(_ context.Context, id ID, record *SignedPreKey) error {
	i.signedPreKeys[id] = record
	return nil
}
