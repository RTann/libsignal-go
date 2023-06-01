package prekey

import "context"

var (
	_ Store       = (*inMemStore)(nil)
	_ SignedStore = (*inMemSignedStore)(nil)
	_ KyberStore  = (*inMemKyberStore)(nil)
)

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

// inMemKyberStore represents an in-memory Kyber pre-key store.
type inMemKyberStore struct {
	kyberPreKeys map[ID]*KyberPreKey
}

// NewInMemKyberStore creates a new in-memory Kyber pre-key store.
func NewInMemKyberStore() KyberStore {
	return &inMemKyberStore{
		kyberPreKeys: make(map[ID]*KyberPreKey),
	}
}

func (i *inMemKyberStore) Load(_ context.Context, id ID) (*KyberPreKey, bool, error) {
	record, exists := i.kyberPreKeys[id]
	return record, exists, nil
}

func (i *inMemKyberStore) Store(_ context.Context, id ID, preKey *KyberPreKey) error {
	i.kyberPreKeys[id] = preKey
	return nil
}

func (i *inMemKyberStore) Delete(_ context.Context, id ID) error {
	delete(i.kyberPreKeys, id)
	return nil
}
