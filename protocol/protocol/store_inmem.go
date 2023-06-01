package protocol

import (
	"github.com/RTann/libsignal-go/protocol/identity"
	"github.com/RTann/libsignal-go/protocol/prekey"
	"github.com/RTann/libsignal-go/protocol/session"
)

var _ Store = (*inMemSignalProtocolStore)(nil)

type inMemSignalProtocolStore struct {
	sessionStore      session.Store
	preKeyStore       prekey.Store
	signedPreKeyStore prekey.SignedStore
	kyberPreKeyStore  prekey.KyberStore
	identityStore     identity.Store
	groupStore        session.GroupStore
}

func NewInMemStore(keyPair identity.KeyPair, registrationID uint32) Store {
	return &inMemSignalProtocolStore{
		sessionStore:      session.NewInMemStore(),
		preKeyStore:       prekey.NewInMemStore(),
		signedPreKeyStore: prekey.NewInMemSignedStore(),
		kyberPreKeyStore:  prekey.NewInMemKyberStore(),
		identityStore:     identity.NewInMemStore(keyPair, registrationID),
		groupStore:        session.NewInMemGroupStore(),
	}
}

func (i *inMemSignalProtocolStore) SessionStore() session.Store {
	return i.sessionStore
}

func (i *inMemSignalProtocolStore) IdentityStore() identity.Store {
	return i.identityStore
}

func (i *inMemSignalProtocolStore) PreKeyStore() prekey.Store {
	return i.preKeyStore
}

func (i *inMemSignalProtocolStore) SignedPreKeyStore() prekey.SignedStore {
	return i.signedPreKeyStore
}

func (i *inMemSignalProtocolStore) KyberPreKeyStore() prekey.KyberStore {
	return i.kyberPreKeyStore
}

func (i *inMemSignalProtocolStore) GroupStore() session.GroupStore {
	return i.groupStore
}
