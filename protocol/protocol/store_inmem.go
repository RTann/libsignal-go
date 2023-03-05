package protocol

import (
	"github.com/RTann/libsignal-go/protocol/identity"
	"github.com/RTann/libsignal-go/protocol/prekey"
	"github.com/RTann/libsignal-go/protocol/session"
)

type inMemSignalProtocolStore struct {
	sessionStore      session.Store
	preKeyStore       prekey.Store
	signedPreKeyStore prekey.SignedStore
	identityStore     identity.Store
	//senderKeyStore
}

func NewInMemStore(keyPair identity.KeyPair, registrationID uint32) Store {
	return &inMemSignalProtocolStore{
		sessionStore:      session.NewInMemStore(),
		preKeyStore:       prekey.NewInMemStore(),
		signedPreKeyStore: prekey.NewInMemSignedStore(),
		identityStore:     identity.NewInMemStore(keyPair, registrationID),
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
