package protocol

import (
	"github.com/RTann/libsignal-go/protocol/identity"
	"github.com/RTann/libsignal-go/protocol/prekey"
	"github.com/RTann/libsignal-go/protocol/session"
)

type Store interface {
	SessionStore() session.Store
	IdentityStore() identity.Store
	PreKeyStore() prekey.Store
	SignedPreKeyStore() prekey.SignedStore
}
