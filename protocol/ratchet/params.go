package ratchet

import (
	"github.com/RTann/libsignal-go/protocol/curve"
	"github.com/RTann/libsignal-go/protocol/identity"
)

// AliceParameters represents the "Alice" side
// of the double ratchet algorithm required to
// perform X3DH.
type AliceParameters struct {
	OurIdentityKeyPair identity.KeyPair
	OurBaseKeyPair     curve.KeyPair

	TheirIdentityKey   identity.Key
	TheirSignedPreKey  curve.PublicKey
	TheirOneTimePreKey curve.PublicKey
	TheirRatchetKey    curve.PublicKey
}

// BobParameters represents the "Bob" side
// of the double ratchet algorithm required to
// perform X3DH.
type BobParameters struct {
	OurIdentityKeyPair   identity.KeyPair
	OurSignedPreKeyPair  curve.KeyPair
	OurOneTimePreKeyPair curve.KeyPair
	OurRatchetKeyPair    curve.KeyPair

	TheirIdentityKey identity.Key
	TheirBaseKey     curve.PublicKey
}
