// Package identity defines an identity key.
package identity

import (
	"io"

	"github.com/RTann/libsignal-go/protocol/curve"
)

var (
	alternateIdentitySignaturePrefix1 = []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	}
	alternateIdentitySignaturePrefix2 = []byte("Signal_PNI_Signature")
)

// Key represents a public identity key.
type Key struct {
	PublicKey curve.PublicKey
}

// NewKey returns a public identity key from the given key bytes.
func NewKey(key []byte) (Key, error) {
	publicKey, err := curve.NewPublicKey(key)
	if err != nil {
		return Key{}, err
	}

	return Key{
		PublicKey: publicKey,
	}, nil
}

// Bytes returns an encoding of the identity key.
func (k Key) Bytes() []byte {
	return k.PublicKey.Bytes()
}

// VerifyAlternateIdentity verifies the other key represents an alternate identity
// for this user.
//
// It is expected the signature is the output of KeyPair.SignAlternateIdentity.
func (k Key) VerifyAlternateIdentity(signature []byte, other Key) (bool, error) {
	return k.PublicKey.VerifySignature(signature,
		alternateIdentitySignaturePrefix1,
		alternateIdentitySignaturePrefix2,
		other.Bytes(),
	)
}

// Equal determines if the identity keys are the same.
func (k Key) Equal(key Key) bool {
	return k.PublicKey.Equal(key.PublicKey)
}

// KeyPair represents a public/private identity key pair.
type KeyPair struct {
	PrivateKey  curve.PrivateKey
	IdentityKey Key
}

// GenerateKeyPair generates an identity key pair using the given random reader.
//
// It is recommended to use a cryptographic random reader.
// If random is `nil`, then crypto/rand.Reader is used.
func GenerateKeyPair(random io.Reader) (KeyPair, error) {
	pair, err := curve.GenerateKeyPair(random)
	if err != nil {
		return KeyPair{}, err
	}

	return KeyPair{
		PrivateKey: pair.PrivateKey,
		IdentityKey: Key{
			PublicKey: pair.PublicKey,
		},
	}, nil
}

// PublicKey returns the key pair's public key.
func (k KeyPair) PublicKey() curve.PublicKey {
	return k.IdentityKey.PublicKey
}

// SignAlternateIdentity generates a signature claiming the other key
// represents the same user as this key pair.
func (k KeyPair) SignAlternateIdentity(random io.Reader, other Key) ([]byte, error) {
	return k.PrivateKey.Sign(random,
		alternateIdentitySignaturePrefix1,
		alternateIdentitySignaturePrefix2,
		other.Bytes(),
	)
}
