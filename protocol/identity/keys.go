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
	publicKey curve.PublicKey
}

// NewKey returns a public identity key from the given public key.
func NewKey(key curve.PublicKey) Key {
	return Key{
		publicKey: key,
	}
}

// NewKeyFromBytes returns a public identity key from the given key bytes.
func NewKeyFromBytes(key []byte) (Key, error) {
	publicKey, err := curve.NewPublicKey(key)
	if err != nil {
		return Key{}, err
	}

	return NewKey(publicKey), nil
}

// PublicKey returns the identity key's public key.
func (k Key) PublicKey() curve.PublicKey {
	return k.publicKey
}

// Bytes returns an encoding of the identity key.
func (k Key) Bytes() []byte {
	return k.publicKey.Bytes()
}

// VerifyAlternateIdentity verifies other key represents an alternate identity
// for this user.
//
// It is expected the signature is the output of KeyPair.SignAlternateIdentity.
func (k Key) VerifyAlternateIdentity(signature []byte, other Key) (bool, error) {
	return k.publicKey.VerifySignature(signature,
		alternateIdentitySignaturePrefix1,
		alternateIdentitySignaturePrefix2,
		other.Bytes(),
	)
}

// Equal determines if the identity keys are the same.
func Equal(a, b Key) bool {
	return curve.PublicKeyEqual(a.PublicKey(), b.PublicKey())
}

// KeyPair represents a public/private identity key pair.
type KeyPair struct {
	identityKey Key
	privateKey  curve.PrivateKey
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
		identityKey: NewKey(pair.PublicKey()),
		privateKey:  pair.PrivateKey(),
	}, nil
}

// NewKeyPair returns an identity key pair based on the given
// public and private keys.
func NewKeyPair(identityKey Key, privateKey curve.PrivateKey) KeyPair {
	return KeyPair{
		identityKey: identityKey,
		privateKey:  privateKey,
	}
}

// IdentityKey returns the key pair's public identity key.
func (k KeyPair) IdentityKey() Key {
	return k.identityKey
}

// PublicKey returns the key pair's public key.
func (k KeyPair) PublicKey() curve.PublicKey {
	return k.identityKey.PublicKey()
}

// PrivateKey returns the key pair's private key.
func (k KeyPair) PrivateKey() curve.PrivateKey {
	return k.privateKey
}

// SignAlternateIdentity generates a signature claiming other key
// represents the same user as this key pair.
func (k KeyPair) SignAlternateIdentity(random io.Reader, other Key) ([]byte, error) {
	return k.privateKey.Sign(random,
		alternateIdentitySignaturePrefix1,
		alternateIdentitySignaturePrefix2,
		other.Bytes(),
	)
}
