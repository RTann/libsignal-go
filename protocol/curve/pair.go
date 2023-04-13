// Package curve implements elliptic curve cryptography
// functions used for the protocol.
package curve

import "io"

// KeyPair represents a related pair of public and private keys.
type KeyPair struct {
	privateKey PrivateKey
	publicKey  PublicKey
}

// GenerateKeyPair returns a public/private key pair using the given reader.
//
// It is recommended to use a cryptographic random reader.
// If random is `nil`, then crypto/rand.Reader is used.
func GenerateKeyPair(random io.Reader) (KeyPair, error) {
	privateKey, err := GeneratePrivateKey(random)
	if err != nil {
		return KeyPair{}, err
	}

	publicKey := privateKey.PublicKey()

	return KeyPair{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

// NewKeyPair returns a public/private key pair from the given pair.
//
// The given pair is expected to represent a valid curve.PrivateKey and
// curve.PublicKey, respectively.
func NewKeyPair(privateKey, publicKey []byte) (KeyPair, error) {
	private, err := NewPrivateKey(privateKey)
	if err != nil {
		return KeyPair{}, err
	}
	public, err := NewPublicKey(publicKey)
	if err != nil {
		return KeyPair{}, err
	}

	return KeyPair{
		privateKey: private,
		publicKey:  public,
	}, nil
}

// PrivateKey returns the pair's private key.
func (k KeyPair) PrivateKey() PrivateKey {
	return k.privateKey
}

// PublicKey returns the pair's public key.
func (k KeyPair) PublicKey() PublicKey {
	return k.publicKey
}

// Agreement calculates and returns the shared secret between
// the key pair's private key and the given public key.
func (k KeyPair) Agreement(key PublicKey) ([]byte, error) {
	return k.privateKey.Agreement(key)
}

// Sign calculates the digital signature of the messages using
// the key pair's private key.
//
// It is recommended to use a cryptographic random reader.
// If random is `nil`, then crypto/rand.Reader is used.
func (k KeyPair) Sign(random io.Reader, messages ...[]byte) ([]byte, error) {
	return k.privateKey.Sign(random, messages...)
}
