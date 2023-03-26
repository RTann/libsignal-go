// Package curve implements elliptic curve cryptography
// functions used for the protocol.
package curve

import "io"

// KeyPair represents a related pair of public and private keys.
type KeyPair struct {
	PrivateKey PrivateKey
	PublicKey  PublicKey
}

// GenerateKeyPair returns a public/private key pair using the given reader.
//
// It is recommended to use a cryptographic random reader.
// If random is `nil`, then crypto/rand.Reader is used.
func GenerateKeyPair(random io.Reader) (*KeyPair, error) {
	privateKey, err := GeneratePrivateKey(random)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  privateKey.PublicKey(),
	}, nil
}

// NewKeyPair returns a public/private key pair from the given pair.
// The given pair is expected to represent a valid PrivateKey and
// PublicKey, respectively.
func NewKeyPair(privateKey, publicKey []byte) (*KeyPair, error) {
	private, err := NewPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	public, err := NewPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: private,
		PublicKey:  public,
	}, nil
}

// Agreement calculates and returns the shared secret between
// the key pair's private key and the given public key.
func (k *KeyPair) Agreement(key PublicKey) ([]byte, error) {
	return k.PrivateKey.Agreement(key)
}

// Sign calculates the digital signature of the messages using
// the key pair's private key.
func (k *KeyPair) Sign(random io.Reader, messages ...[]byte) ([]byte, error) {
	return k.PrivateKey.Sign(random, messages...)
}
