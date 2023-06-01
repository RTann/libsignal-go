package kem

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

var (
	_ KeyPair    = (*Kyber768KeyPair)(nil)
	_ PrivateKey = (*Kyber768PrivateKey)(nil)
	_ PublicKey  = (*Kyber768PublicKey)(nil)
)

// Kyber768KeyPair is a Kyber-768 key pair.
type Kyber768KeyPair struct {
	private Kyber768PrivateKey
	public  Kyber768PublicKey
}

func generateKyber768KeyPair(random io.Reader) (KeyPair, error) {
	public, private, err := kyber768.GenerateKeyPair(random)
	if err != nil {
		return Kyber768KeyPair{}, err
	}

	return Kyber768KeyPair{
		private: Kyber768PrivateKey{
			key: private,
		},
		public: Kyber768PublicKey{
			key: public,
		},
	}, nil
}

func (k Kyber768KeyPair) PrivateKey() PrivateKey {
	return k.private
}

func (k Kyber768KeyPair) PublicKey() PublicKey {
	return k.public
}

// Kyber768PrivateKey represents a Kyber-768 private key.
type Kyber768PrivateKey struct {
	key *kyber768.PrivateKey
}

func (k Kyber768PrivateKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != kyber768.CiphertextSize+1 {
		return nil, fmt.Errorf("invalid ciphertext length (%d != %d)", len(ciphertext), kyber768.CiphertextSize+1)
	}
	sharedSecret := make([]byte, kyber768.SharedKeySize)
	k.key.DecapsulateTo(sharedSecret, ciphertext[1:])
	return sharedSecret, nil
}

func (k Kyber768PrivateKey) Bytes() []byte {
	bytes := make([]byte, 1+kyber768.PrivateKeySize)
	bytes[0] = byte(KeyTypeKyber768)
	// TODO: error or panic?
	keyBytes, _ := k.key.MarshalBinary()
	copy(bytes[1:], keyBytes)
	return bytes
}

// Kyber768PublicKey represents a Kyber-768 public key.
type Kyber768PublicKey struct {
	key *kyber768.PublicKey
}

func (k Kyber768PublicKey) Encapsulate() ([]byte, []byte) {
	ciphertext := make([]byte, 1+kyber768.CiphertextSize)
	ciphertext[0] = byte(KeyTypeKyber768)
	sharedSecret := make([]byte, kyber768.SharedKeySize)
	k.key.EncapsulateTo(ciphertext[1:], sharedSecret, nil)
	return sharedSecret, ciphertext
}

func (k Kyber768PublicKey) Bytes() []byte {
	bytes := make([]byte, 1+kyber768.PublicKeySize)
	bytes[0] = byte(KeyTypeKyber768)
	// TODO: error or panic?
	keyBytes, _ := k.key.MarshalBinary()
	copy(bytes[1:], keyBytes)
	return bytes
}
