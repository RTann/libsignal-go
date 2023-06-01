package kem

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
)

var (
	_ KeyPair    = (*Kyber1024KeyPair)(nil)
	_ PrivateKey = (*Kyber1024PrivateKey)(nil)
	_ PublicKey  = (*Kyber1024PublicKey)(nil)
)

// Kyber1024KeyPair is a Kyber-1024 key pair.
type Kyber1024KeyPair struct {
	private Kyber1024PrivateKey
	public  Kyber1024PublicKey
}

func generateKyber1024KeyPair(random io.Reader) (KeyPair, error) {
	public, private, err := kyber1024.GenerateKeyPair(random)
	if err != nil {
		return Kyber1024KeyPair{}, err
	}

	return Kyber1024KeyPair{
		private: Kyber1024PrivateKey{
			key: private,
		},
		public: Kyber1024PublicKey{
			key: public,
		},
	}, nil
}

func (k Kyber1024KeyPair) PrivateKey() PrivateKey {
	return k.private
}

func (k Kyber1024KeyPair) PublicKey() PublicKey {
	return k.public
}

// Kyber1024PrivateKey represents a Kyber-1024 private key.
type Kyber1024PrivateKey struct {
	key *kyber1024.PrivateKey
}

func (k Kyber1024PrivateKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != kyber1024.CiphertextSize+1 {
		return nil, fmt.Errorf("invalid ciphertext length (%d != %d)", len(ciphertext), kyber1024.CiphertextSize+1)
	}
	sharedSecret := make([]byte, kyber1024.SharedKeySize)
	k.key.DecapsulateTo(sharedSecret, ciphertext[1:])
	return sharedSecret, nil
}

func (k Kyber1024PrivateKey) Bytes() []byte {
	bytes := make([]byte, 1+kyber1024.PrivateKeySize)
	bytes[0] = byte(KeyTypeKyber1024)
	// TODO: error or panic?
	keyBytes, _ := k.key.MarshalBinary()
	copy(bytes[1:], keyBytes)
	return bytes
}

// Kyber1024PublicKey represents a Kyber-1024 public key.
type Kyber1024PublicKey struct {
	key *kyber1024.PublicKey
}

func (k Kyber1024PublicKey) Encapsulate() ([]byte, []byte) {
	ciphertext := make([]byte, 1+kyber1024.CiphertextSize)
	ciphertext[0] = byte(KeyTypeKyber1024)
	sharedSecret := make([]byte, kyber1024.SharedKeySize)
	k.key.EncapsulateTo(ciphertext[1:], sharedSecret, nil)
	return sharedSecret, ciphertext
}

func (k Kyber1024PublicKey) Bytes() []byte {
	bytes := make([]byte, 1+kyber1024.PublicKeySize)
	bytes[0] = byte(KeyTypeKyber1024)
	// TODO: error or panic?
	keyBytes, _ := k.key.MarshalBinary()
	copy(bytes[1:], keyBytes)
	return bytes
}
