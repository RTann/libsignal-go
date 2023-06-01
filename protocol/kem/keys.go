// Package kem defines key encapsulation mechanisms used by the protocol
// to support post-quantum cryptography.
package kem

import (
	"errors"
	"io"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// KeyType specifies the type of the key encapsulation mechanism.
type KeyType byte

const (
	// KeyTypeKyber768 specifies the Kyber-768 key type.
	KeyTypeKyber768 KeyType = 0x07
	// KeyTypeKyber1024 specifies the Kyber-1024 key type.
	KeyTypeKyber1024 KeyType = 0x08
)

// PrivateKeySize returns the size of the associated private key.
func (k KeyType) PrivateKeySize() int {
	switch k {
	case KeyTypeKyber768:
		return kyber768.PrivateKeySize
	case KeyTypeKyber1024:
		return kyber1024.PrivateKeySize
	default:
		panic("not possible")
	}
}

// PublicKeySize returns the size of the associated public key.
func (k KeyType) PublicKeySize() int {
	switch k {
	case KeyTypeKyber768:
		return kyber768.PublicKeySize
	case KeyTypeKyber1024:
		return kyber1024.PublicKeySize
	default:
		panic("not possible")
	}
}

// SharedKeySize returns the size of the associated shared key.
func (k KeyType) SharedKeySize() int {
	switch k {
	case KeyTypeKyber768:
		return kyber768.SharedKeySize
	case KeyTypeKyber1024:
		return kyber1024.SharedKeySize
	default:
		panic("not possible")
	}
}

// CiphertextSize returns the size of the associated ciphertext.
func (k KeyType) CiphertextSize() int {
	switch k {
	case KeyTypeKyber768:
		return kyber768.CiphertextSize
	case KeyTypeKyber1024:
		return kyber1024.CiphertextSize
	default:
		panic("not possible")
	}
}

// PrivateKey represents a post-quantum private key.
type PrivateKey interface {
	// Decapsulate computes the shared secret encapsulated in the
	// given ciphertext by the private key.
	Decapsulate(ciphertext []byte) (sharedSecret []byte, err error)
	// Bytes returns the byte slice representation of the private key.
	Bytes() []byte
}

// PublicKey represents a post-quantum public key.
type PublicKey interface {
	// Encapsulate generates a shared secret and ciphertext, respectively,
	// for the public key.
	Encapsulate() (sharedSecret []byte, ciphertext []byte)
	// Bytes returns the byte slice representation of the public key.
	Bytes() []byte
}

// KeyPair represents a post-quantum key pair.
type KeyPair interface {
	// PrivateKey returns the key pair's private key.
	PrivateKey() PrivateKey
	// PublicKey returns the key pair's public key.
	PublicKey() PublicKey
}

// GenerateKeyPair generates a random key pair of the given key type.
//
// It is recommended to use a cryptographic random reader.
// If random is nil, then [crypto/rand.Reader] is used.
func GenerateKeyPair(random io.Reader, keyType KeyType) (KeyPair, error) {
	switch keyType {
	case KeyTypeKyber768:
		return generateKyber768KeyPair(random)
	case KeyTypeKyber1024:
		return generateKyber1024KeyPair(random)
	default:
		return nil, errors.New("invalid key type")
	}
}
