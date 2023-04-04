package curve

import (
	"fmt"

	"github.com/RTann/libsignal-go/protocol/curve/curve25519"
	"github.com/RTann/libsignal-go/protocol/perrors"
)

const (
	PublicKeySize = curve25519.PublicKeySize
	SignatureSize = curve25519.SignatureSize
)

// PublicKey represents an elliptic curve public key.
type PublicKey interface {
	keyType() KeyType
	// Bytes returns an encoding of the public key.
	Bytes() []byte
	// KeyBytes returns an encoding of the public key without the type prefix.
	KeyBytes() []byte
	// Equal reports whether the given public key is the same as this public key.
	//
	// This check is performed in constant time as long as the keys have the same type.
	Equal(key PublicKey) bool
	// VerifySignature verifies the signature is a valid signature
	// of the messages by the public key.
	VerifySignature(signature []byte, messages ...[]byte) (bool, error)
}

// NewPublicKey returns a PublicKey based on the given key.
//
// The first byte of the given key is expected to identify the type of the key.
func NewPublicKey(key []byte) (PublicKey, error) {
	// Allow trailing data after the public key for some reason...
	if len(key) < 1+PublicKeySize {
		return nil, perrors.ErrInvalidKeyLength(1+PublicKeySize, len(key))
	}

	publicKey := make([]byte, PublicKeySize)
	copy(publicKey, key[1:])

	switch t := KeyType(key[0]); t {
	case DJB:
		return newDJBPublicKey(publicKey)
	default:
		return nil, fmt.Errorf("unsupported key type: %v", t)
	}
}
