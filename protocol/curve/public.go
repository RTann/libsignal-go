package curve

import (
	"crypto/subtle"
	"fmt"

	"github.com/RTann/libsignal-go/protocol/curve/curve25519"
	"github.com/RTann/libsignal-go/protocol/perrors"
)

// PublicKey represents an elliptic curve public key.
type PublicKey interface {
	// Bytes returns an encoding of the public key.
	Bytes() []byte
	// KeyBytes returns an encoding of the public key without the type prefix.
	KeyBytes() []byte
	// VerifySignature verifies the signature is a valid signature
	// of the messages by the public key.
	VerifySignature(signature []byte, messages ...[]byte) (bool, error)
}

// NewPublicKey returns a PublicKey based on the given key.
//
// The first byte of the given key is expected to identify the type of the key.
func NewPublicKey(key []byte) (PublicKey, error) {
	if len(key) != 1+curve25519.PublicKeySize {
		return nil, perrors.ErrInvalidKeyLength(1+curve25519.PublicKeySize, len(key))
	}

	switch t := KeyType(key[0]); t {
	case DJB:
		return newDJBPublicKey(key[1:])
	default:
		return nil, fmt.Errorf("unsupported key type: %v", t)
	}
}

// PublicKeyEqual reports whether two public keys are the same.
func PublicKeyEqual(a, b PublicKey) bool {
	return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
}
