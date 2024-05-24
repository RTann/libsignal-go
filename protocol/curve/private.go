package curve

import (
	"io"

	"github.com/RTann/libsignal-go/protocol/curve/curve25519"
	"github.com/RTann/libsignal-go/protocol/perrors"
)

const PrivateKeySize = curve25519.PrivateKeySize

// PrivateKey represents an elliptic curve private key.
type PrivateKey interface {
	// Bytes returns an encoding of the private key.
	Bytes() []byte
	// PublicKey returns the private key's related public key.
	PublicKey() PublicKey
	// Agreement calculates and returns the shared secret between the private key
	// and the given public key.
	Agreement(key PublicKey) ([]byte, error)
	// Sign calculates the digital signature of the messages.
	Sign(random io.Reader, messages ...[]byte) ([]byte, error)
}

// NewPrivateKey returns a PrivateKey based on the given key.
func NewPrivateKey(key []byte) (PrivateKey, error) {
	if len(key) != PrivateKeySize {
		return nil, perrors.ErrInvalidKeyLength(PrivateKeySize, len(key))
	}

	return newDJBPrivateKey(key)
}
