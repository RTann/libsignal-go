package curve

import (
	"io"

	"github.com/RTann/libsignal-go/protocol/curve/curve25519"
	"github.com/RTann/libsignal-go/protocol/perrors"
)

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
	if len(key) != curve25519.PrivateKeySize {
		return nil, perrors.ErrInvalidKeyLength(curve25519.PrivateKeySize, len(key))
	}

	djbKey := make([]byte, len(key))
	copy(djbKey, key)

	// Clamp the given key.
	// See step 2 in https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5.
	djbKey[0] &= 248
	djbKey[31] &= 63
	djbKey[31] |= 64

	return newDJBPrivateKey(djbKey)
}
