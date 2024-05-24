package curve

import (
	"crypto/subtle"

	"github.com/RTann/libsignal-go/protocol/curve/curve25519"
	"github.com/RTann/libsignal-go/protocol/perrors"
)

var _ PublicKey = (*DJBPublicKey)(nil)

// DJBPublicKey represents an elliptic curve public key.
type DJBPublicKey struct {
	key []byte
}

// newDJBPublicKey returns a public key based on the given key bytes.
func newDJBPublicKey(key []byte) (*DJBPublicKey, error) {
	if len(key) != PublicKeySize {
		return nil, perrors.ErrInvalidKeyLength(PublicKeySize, len(key))
	}

	return &DJBPublicKey{
		key: key,
	}, nil
}

func (d *DJBPublicKey) keyType() KeyType {
	return DJB
}

func (d *DJBPublicKey) Bytes() []byte {
	bytes := make([]byte, 1+PublicKeySize)
	bytes[0] = byte(DJB)
	copy(bytes[1:], d.key)
	return bytes
}

func (d *DJBPublicKey) KeyBytes() []byte {
	bytes := make([]byte, PublicKeySize)
	copy(bytes, d.key)
	return bytes
}

func (d *DJBPublicKey) Equal(key PublicKey) bool {
	return key.keyType() == DJB &&
		subtle.ConstantTimeCompare(d.KeyBytes(), key.KeyBytes()) == 1
}

func (d *DJBPublicKey) VerifySignature(signature []byte, messages ...[]byte) (bool, error) {
	if len(signature) != SignatureSize {
		return false, nil
	}

	return curve25519.VerifySignature(d.key, signature, messages...)
}
