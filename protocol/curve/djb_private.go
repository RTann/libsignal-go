package curve

import (
	"io"

	"github.com/RTann/libsignal-go/protocol/curve/curve25519"
)

var _ PrivateKey = (*DJBPrivateKey)(nil)

// DJBPrivateKey represents an elliptic curve private key.
type DJBPrivateKey struct {
	key *curve25519.PrivateKey
}

// GeneratePrivateKey generates a private key using the given random reader.
//
// It is recommended to use a cryptographic random reader.
// If random is `nil`, then crypto/rand.Reader is used.
func GeneratePrivateKey(random io.Reader) (PrivateKey, error) {
	privateKey, err := curve25519.GeneratePrivateKey(random)
	if err != nil {
		return nil, err
	}

	return &DJBPrivateKey{
		key: privateKey,
	}, nil
}

// newDJBPrivateKey returns a private key based on the given key bytes.
//
// It is expected that the given key is already clamped based on
// https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5.
func newDJBPrivateKey(key []byte) (PrivateKey, error) {
	privateKey, err := curve25519.NewPrivateKey(key)
	if err != nil {
		return nil, err
	}

	return &DJBPrivateKey{
		key: privateKey,
	}, nil
}

func (d *DJBPrivateKey) Bytes() []byte {
	return d.key.Bytes()
}

func (d *DJBPrivateKey) PublicKey() PublicKey {
	key, _ := newDJBPublicKey(d.key.PublicKeyBytes())
	return key
}

func (d *DJBPrivateKey) Agreement(key PublicKey) ([]byte, error) {
	return d.key.Agreement(key.KeyBytes())
}

func (d *DJBPrivateKey) Sign(random io.Reader, messages ...[]byte) ([]byte, error) {
	return d.key.Sign(random, messages...)
}
