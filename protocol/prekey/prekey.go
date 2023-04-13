// Package prekey defines a pre-key and signed pre-key.
package prekey

import (
	"strconv"

	"github.com/RTann/libsignal-go/protocol/curve"
	v1 "github.com/RTann/libsignal-go/protocol/generated/v1"
)

// ID represents a pre-key identifier.
type ID uint32

func (i ID) String() string {
	return strconv.FormatUint(uint64(i), 10)
}

// PreKey represents a public pre-key.
type PreKey struct {
	preKey *v1.PreKeyRecordStructure
}

// NewPreKey creates a new pre-key.
func NewPreKey(id ID, key curve.KeyPair) PreKey {
	return PreKey{
		preKey: &v1.PreKeyRecordStructure{
			Id:         uint32(id),
			PublicKey:  key.PublicKey().Bytes(),
			PrivateKey: key.PrivateKey().Bytes(),
		},
	}
}

// KeyPair returns the pre-key's public/private key pair.
func (s *PreKey) KeyPair() (curve.KeyPair, error) {
	return curve.NewKeyPair(s.preKey.GetPrivateKey(), s.preKey.GetPublicKey())
}
