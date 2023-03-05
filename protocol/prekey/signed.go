package prekey

import (
	"github.com/RTann/libsignal-go/protocol/curve"
	v1 "github.com/RTann/libsignal-go/protocol/generated/v1"
)

// SignedPreKey represents a public signed pre-key.
type SignedPreKey struct {
	signed *v1.SignedPreKeyRecordStructure
}

// NewSigned creates a new signed pre-key.
func NewSigned(id ID, timestamp uint64, key *curve.KeyPair, signature []byte) *SignedPreKey {
	return &SignedPreKey{
		signed: &v1.SignedPreKeyRecordStructure{
			Id:         uint32(id),
			PublicKey:  key.PublicKey().Bytes(),
			PrivateKey: key.PrivateKey().Bytes(),
			Signature:  signature,
			Timestamp:  timestamp,
		},
	}
}

// KeyPair returns the signed pre-key's public/private key pair.
func (s *SignedPreKey) KeyPair() (*curve.KeyPair, error) {
	return curve.NewKeyPairFromBytes(s.signed.GetPrivateKey(), s.signed.GetPublicKey())
}
