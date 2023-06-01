package prekey

import (
	"io"
	"time"

	"github.com/RTann/libsignal-go/protocol/curve"
	v1 "github.com/RTann/libsignal-go/protocol/generated/v1"
	"github.com/RTann/libsignal-go/protocol/kem"
)

// KyberPreKey represents a public Kyber pre-key.
type KyberPreKey struct {
	signed *v1.SignedPreKeyRecordStructure
}

// GenerateKyberPreKey generates a random key pair.
//
// It is recommended to use a cryptographic random reader.
// If random is nil, then [crypto/rand.Reader] is used.
func GenerateKyberPreKey(random io.Reader, keyType kem.KeyType, id ID, signingKey curve.PrivateKey) (*KyberPreKey, error) {
	keyPair, err := kem.GenerateKeyPair(random, keyType)
	if err != nil {
		return nil, err
	}

	signature, err := signingKey.Sign(random, keyPair.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}

	timestamp := time.Now().UnixMilli()
	if timestamp < 0 {
		// TODO
		panic("time moved backwards???")
	}
	return &KyberPreKey{
		signed: &v1.SignedPreKeyRecordStructure{
			Id:         uint32(id),
			PublicKey:  keyPair.PublicKey().Bytes(),
			PrivateKey: keyPair.PrivateKey().Bytes(),
			Signature:  signature,
			Timestamp:  uint64(timestamp),
		},
	}, nil
}

// KeyPair returns the signed pre-key's public/private key pair.
func (s *KyberPreKey) KeyPair() (kem.KeyPair, error) {
	return nil, nil
}
