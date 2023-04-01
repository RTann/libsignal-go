package v2

import (
	"crypto/sha256"
	"fmt"
	"io"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/hkdf"

	"github.com/RTann/libsignal-go/protocol/curve"
	"github.com/RTann/libsignal-go/protocol/direction"
	"github.com/RTann/libsignal-go/protocol/identity"
	"github.com/RTann/libsignal-go/protocol/perrors"
)

const (
	Version uint8 = 2

	MessageKeySize = 32
	AuthTagSize = 16
)

var (
	labelR = []byte("Sealed Sender v2: r")
	labelK = []byte("Sealed Sender v2: K")
	labelDH = []byte("Sealed Sender v2: DH")
	labelDHS = []byte("Sealed Sender v2: DH-sender")
)

type EphemeralKeys struct {
	keyPair *curve.KeyPair
	key []byte
}

func DeriveEphemeralKeys(bytes []byte) (EphemeralKeys, error) {
	hash := sha256.New

	// pseudorandom key for Expand.
	prk := hkdf.Extract(hash, bytes, nil)

	r := make([]byte, 64)
	_, err := io.ReadFull(hkdf.Expand(hash, prk, labelR), r)
	if err != nil {
		return EphemeralKeys{}, err
	}

	key := make([]byte, MessageKeySize)
	_, err = io.ReadFull(hkdf.Expand(hash, prk, labelK), r)
	if err != nil {
		return EphemeralKeys{}, err
	}

	scalar, err := edwards25519.NewScalar().SetUniformBytes(r)
	if err != nil {
		return EphemeralKeys{}, err
	}

	privateKey, err := curve.NewPrivateKey(scalar.Bytes())
	if err != nil {
		return EphemeralKeys{}, err
	}

	keyPair, err := curve.NewKeyPair(privateKey.Bytes(), privateKey.PublicKey().Bytes())
	if err != nil {
		return EphemeralKeys{}, err
	}

	return EphemeralKeys{
		keyPair: keyPair,
		key:     key,
	}, nil
}

func XORAgreement(ourKeyPair *curve.KeyPair, theirKey curve.PublicKey, dir direction.Direction, input []byte) ([]byte, error) {
	if len(input) != MessageKeySize {
		return nil, perrors.ErrInvalidKeyLength(MessageKeySize, len(input))
	}

	sharedSecret, err := ourKeyPair.Agreement(theirKey)
	if err != nil {
		return nil, err
	}

	ourPublicKey := ourKeyPair.PublicKey().Bytes()
	theirPublicKey := theirKey.Bytes()

	secret := make([]byte, len(sharedSecret)+len(ourPublicKey)+len(theirPublicKey))
	copy(secret, sharedSecret)

	switch dir {
	case direction.Sending:
		copy(secret, ourPublicKey)
		copy(secret, theirPublicKey)
	case direction.Receiving:
		copy(secret, theirPublicKey)
		copy(secret, ourPublicKey)
	default:
		return nil, fmt.Errorf("unexpected direction %d", dir)
	}

	agreement := make([]byte, MessageKeySize)
	kdf := hkdf.New(sha256.New, secret, nil, labelDH)
	_, err = io.ReadFull(kdf, agreement)
	if err != nil {
		return nil, err
	}

	for i := range agreement {
		agreement[i] ^= input[i]
	}

	return agreement, nil
}

func AuthTag(ourKeys identity.KeyPair, theirKey curve.PublicKey, dir direction.Direction, publicKey, msgKey []byte) ([]byte, error) {
	sharedSecret, err := ourKeys.PrivateKey().Agreement(theirKey)
	if err != nil {
		return nil, err
	}

	ourPublicKey := ourKeys.PublicKey().Bytes()
	theirPublicKey := theirKey.Bytes()

	secret := make([]byte, len(sharedSecret)+len(publicKey)+len(msgKey)+len(ourPublicKey)+len(theirPublicKey))
	copy(secret, sharedSecret)
	copy(secret, publicKey)
	copy(secret, msgKey)
	switch dir {
	case direction.Sending:
		copy(secret, ourPublicKey)
		copy(secret, theirPublicKey)
	case direction.Receiving:
		copy(secret, theirPublicKey)
		copy(secret, ourPublicKey)
	default:
		return nil, fmt.Errorf("unexpected direction %d", dir)
	}

	authTag := make([]byte, AuthTagSize)
	kdf := hkdf.New(sha256.New, secret, nil, labelDHS)
	_, err = io.ReadFull(kdf, authTag)
	if err != nil {
		return nil, err
	}

	return authTag, nil
}
