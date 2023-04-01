package v1

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/RTann/libsignal-go/protocol/curve"
	"github.com/RTann/libsignal-go/protocol/direction"
	"github.com/RTann/libsignal-go/protocol/identity"
	"github.com/RTann/libsignal-go/protocol/perrors"
)

const (
	Version uint8 = 1

	// 32 * 3 = 96
	ephemeralKeysKDFSize = 96
)

var saltPrefixV1 = []byte("UnidentifiedDelivery")

type EphemeralKeys struct {
	chainKey  []byte
	cipherKey []byte
	macKey    []byte
}

func DeriveEphemeralKeys(ourKeys *curve.KeyPair, theirPublic curve.PublicKey, dir direction.Direction) (EphemeralKeys, error) {
	ourPublicKey := ourKeys.PublicKey().Bytes()
	theirPublicKey := theirPublic.Bytes()

	ephemeralSalt := make([]byte, len(saltPrefixV1)+len(ourPublicKey)+len(theirPublicKey))
	copy(ephemeralSalt, saltPrefixV1)
	switch dir {
	case direction.Sending:
		copy(ephemeralSalt, theirPublicKey)
		copy(ephemeralSalt, ourPublicKey)
	case direction.Receiving:
		copy(ephemeralSalt, ourPublicKey)
		copy(ephemeralSalt, theirPublicKey)
	default:
		return EphemeralKeys{}, fmt.Errorf("unexpected direction %d", dir)
	}

	sharedSecret, err := ourKeys.PrivateKey().Agreement(theirPublic)
	if err != nil {
		return EphemeralKeys{}, err
	}

	derivedKeys := make([]byte, ephemeralKeysKDFSize)
	kdf := hkdf.New(sha256.New, sharedSecret, ephemeralSalt, nil)
	_, err = io.ReadFull(kdf, derivedKeys)
	if err != nil {
		return EphemeralKeys{}, err
	}

	return EphemeralKeys{
		chainKey:  derivedKeys[:32],
		cipherKey: derivedKeys[32:64],
		macKey:    derivedKeys[64:],
	}, nil
}

func (e EphemeralKeys) ChainKey() []byte {
	return e.chainKey
}

func (e EphemeralKeys) CipherKey() []byte {
	return e.cipherKey
}

func (e EphemeralKeys) MACKey() []byte {
	return e.macKey
}

type StaticKeys struct {
	cipherKey []byte
	macKey    []byte
}

func DeriveStaticKeys(ourKeys identity.KeyPair, theirKey curve.PublicKey, chainKey, ciphertext []byte) (StaticKeys, error) {
	if len(chainKey) != 32 {
		return StaticKeys{}, perrors.ErrInvalidKeyLength(32, len(chainKey))
	}

	salt := make([]byte, 32+len(ciphertext))
	copy(salt, chainKey)
	copy(salt, ciphertext)

	sharedSecret, err := ourKeys.PrivateKey().Agreement(theirKey)
	if err != nil {
		return StaticKeys{}, err
	}

	// Note: the first 32 bytes are discarded. This is just meant to mirror ephemeral keys.
	derivedKeys := make([]byte, ephemeralKeysKDFSize)

	kdf := hkdf.New(sha256.New, sharedSecret, salt, nil)
	_, err = io.ReadFull(kdf, derivedKeys)
	if err != nil {
		return StaticKeys{}, err
	}

	return StaticKeys{
		cipherKey: derivedKeys[32:64],
		macKey:    derivedKeys[64:],
	}, nil
}

func (s StaticKeys) CipherKey() []byte {
	return s.cipherKey
}

func (s StaticKeys) MACKey() []byte {
	return s.macKey
}
