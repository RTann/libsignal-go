package ratchet

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/RTann/libsignal-go/protocol/curve"
	"github.com/RTann/libsignal-go/protocol/perrors"
)

const (
	cipherKeySize   = 32
	macKeySize      = 32
	ivSize          = 16
	messageKeysInfo = "WhisperMessageKeys"

	ChainKeySize = 32

	RootKeySize = 32
	ratchetInfo = "WhisperRatchet"
)

var (
	messageKeySeed = []byte{0x01}
	chainKeySeed   = []byte{0x02}
)

// MessageKeys defines the keys used to encrypt messages.
type MessageKeys struct {
	cipherKey []byte
	macKey    []byte
	// initialization vector
	iv      []byte
	counter uint32
}

// NewMessageKeys creates message keys.
func NewMessageKeys(cipherKey, macKey, iv []byte, counter uint32) (MessageKeys, error) {
	if len(cipherKey) != cipherKeySize {
		return MessageKeys{}, perrors.ErrInvalidKeyLength(cipherKeySize, len(cipherKey))
	}
	if len(macKey) != macKeySize {
		return MessageKeys{}, perrors.ErrInvalidKeyLength(macKeySize, len(macKey))
	}
	if len(iv) != ivSize {
		return MessageKeys{}, perrors.ErrInvalidKeyLength(ivSize, len(iv))
	}

	return MessageKeys{
		cipherKey: cipherKey,
		macKey:    macKey,
		iv:        iv,
		counter:   counter,
	}, nil
}

func (m MessageKeys) CipherKey() []byte {
	return m.cipherKey
}

func (m MessageKeys) MACKey() []byte {
	return m.macKey
}

func (m MessageKeys) IV() []byte {
	return m.iv
}

func (m MessageKeys) Counter() uint32 {
	return m.counter
}

// DeriveMessageKeys creates message keys from the given input material and counter.
func DeriveMessageKeys(inputKeyMaterial []byte, counter uint32) (MessageKeys, error) {
	kdf := hkdf.New(sha256.New, inputKeyMaterial, nil, []byte(messageKeysInfo))
	// 32 + 32 + 16 = 80
	outputKeyMaterial := make([]byte, 80)
	_, err := io.ReadFull(kdf, outputKeyMaterial)
	if err != nil {
		return MessageKeys{}, err
	}

	return MessageKeys{
		cipherKey: outputKeyMaterial[:32],
		macKey:    outputKeyMaterial[32:64],
		iv:        outputKeyMaterial[64:],
		counter:   counter,
	}, nil
}

type ChainKey struct {
	key   []byte
	index uint32
}

func NewChainKey(key []byte, index uint32) (ChainKey, error) {
	if len(key) != ChainKeySize {
		return ChainKey{}, perrors.ErrInvalidKeyLength(ChainKeySize, len(key))
	}

	return ChainKey{
		key:   key,
		index: index,
	}, nil
}

func (c ChainKey) Index() uint32 {
	return c.index
}

func (c ChainKey) Key() []byte {
	return c.key
}

func (c ChainKey) Next() ChainKey {
	return ChainKey{
		key:   hash(c.key, chainKeySeed),
		index: c.index + 1,
	}
}

func (c ChainKey) MessageKeys() (MessageKeys, error) {
	return DeriveMessageKeys(hash(c.key, messageKeySeed), c.index)
}

func hash(key, seed []byte) []byte {
	buf := make([]byte, 0, ChainKeySize)
	hash := hmac.New(sha256.New, key)
	hash.Write(seed)
	buf = hash.Sum(buf)
	return buf
}

type RootKey struct {
	key []byte
}

func NewRootKey(key []byte) (RootKey, error) {
	if len(key) != RootKeySize {
		return RootKey{}, perrors.ErrInvalidKeyLength(RootKeySize, len(key))
	}

	return RootKey{
		key: key,
	}, nil
}

func (r RootKey) Bytes() []byte {
	return r.key
}

func (r RootKey) CreateChain(ourRatchetKey curve.PrivateKey, theirRatchetKey curve.PublicKey) (RootKey, ChainKey, error) {
	sharedSecret, err := ourRatchetKey.Agreement(theirRatchetKey)
	if err != nil {
		return RootKey{}, ChainKey{}, err
	}

	derivedSecret := make([]byte, 64)
	kdf := hkdf.New(sha256.New, sharedSecret, r.key, []byte(ratchetInfo))
	_, err = io.ReadFull(kdf, derivedSecret)
	if err != nil {
		return RootKey{}, ChainKey{}, err
	}

	rootKey := RootKey{
		key: derivedSecret[:32],
	}
	chainKey := ChainKey{
		key:   derivedSecret[32:],
		index: 0,
	}

	return rootKey, chainKey, nil
}
