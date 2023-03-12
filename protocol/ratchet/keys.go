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
	rootInfo    = "WhisperRatchet"
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

// NewMessageKeys derives message keys from the given inputs.
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

// DeriveMessageKeys derives message keys from the given input material and counter.
//
// The input material is used as the secret for HKDF.
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

// CipherKey returns a block cipher key.
func (m MessageKeys) CipherKey() []byte {
	return m.cipherKey
}

// MACKey returns a key used for a MAC function like HMAC.
func (m MessageKeys) MACKey() []byte {
	return m.macKey
}

// IV returns an initialization vector used
// for encryption and decryption.
func (m MessageKeys) IV() []byte {
	return m.iv
}

// Counter returns the corresponding index in the chain.
func (m MessageKeys) Counter() uint32 {
	return m.counter
}

// ChainKey represents a sending or receiving chain key
// used for Symmetric-key ratchet.
type ChainKey struct {
	key   []byte
	index uint32
}

// NewChainKey derives a chain key from the given key and index.
func NewChainKey(key []byte, index uint32) (ChainKey, error) {
	if len(key) != ChainKeySize {
		return ChainKey{}, perrors.ErrInvalidKeyLength(ChainKeySize, len(key))
	}

	return ChainKey{
		key:   key,
		index: index,
	}, nil
}

// Index returns the index of chain key in the
// sending or receiving chain.
func (c ChainKey) Index() uint32 {
	return c.index
}

// Key returns an encoding of the chain key.
func (c ChainKey) Key() []byte {
	return c.key
}

// Next derives the next chain key in the
// sending or receiving chain.
func (c ChainKey) Next() ChainKey {
	return ChainKey{
		key:   hash(c.key, chainKeySeed),
		index: c.index + 1,
	}
}

// MessageKeys performs a Symmetric-key ratchet step
// to derive new message keys.
func (c ChainKey) MessageKeys() (MessageKeys, error) {
	return DeriveMessageKeys(hash(c.key, messageKeySeed), c.index)
}

// hash returns the HMAC hash of the seed using the given key.
func hash(key, seed []byte) []byte {
	buf := make([]byte, 0, ChainKeySize)
	hash := hmac.New(sha256.New, key)
	hash.Write(seed)
	buf = hash.Sum(buf)
	return buf
}

// RootKey is a key used for the root chain in the Double Ratchet algorithm.
type RootKey struct {
	key []byte
}

// NewRootKey derives a root key from the given bytes.
func NewRootKey(key []byte) (RootKey, error) {
	if len(key) != RootKeySize {
		return RootKey{}, perrors.ErrInvalidKeyLength(RootKeySize, len(key))
	}

	return RootKey{
		key: key,
	}, nil
}

// Bytes returns an encoding of the root key.
func (r RootKey) Bytes() []byte {
	return r.key
}

// CreateChain performs a single Diffie-Hellman ratchet step to
// create a new root key and chain key.
func (r RootKey) CreateChain(ourRatchetKey curve.PrivateKey, theirRatchetKey curve.PublicKey) (RootKey, ChainKey, error) {
	sharedSecret, err := ourRatchetKey.Agreement(theirRatchetKey)
	if err != nil {
		return RootKey{}, ChainKey{}, err
	}

	derivedSecret := make([]byte, 64)
	kdf := hkdf.New(sha256.New, sharedSecret, r.key, []byte(rootInfo))
	_, err = io.ReadFull(kdf, derivedSecret)
	if err != nil {
		return RootKey{}, ChainKey{}, err
	}

	rootKey, err := NewRootKey(derivedSecret[:32])
	if err != nil {
		return RootKey{}, ChainKey{}, err
	}

	chainKey, err := NewChainKey(derivedSecret[32:], 0)
	if err != nil {
		return RootKey{}, ChainKey{}, err
	}

	return rootKey, chainKey, nil
}
