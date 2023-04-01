// Package senderkey defines the keys required to
// send and receive encrypted messages in a group.
package senderkey

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	ChainKeySize = 32

	info = "WhisperGroup"
)

var (
	messageKeySeed = []byte{0x01}
	chainKeySeed   = []byte{0x02}
)

type MessageKey struct {
	cipherKey []byte
	iv        []byte
	seed      []byte
	iteration uint32
}

func DeriveMessageKey(seed []byte, iteration uint32) (MessageKey, error) {
	// 16 + 32 = 48
	derived := make([]byte, 48)
	kdf := hkdf.New(sha256.New, seed, nil, []byte(info))
	_, err := io.ReadFull(kdf, derived)
	if err != nil {
		return MessageKey{}, err
	}

	return MessageKey{
		cipherKey: derived[16:],
		iv:        derived[:16],
		seed:      seed,
		iteration: iteration,
	}, nil
}

func (m MessageKey) CipherKey() []byte {
	return m.cipherKey
}

func (m MessageKey) IV() []byte {
	return m.iv
}

func (m MessageKey) Seed() []byte {
	return m.seed
}

func (m MessageKey) Iteration() uint32 {
	return m.iteration
}

type ChainKey struct {
	iteration uint32
	chainKey  []byte
}

func NewChainKey(chainKey []byte, iteration uint32) ChainKey {
	return ChainKey{
		chainKey:  chainKey,
		iteration: iteration,
	}
}

func (c ChainKey) Iteration() uint32 {
	return c.iteration
}

func (c ChainKey) Seed() []byte {
	return c.chainKey
}

func (c ChainKey) Next() ChainKey {
	return ChainKey{
		iteration: c.iteration + 1,
		chainKey:  hash(c.chainKey, chainKeySeed),
	}
}

func (c ChainKey) MessageKey() (MessageKey, error) {
	return DeriveMessageKey(hash(c.chainKey, messageKeySeed), c.iteration)
}

func hash(key, seed []byte) []byte {
	buf := make([]byte, 0, ChainKeySize)
	hash := hmac.New(sha256.New, key)
	hash.Write(seed)
	buf = hash.Sum(buf)
	return buf
}
