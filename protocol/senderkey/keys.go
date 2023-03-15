package senderkey

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"

	v1 "github.com/RTann/libsignal-go/protocol/generated/v1"
)

const (
	ChainKeySize = 32

	info = "WhisperGroup"
)

var (
	messageKeySeed = []byte{0x01}
	chainKeySeed   = []byte{0x02}
)

type MessageKeys struct {
	cipherKey []byte
	iv        []byte
	seed      []byte
	iteration uint32
}

func DeriveMessageKeys(seed []byte, iteration uint32) (MessageKeys, error) {
	// 16 + 32 = 48
	derived := make([]byte, 48)
	kdf := hkdf.New(sha256.New, seed, nil, []byte(info))
	_, err := io.ReadFull(kdf, derived)
	if err != nil {
		return MessageKeys{}, err
	}

	return MessageKeys{
		cipherKey: derived[16:],
		iv:        derived[:16],
		seed:      seed,
		iteration: iteration,
	}, nil
}

func (m MessageKeys) CipherKey() []byte {
	return m.cipherKey
}

func (m MessageKeys) IV() []byte {
	return m.iv
}

func (m MessageKeys) Seed() []byte {
	return m.seed
}

func (m MessageKeys) Iteration() uint32 {
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

func (c ChainKey) MessageKeys() (MessageKeys, error) {
	return DeriveMessageKeys(hash(c.chainKey, messageKeySeed), c.iteration)
}

func hash(key, seed []byte) []byte {
	buf := make([]byte, 0, ChainKeySize)
	hash := hmac.New(sha256.New, key)
	hash.Write(seed)
	buf = hash.Sum(buf)
	return buf
}

func (c ChainKey) Proto() *v1.SenderKeyStateStructure_SenderChainKey {
	seed := make([]byte, len(c.chainKey))
	copy(seed, c.chainKey)

	return &v1.SenderKeyStateStructure_SenderChainKey{
		Iteration: c.iteration,
		Seed:      seed,
	}
}
