// Package ratchet defines the keys and parameters required to perform
// the Double Ratchet algorithm to send and receive encrypted messages.
package ratchet

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

var (
	initRootInfo      = []byte("WhisperText")
	initKyberRootInfo = []byte("WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024")
)

// DeriveKeys derives a root key and chain key based on the secret input
// for the root KDF chain.
func DeriveKeys(secretInput []byte, kyber bool) (RootKey, ChainKey, error) {
	info := initRootInfo
	if kyber {
		info = initKyberRootInfo
	}

	secrets := make([]byte, 64)
	kdf := hkdf.New(sha256.New, secretInput, nil, info)
	_, err := io.ReadFull(kdf, secrets)
	if err != nil {
		return RootKey{}, ChainKey{}, err
	}

	rootKey, err := NewRootKey(secrets[:32])
	if err != nil {
		return RootKey{}, ChainKey{}, err
	}

	chainKey, err := NewChainKey(secrets[32:], 0)
	if err != nil {
		return RootKey{}, ChainKey{}, err
	}

	return rootKey, chainKey, nil
}
