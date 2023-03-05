// Package ratchet defines the keys and parameters required to perform
// the double ratchet algorithm to send and receive encrypted messages.
package ratchet

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

const info = "WhisperText"

// DeriveKeys derives a KDF chain root-key and chain-key based on the secret input.
func DeriveKeys(secretInput []byte) (RootKey, ChainKey, error) {
	secrets := make([]byte, 64)
	kdf := hkdf.New(sha256.New, secretInput, nil, []byte(info))
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
