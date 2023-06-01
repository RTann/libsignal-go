package kem

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKyber1024KeyPair(t *testing.T) {
	keyType := KeyTypeKyber1024
	keyPair, err := GenerateKeyPair(rand.Reader, keyType)
	assert.NoError(t, err)
	assert.Len(t, keyPair.PrivateKey().Bytes(), 1+keyType.PrivateKeySize())
	assert.Len(t, keyPair.PublicKey().Bytes(), 1+keyType.PublicKeySize())
	senderSharedSecret, ciphertext := keyPair.PublicKey().Encapsulate()
	assert.Len(t, ciphertext, 1+keyType.CiphertextSize())
	assert.Len(t, senderSharedSecret, keyType.SharedKeySize())
	recipientSharedSecret, err := keyPair.PrivateKey().Decapsulate(ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, senderSharedSecret, recipientSharedSecret)
}
