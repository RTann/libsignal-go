package curve

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignatures(t *testing.T) {
	keyPair, err := GenerateKeyPair(rand.Reader)
	assert.NoError(t, err)

	msg := make([]byte, 1024*1024)
	signature, err := keyPair.PrivateKey().Sign(rand.Reader, msg)
	assert.NoError(t, err)

	valid, err := keyPair.PublicKey().VerifySignature(signature, msg)
	assert.NoError(t, err)
	assert.True(t, valid)

	msg[0] ^= 0x01
	valid, err = keyPair.PublicKey().VerifySignature(signature, msg)
	assert.NoError(t, err)
	assert.False(t, valid)

	msg[0] ^= 0x01
	publicKey := keyPair.PrivateKey().PublicKey()
	valid, err = publicKey.VerifySignature(signature, msg)
	assert.NoError(t, err)
	assert.True(t, valid)

	valid, err = publicKey.VerifySignature(signature, msg[:7], msg[7:])
	assert.NoError(t, err)
	assert.True(t, valid)

	signature, err = keyPair.PrivateKey().Sign(rand.Reader, msg[:20], msg[20:])
	assert.NoError(t, err)
	valid, err = publicKey.VerifySignature(signature, msg)
	assert.NoError(t, err)
	assert.True(t, valid)
}
