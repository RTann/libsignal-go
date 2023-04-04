package curve

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicKeySize(t *testing.T) {
	keyPair, err := GenerateKeyPair(rand.Reader)
	require.NoError(t, err)

	publicBytes := keyPair.PublicKey().Bytes()
	assert.Equal(t, publicBytes, keyPair.PrivateKey().PublicKey().Bytes())

	goodPublicKey, err := NewPublicKey(publicBytes)
	assert.NoError(t, err)
	_, err = NewPublicKey(publicBytes[1:])
	assert.Error(t, err)
	_, err = NewPublicKey([]byte{})
	assert.Error(t, err)

	badType := make([]byte, len(publicBytes))
	copy(badType, publicBytes)
	badType[0] = 0x01
	_, err = NewPublicKey(badType)
	assert.Error(t, err)

	large := make([]byte, len(publicBytes)+1)
	copy(large, publicBytes)
	largePublicKey, err := NewPublicKey(large)
	assert.NoError(t, err)

	assert.Equal(t, publicBytes, goodPublicKey.Bytes())
	assert.Equal(t, publicBytes, largePublicKey.Bytes())
}
