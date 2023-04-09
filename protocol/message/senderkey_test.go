package message

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/RTann/libsignal-go/protocol/curve"
	"github.com/RTann/libsignal-go/protocol/distribution"
)

func TestSenderKey(t *testing.T) {
	signatureKeyPair, err := curve.GenerateKeyPair(rand.Reader)
	require.NoError(t, err)
	
	senderKey1, err := NewSenderKey(rand.Reader, SenderKeyConfig{
		Version:      SenderKeyVersion,
		DistID:       distribution.MustParse("d1d1d1d1-7000-11eb-b32a-33b8a8a487a6"),
		ChainID:      42,
		Iteration:    7,
		Ciphertext:   []byte{1, 2, 3},
		SignatureKey: signatureKeyPair.PrivateKey(),
	})
	assert.NoError(t, err)

	senderKey2, err := NewSenderKeyFromBytes(senderKey1.Bytes())
	assert.NoError(t, err)

	assert.Equal(t, senderKey1.version, senderKey2.version)
	assert.Equal(t, senderKey1.distID, senderKey2.distID)
	assert.Equal(t, senderKey1.chainID, senderKey2.chainID)
	assert.Equal(t, senderKey1.iteration, senderKey2.iteration)
	assert.Equal(t, senderKey1.ciphertext, senderKey2.ciphertext)
	assert.Equal(t, senderKey1.serialized, senderKey2.serialized)
}
