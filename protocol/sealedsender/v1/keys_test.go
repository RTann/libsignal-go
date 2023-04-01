package v1

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/RTann/libsignal-go/protocol/crypto/aes"
	"github.com/RTann/libsignal-go/protocol/curve"
	"github.com/RTann/libsignal-go/protocol/direction"
	"github.com/RTann/libsignal-go/protocol/identity"
)

func TestAgreementAndAuthN(t *testing.T) {
	senderIdentity, err := identity.GenerateKeyPair(rand.Reader)
	require.NoError(t, err)
	receiverIdentity, err := identity.GenerateKeyPair(rand.Reader)
	require.NoError(t, err)
	receiverKeyPair := keyPair(t, receiverIdentity)

	senderEphemeral, err := curve.GenerateKeyPair(rand.Reader)
	require.NoError(t, err)

	senderEphemeralKeys, err := DeriveEphemeralKeys(senderEphemeral, receiverIdentity.PublicKey(), direction.Sending)
	assert.NoError(t, err)

	senderCipherKey := senderEphemeralKeys.cipherKey
	senderChainKey := senderEphemeralKeys.chainKey
	senderMACKey := senderEphemeralKeys.macKey

	senderStaticKeyCiphertext, err := aes.CTRHMACSHA256Encrypt(senderCipherKey, senderMACKey, senderIdentity.PublicKey().Bytes())
	assert.NoError(t, err)

	senderStaticKeys, err := DeriveStaticKeys(senderIdentity, receiverIdentity.PublicKey(), senderChainKey, senderStaticKeyCiphertext)
	assert.NoError(t, err)

	plaintext := []byte("this is a binary message")
	ciphertext, err := aes.CTRHMACSHA256Encrypt(senderStaticKeys.cipherKey, senderStaticKeys.macKey, plaintext)
	assert.NoError(t, err)

	receiverEphemeralKeys, err := DeriveEphemeralKeys(receiverKeyPair, senderEphemeral.PublicKey(), direction.Receiving)
	assert.NoError(t, err)
	assert.Equal(t, senderEphemeralKeys, receiverEphemeralKeys)

	receiverCipherKey := receiverEphemeralKeys.cipherKey
	receiverChainKey := receiverEphemeralKeys.chainKey
	receiverMACKey := receiverEphemeralKeys.macKey

	receivedPublicKey, err := aes.CTRHMACSHA256Decrypt(receiverCipherKey, receiverMACKey, senderStaticKeyCiphertext)
	assert.NoError(t, err)

	senderPublicKey, err := curve.NewPublicKey(receivedPublicKey)
	assert.NoError(t, err)
	assert.True(t, senderPublicKey.Equal(senderIdentity.PublicKey()))

	receiverStaticKeys, err := DeriveStaticKeys(receiverIdentity, senderPublicKey, receiverChainKey, senderStaticKeyCiphertext)
	assert.NoError(t, err)

	receivedPlaintext, err := aes.CTRHMACSHA256Decrypt(receiverStaticKeys.cipherKey, receiverStaticKeys.macKey, ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, receivedPlaintext)
}

func keyPair(t *testing.T, identity identity.KeyPair) *curve.KeyPair {
	pair, err := curve.NewKeyPair(identity.PrivateKey().Bytes(), identity.PublicKey().Bytes())
	require.NoError(t, err)

	return pair
}
