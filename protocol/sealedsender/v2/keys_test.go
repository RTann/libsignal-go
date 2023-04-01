package v2

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/RTann/libsignal-go/protocol/curve"
	"github.com/RTann/libsignal-go/protocol/direction"
	"github.com/RTann/libsignal-go/protocol/identity"
)

func TestAgreementAndAuthN(t *testing.T) {
	random := rand.Reader

	senderIdentity, err := identity.GenerateKeyPair(random)
	require.NoError(t, err)
	receiverIdentity, err := identity.GenerateKeyPair(random)
	require.NoError(t, err)
	receiverKeyPair := keyPair(t, receiverIdentity)

	msg := make([]byte, messageKeySize)
	_, err = io.ReadFull(random, msg)
	require.NoError(t, err)

	ephemeralKeys, err := DeriveEphemeralKeys(msg)
	assert.NoError(t, err)
	publicKey := ephemeralKeys.keyPair.PublicKey().Bytes()

	senderCiphertext, err := XORAgreement(ephemeralKeys.keyPair, receiverIdentity.PublicKey(), direction.Sending, msg)
	assert.NoError(t, err)
	senderAuthTag, err := AuthTag(senderIdentity, receiverIdentity.PublicKey(), direction.Sending, publicKey, senderCiphertext)
	assert.NoError(t, err)

	keyPair(t, receiverIdentity)
	receiveM, err := XORAgreement(receiverKeyPair, ephemeralKeys.keyPair.PublicKey(), direction.Receiving, senderCiphertext)
	assert.NoError(t, err)
	assert.Equal(t, msg, receiveM)

	receiveAuthTag, err := AuthTag(receiverIdentity, senderIdentity.PublicKey(), direction.Receiving, publicKey, senderCiphertext)
	assert.NoError(t, err)
	assert.Equal(t, senderAuthTag, receiveAuthTag)
}

func keyPair(t *testing.T, identity identity.KeyPair) *curve.KeyPair {
	pair, err := curve.NewKeyPair(identity.PrivateKey().Bytes(), identity.PublicKey().Bytes())
	require.NoError(t, err)

	return pair
}