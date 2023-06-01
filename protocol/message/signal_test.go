package message

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/RTann/libsignal-go/protocol/curve"
	"github.com/RTann/libsignal-go/protocol/identity"
)

func testSignalMsg(t *testing.T) *Signal {
	random := rand.Reader

	macKey := make([]byte, 32)
	_, err := io.ReadFull(random, macKey)
	require.NoError(t, err)

	ciphertext := make([]byte, 20)
	_, err = io.ReadFull(random, ciphertext)
	require.NoError(t, err)

	senderRatchetKeyPair, err := curve.GenerateKeyPair(random)
	require.NoError(t, err)
	senderIdentityKeyPair, err := identity.GenerateKeyPair(random)
	require.NoError(t, err)
	receiverIdentityKeyPair, err := identity.GenerateKeyPair(random)
	require.NoError(t, err)

	signal, err := NewSignal(SignalConfig{
		Version:             CiphertextVersion,
		MACKey:              macKey,
		SenderRatchetKey:    senderRatchetKeyPair.PublicKey(),
		PreviousCounter:     41,
		Counter:             42,
		Ciphertext:          ciphertext,
		SenderIdentityKey:   senderIdentityKeyPair.IdentityKey(),
		ReceiverIdentityKey: receiverIdentityKeyPair.IdentityKey(),
	})
	require.NoError(t, err)

	return signal.(*Signal)
}

func assertSignalEquals(t *testing.T, a, b *Signal) {
	assert.Equal(t, a.version, b.version)
	assert.True(t, a.senderRatchetKey.Equal(b.senderRatchetKey))
	assert.Equal(t, a.counter, b.counter)
	assert.Equal(t, a.previousCounter, b.previousCounter)
	assert.Equal(t, a.ciphertext, b.ciphertext)
	assert.Equal(t, a.serialized, b.serialized)
}

func TestSignal(t *testing.T) {
	msg1 := testSignalMsg(t)
	msg2, err := NewSignalFromBytes(msg1.Bytes())
	assert.NoError(t, err)
	assertSignalEquals(t, msg1, msg2.(*Signal))
}
