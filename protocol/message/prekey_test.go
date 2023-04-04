package message

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/RTann/libsignal-go/protocol/curve"
	"github.com/RTann/libsignal-go/protocol/identity"
)

func TestPreKey(t *testing.T) {
	random := rand.Reader

	identityKeyPair, err := identity.GenerateKeyPair(random)
	require.NoError(t, err)
	baseKeyPair, err := curve.GenerateKeyPair(random)
	require.NoError(t, err)
	signalMsg := testSignalMsg(t)

	preKey1, err := NewPreKey(PreKeyConfig{
		Version:        3,
		RegistrationID: 365,
		PreKeyID:       nil,
		SignedPreKeyID: 97,
		BaseKey:        baseKeyPair.PublicKey(),
		IdentityKey:    identityKeyPair.IdentityKey(),
		Message:        signalMsg,
	})
	assert.NoError(t, err)

	preKey2, err := NewPreKeyFromBytes(preKey1.Bytes())
	assert.NoError(t, err)

	msg1, msg2 := preKey1.(*PreKey), preKey2.(*PreKey)

	assert.Equal(t, msg1.version, msg2.version)
	assert.Equal(t, msg1.registrationID, msg2.registrationID)
	assert.Equal(t, msg1.preKeyID, msg2.preKeyID)
	assert.Equal(t, msg1.signedPreKeyID, msg2.signedPreKeyID)
	assert.True(t, msg1.baseKey.Equal(msg2.baseKey))
	assert.True(t, msg1.identityKey.Equal(msg2.identityKey))
	assertSignalEquals(t, msg1.message, msg2.message)
	assert.Equal(t, msg1.serialized, msg2.serialized)
}
