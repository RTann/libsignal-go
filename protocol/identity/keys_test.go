package identity

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentityKey(t *testing.T) {
	pair, err := GenerateKeyPair(rand.Reader)
	require.NoError(t, err)

	key := Key{PublicKey: pair.PublicKey()}
	assert.Equal(t, pair.PublicKey().Bytes(), key.Bytes())
}

func TestSignAlternateIdentity(t *testing.T) {
	random := rand.Reader

	primary, err := GenerateKeyPair(random)
	require.NoError(t, err)
	secondary, err := GenerateKeyPair(random)
	require.NoError(t, err)

	signature, err := secondary.SignAlternateIdentity(random, primary.IdentityKey)
	assert.NoError(t, err)
	valid, err := secondary.IdentityKey.VerifyAlternateIdentity(signature, primary.IdentityKey)
	assert.NoError(t, err)
	assert.True(t, valid)
	// Should not be symmetric.
	valid, err = primary.IdentityKey.VerifyAlternateIdentity(signature, secondary.IdentityKey)
	assert.NoError(t, err)
	assert.False(t, valid)

	anotherSignature, err := secondary.SignAlternateIdentity(random, primary.IdentityKey)
	assert.NoError(t, err)
	assert.NotEqual(t, signature, anotherSignature)
	valid, err = secondary.IdentityKey.VerifyAlternateIdentity(anotherSignature, primary.IdentityKey)
	assert.NoError(t, err)
	assert.True(t, valid)

	unrelated, err := GenerateKeyPair(random)
	require.NoError(t, err)
	valid, err = secondary.IdentityKey.VerifyAlternateIdentity(signature, unrelated.IdentityKey)
	assert.NoError(t, err)
	assert.False(t, valid)
	valid, err = unrelated.IdentityKey.VerifyAlternateIdentity(signature, primary.IdentityKey)
	assert.NoError(t, err)
	assert.False(t, valid)
}
