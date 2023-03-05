package fingerprint

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/RTann/libsignal-go/protocol/identity"
)

const (
	aliceIdentityHex = "0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868"
	bobIdentityHex   = "05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b"

	displayableFingerprintV1 = "300354477692869396892869876765458257569162576843440918079131"

	aliceScannableFingerprintV1 = "080112220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df1a220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d"
	bobScannableFingerprintV1   = "080112220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d1a220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df"

	aliceScannableFingerprintV2 = "080212220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df1a220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d"
	bobScannableFingerprintV2   = "080212220a20d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d1a220a201e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df"
)

var (
	aliceStableID = []byte("+14152222222")
	bobStableID   = []byte("+14153333333")
)

func TestFingerprint_V1(t *testing.T) {
	aliceIdentity, err := hex.DecodeString(aliceIdentityHex)
	require.NoError(t, err)
	bobIdentity, err := hex.DecodeString(bobIdentityHex)
	require.NoError(t, err)

	aKey, err := identity.NewKeyFromBytes(aliceIdentity)
	require.NoError(t, err)
	bKey, err := identity.NewKeyFromBytes(bobIdentity)
	require.NoError(t, err)

	version := uint32(1)
	iterations := uint32(5200)

	aFprint, err := New(version, iterations, aliceStableID, aKey, bobStableID, bKey)
	assert.NoError(t, err)
	bFprint, err := New(version, iterations, bobStableID, bKey, aliceStableID, aKey)
	assert.NoError(t, err)

	aScannableBytes, err := aFprint.scannable.Bytes()
	require.NoError(t, err)
	assert.Equal(t, aliceScannableFingerprintV1, hex.EncodeToString(aScannableBytes))
	bScannableBytes, err := bFprint.scannable.Bytes()
	require.NoError(t, err)
	assert.Equal(t, bobScannableFingerprintV1, hex.EncodeToString(bScannableBytes))

	assert.Equal(t, displayableFingerprintV1, aFprint.displayable.String())
	assert.Equal(t, displayableFingerprintV1, bFprint.displayable.String())
}

func TestFingerprint_V2(t *testing.T) {
	aliceIdentity, err := hex.DecodeString(aliceIdentityHex)
	require.NoError(t, err)
	bobIdentity, err := hex.DecodeString(bobIdentityHex)
	require.NoError(t, err)

	aKey, err := identity.NewKeyFromBytes(aliceIdentity)
	require.NoError(t, err)
	bKey, err := identity.NewKeyFromBytes(bobIdentity)
	require.NoError(t, err)

	version := uint32(2)
	iterations := uint32(5200)

	aFprint, err := New(version, iterations, aliceStableID, aKey, bobStableID, bKey)
	assert.NoError(t, err)
	bFprint, err := New(version, iterations, bobStableID, bKey, aliceStableID, aKey)
	assert.NoError(t, err)

	aScannableBytes, err := aFprint.scannable.Bytes()
	require.NoError(t, err)
	assert.Equal(t, aliceScannableFingerprintV2, hex.EncodeToString(aScannableBytes))
	bScannableBytes, err := bFprint.scannable.Bytes()
	require.NoError(t, err)
	assert.Equal(t, bobScannableFingerprintV2, hex.EncodeToString(bScannableBytes))

	assert.Equal(t, displayableFingerprintV1, aFprint.displayable.String())
	assert.Equal(t, displayableFingerprintV1, bFprint.displayable.String())
}

func TestFingerprint_MatchingIdentifiers(t *testing.T) {
	aKeyPair, err := identity.GenerateKeyPair(rand.Reader)
	require.NoError(t, err)
	bKeyPair, err := identity.GenerateKeyPair(rand.Reader)
	require.NoError(t, err)

	aKey := aKeyPair.IdentityKey()
	bKey := bKeyPair.IdentityKey()

	version := uint32(1)
	iterations := uint32(1024)

	aFprint, err := New(version, iterations, aliceStableID, aKey, bobStableID, bKey)
	assert.NoError(t, err)
	bFprint, err := New(version, iterations, bobStableID, bKey, aliceStableID, aKey)
	assert.NoError(t, err)

	assert.Equal(t, aFprint.displayable.String(), bFprint.displayable.String())
	assert.Len(t, aFprint.displayable.String(), 60)

	aScannable, err := aFprint.scannable.Bytes()
	require.NoError(t, err)
	bScannable, err := bFprint.scannable.Bytes()
	require.NoError(t, err)
	equal, err := aFprint.scannable.Compare(bScannable)
	assert.NoError(t, err)
	assert.True(t, equal)
	equal, err = bFprint.scannable.Compare(aScannable)
	assert.NoError(t, err)
	assert.True(t, equal)
}

func TestFingerprint_MismatchingVersions(t *testing.T) {
	aKeyPair, err := identity.GenerateKeyPair(rand.Reader)
	require.NoError(t, err)
	bKeyPair, err := identity.GenerateKeyPair(rand.Reader)
	require.NoError(t, err)

	aKey := aKeyPair.IdentityKey()
	bKey := bKeyPair.IdentityKey()

	iterations := uint32(5200)

	aFprintV1, err := New(uint32(1), iterations, aliceStableID, aKey, bobStableID, bKey)
	assert.NoError(t, err)
	aFprintV2, err := New(uint32(2), iterations, aliceStableID, aKey, bobStableID, bKey)
	assert.NoError(t, err)

	assert.Equal(t, aFprintV1.displayable.String(), aFprintV2.displayable.String())
	aV1Scannable, err := aFprintV1.scannable.Bytes()
	require.NoError(t, err)
	aV2Scannable, err := aFprintV2.scannable.Bytes()
	require.NoError(t, err)
	assert.NotEqual(t, hex.EncodeToString(aV1Scannable), hex.EncodeToString(aV2Scannable))
}
