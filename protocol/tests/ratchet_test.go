package tests

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/RTann/libsignal-go/protocol/curve"
	"github.com/RTann/libsignal-go/protocol/identity"
	"github.com/RTann/libsignal-go/protocol/ratchet"
	"github.com/RTann/libsignal-go/protocol/session"
)

func TestBobSession(t *testing.T) {
	bobEphemeralPublic, err := hex.DecodeString("052cb49776b8770205745a3a6e24f579cdb4ba7a89041005928ebbadc9c05ad458")
	require.NoError(t, err)
	bobEphemeralPrivate, err := hex.DecodeString("a1cab48f7c893fafa9880a28c3b4999d28d6329562d27a4ea4e22e9ff1bdd65a")
	require.NoError(t, err)
	bobIdentityPublic, err := hex.DecodeString("05f1f43874f6966956c2dd473f8fa15adeb71d1cb991b2341692324cefb1c5e626")
	require.NoError(t, err)
	bobIdentityPrivate, err := hex.DecodeString("4875cc69ddf8ea0719ec947d61081135868d5fd801f02c0225e516df2156605e")
	require.NoError(t, err)
	aliceBasePublic, err := hex.DecodeString("05472d1fb1a9862c3af6beaca8920277e2b26f4a79213ec7c906aeb35e03cf8950")
	require.NoError(t, err)
	aliceIdentityPublic, err := hex.DecodeString("05b4a8455660ada65b401007f615e654041746432e3339c6875149bceefcb42b4a")
	require.NoError(t, err)
	bobSignedPreKeyPublic, err := hex.DecodeString("05ac248a8f263be6863576eb0362e28c828f0107a3379d34bab1586bf8c770cd67")
	require.NoError(t, err)
	bobSignedPreKeyPrivate, err := hex.DecodeString("583900131fb727998b7803fe6ac22cc591f342e4e42a8c8d5d78194209b8d253")
	require.NoError(t, err)

	expectedSenderChain := "9797caca53c989bbe229a40ca7727010eb2604fc14945d77958a0aeda088b44d"

	bobIdentityKeyPrivate, err := curve.NewPrivateKey(bobIdentityPrivate)
	require.NoError(t, err)
	bobIdentityKeyPublic, err := identity.NewKey(bobIdentityPublic)
	require.NoError(t, err)
	bobIdentityKeyPair := identity.NewKeyPair(bobIdentityKeyPrivate, bobIdentityKeyPublic)

	bobEphemeralPair, err := curve.NewKeyPair(bobEphemeralPrivate, bobEphemeralPublic)
	require.NoError(t, err)
	bobSignedPreKeyPair, err := curve.NewKeyPair(bobSignedPreKeyPrivate, bobSignedPreKeyPublic)
	require.NoError(t, err)

	aliceIdentityPublicKey, err := identity.NewKey(aliceIdentityPublic)
	require.NoError(t, err)
	aliceBasePublicKey, err := curve.NewPublicKey(aliceBasePublic)
	require.NoError(t, err)

	bobParams := &ratchet.BobParameters{
		OurIdentityKeyPair:   bobIdentityKeyPair,
		OurSignedPreKeyPair:  bobSignedPreKeyPair,
		OurOneTimePreKeyPair: nil,
		OurRatchetKeyPair:    bobEphemeralPair,
		TheirIdentityKey:     aliceIdentityPublicKey,
		TheirBaseKey:         aliceBasePublicKey,
	}

	bobRecord, err := session.InitializeBobSessionRecord(bobParams)
	assert.NoError(t, err)

	bobLocalIdentityKey, err := bobRecord.LocalIdentityKey()
	assert.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(bobIdentityPublic), hex.EncodeToString(bobLocalIdentityKey.Bytes()))

	bobRemoteIdentityKey, exists, err := bobRecord.RemoteIdentityKey()
	assert.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, hex.EncodeToString(aliceIdentityPublic), hex.EncodeToString(bobRemoteIdentityKey.Bytes()))

	bobSenderChainKey, err := bobRecord.SenderChainKey()
	assert.NoError(t, err)
	assert.Equal(t, expectedSenderChain, hex.EncodeToString(bobSenderChainKey.Key()))
}

func TestAliceSession(t *testing.T) {
	bobEphemeralPublic, err := hex.DecodeString("052cb49776b8770205745a3a6e24f579cdb4ba7a89041005928ebbadc9c05ad458")
	require.NoError(t, err)
	bobIdentityPublic, err := hex.DecodeString("05f1f43874f6966956c2dd473f8fa15adeb71d1cb991b2341692324cefb1c5e626")
	require.NoError(t, err)
	aliceBasePublic, err := hex.DecodeString("05472d1fb1a9862c3af6beaca8920277e2b26f4a79213ec7c906aeb35e03cf8950")
	require.NoError(t, err)
	aliceBasePrivate, err := hex.DecodeString("11ae7c64d1e61cd596b76a0db5012673391cae66edbfcf073b4da80516a47449")
	require.NoError(t, err)
	bobSignedPrePublic, err := hex.DecodeString("05ac248a8f263be6863576eb0362e28c828f0107a3379d34bab1586bf8c770cd67")
	require.NoError(t, err)
	aliceIdentityPublic, err := hex.DecodeString("05b4a8455660ada65b401007f615e654041746432e3339c6875149bceefcb42b4a")
	require.NoError(t, err)
	aliceIdentityPrivate, err := hex.DecodeString("9040f0d4e09cf38f6dc7c13779c908c015a1da4fa78737a080eb0a6f4f5f8f58")
	require.NoError(t, err)

	expectedReceiverChain := "ab9be50e5cb22a925446ab90ee5670545f4fd32902459ec274b6ad0ae5d6031a"

	aliceIdentityKeyPrivate, err := curve.NewPrivateKey(aliceIdentityPrivate)
	require.NoError(t, err)
	aliceIdentityKeyPublic, err := identity.NewKey(aliceIdentityPublic)
	require.NoError(t, err)
	aliceIdentityKeyPair := identity.NewKeyPair(aliceIdentityKeyPrivate, aliceIdentityKeyPublic)

	aliceBaseKeyPair, err := curve.NewKeyPair(aliceBasePrivate, aliceBasePublic)
	require.NoError(t, err)

	bobIdentityKey, err := identity.NewKey(bobIdentityPublic)
	require.NoError(t, err)

	bobEphemeralKeyPublic, err := curve.NewPublicKey(bobEphemeralPublic)
	require.NoError(t, err)
	bobSignedPreKeyPublic, err := curve.NewPublicKey(bobSignedPrePublic)
	require.NoError(t, err)

	aliceParams := &ratchet.AliceParameters{
		OurIdentityKeyPair: aliceIdentityKeyPair,
		OurBaseKeyPair:     aliceBaseKeyPair,
		TheirIdentityKey:   bobIdentityKey,
		TheirSignedPreKey:  bobSignedPreKeyPublic,
		TheirOneTimePreKey: nil,
		TheirRatchetKey:    bobEphemeralKeyPublic,
	}

	aliceRecord, err := session.InitializeAliceSessionRecord(rand.Reader, aliceParams)
	assert.NoError(t, err)

	aliceLocalIdentityKey, err := aliceRecord.LocalIdentityKey()
	assert.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(aliceIdentityPublic), hex.EncodeToString(aliceLocalIdentityKey.Bytes()))

	aliceRemoteIdentityKey, exists, err := aliceRecord.RemoteIdentityKey()
	assert.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, hex.EncodeToString(bobIdentityPublic), hex.EncodeToString(aliceRemoteIdentityKey.Bytes()))

	aliceReceiverChainKey, exists, err := aliceRecord.ReceiverChainKey(bobEphemeralKeyPublic)
	assert.NoError(t, err)
	assert.True(t, exists)
	assert.Equal(t, expectedReceiverChain, hex.EncodeToString(aliceReceiverChainKey.Key()))
}
