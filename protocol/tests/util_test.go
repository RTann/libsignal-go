package tests

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/RTann/libsignal-go/protocol/curve"
	"github.com/RTann/libsignal-go/protocol/identity"
	"github.com/RTann/libsignal-go/protocol/protocol"
	"github.com/RTann/libsignal-go/protocol/ratchet"
	"github.com/RTann/libsignal-go/protocol/session"
)

func testInMemProtocolStore(t *testing.T, random io.Reader) protocol.Store {
	identityKeyPair, err := identity.GenerateKeyPair(random)
	require.NoError(t, err)

	registrationID := uint32(5)

	return protocol.NewInMemStore(identityKeyPair, registrationID)
}

func testInitRecordsV3(t *testing.T, random io.Reader) (*session.Record, *session.Record) {
	aliceIdentity, err := identity.GenerateKeyPair(random)
	require.NoError(t, err)
	bobIdentity, err := identity.GenerateKeyPair(random)
	require.NoError(t, err)

	aliceBaseKey, err := curve.GenerateKeyPair(random)
	require.NoError(t, err)

	bobBaseKey, err := curve.GenerateKeyPair(random)
	require.NoError(t, err)
	bobEphemeralKey := bobBaseKey

	aliceParams := &ratchet.AliceParameters{
		OurIdentityKeyPair: aliceIdentity,
		OurBaseKeyPair:     aliceBaseKey,
		TheirIdentityKey:   bobIdentity.IdentityKey,
		TheirSignedPreKey:  bobBaseKey.PublicKey,
		TheirOneTimePreKey: nil,
		TheirRatchetKey:    bobEphemeralKey.PublicKey,
	}
	aliceSession, err := session.InitializeAliceSessionRecord(random, aliceParams)
	require.NoError(t, err)

	bobParams := &ratchet.BobParameters{
		OurIdentityKeyPair:   bobIdentity,
		OurSignedPreKeyPair:  bobBaseKey,
		OurOneTimePreKeyPair: nil,
		OurRatchetKeyPair:    bobEphemeralKey,
		TheirIdentityKey:     aliceIdentity.IdentityKey,
		TheirBaseKey:         aliceBaseKey.PublicKey,
	}
	bobSession, err := session.InitializeBobSessionRecord(bobParams)
	require.NoError(t, err)

	return aliceSession, bobSession
}
