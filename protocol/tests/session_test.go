package tests

import (
	"context"
	"crypto/rand"
	"fmt"
	mathrand "math/rand"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/RTann/libsignal-go/protocol/address"
	"github.com/RTann/libsignal-go/protocol/curve"
	"github.com/RTann/libsignal-go/protocol/internal/pointer"
	"github.com/RTann/libsignal-go/protocol/message"
	"github.com/RTann/libsignal-go/protocol/perrors"
	"github.com/RTann/libsignal-go/protocol/prekey"
	"github.com/RTann/libsignal-go/protocol/session"
)

var (
	ctx    = context.Background()
	random = rand.Reader
)

func TestPreKey(t *testing.T) {
	aliceAddress := address.Address{
		Name:     "+14151111111",
		DeviceID: address.DeviceID(1),
	}
	bobAddress := address.Address{
		Name:     "+14151111112",
		DeviceID: address.DeviceID(1),
	}

	aliceStore := testInMemProtocolStore(t, random)
	bobStore := testInMemProtocolStore(t, random)

	bobPreKeyPair, err := curve.GenerateKeyPair(random)
	require.NoError(t, err)
	bobSignedPreKeyPair, err := curve.GenerateKeyPair(random)
	require.NoError(t, err)

	bobSignedPreKeyPublic := bobSignedPreKeyPair.PublicKey().Bytes()
	bobSignedPreKeySignature, err := bobStore.IdentityStore().KeyPair(ctx).PrivateKey().Sign(random, bobSignedPreKeyPublic)
	assert.NoError(t, err)

	preKeyID := prekey.ID(31337)
	signedPreKeyID := prekey.ID(22)

	bobPreKeyBundle := &prekey.Bundle{
		RegistrationID:        bobStore.IdentityStore().LocalRegistrationID(ctx),
		DeviceID:              1,
		PreKeyID:              pointer.To(preKeyID),
		PreKeyPublic:          bobPreKeyPair.PublicKey(),
		SignedPreKeyID:        signedPreKeyID,
		SignedPreKeyPublic:    bobSignedPreKeyPair.PublicKey(),
		SignedPreKeySignature: bobSignedPreKeySignature,
		IdentityKey:           bobStore.IdentityStore().KeyPair(ctx).IdentityKey(),
	}

	aliceSession := &session.Session{
		RemoteAddress:    bobAddress,
		SessionStore:     aliceStore.SessionStore(),
		IdentityKeyStore: aliceStore.IdentityStore(),
	}
	assert.NoError(t, aliceSession.ProcessPreKeyBundle(ctx, random, bobPreKeyBundle))

	aliceSessionWithBob, exists, err := aliceStore.SessionStore().Load(ctx, bobAddress)
	assert.NoError(t, err)
	assert.True(t, exists)
	version, err := aliceSessionWithBob.Version()
	assert.NoError(t, err)
	assert.Equal(t, uint32(message.PreKyberCiphertextVersion), version)

	originalMsg := []byte("L'homme est condamné à être libre")
	outgoingMsg, err := aliceSession.EncryptMessage(ctx, originalMsg)
	assert.NoError(t, err)
	assert.Equal(t, message.PreKeyType, outgoingMsg.Type())

	incomingMsg, err := message.NewPreKeyFromBytes(outgoingMsg.Bytes())
	assert.NoError(t, err)

	assert.NoError(t, bobStore.PreKeyStore().Store(ctx, preKeyID, prekey.NewPreKey(preKeyID, bobPreKeyPair)))
	assert.NoError(t, bobStore.SignedPreKeyStore().Store(ctx, signedPreKeyID, prekey.NewSigned(signedPreKeyID, 42, bobSignedPreKeyPair, bobSignedPreKeySignature)))

	bobSession := &session.Session{
		RemoteAddress:     aliceAddress,
		SessionStore:      bobStore.SessionStore(),
		PreKeyStore:       bobStore.PreKeyStore(),
		SignedPreKeyStore: bobStore.SignedPreKeyStore(),
		IdentityKeyStore:  bobStore.IdentityStore(),
	}
	plaintext, err := bobSession.DecryptMessage(ctx, random, incomingMsg)
	assert.NoError(t, err)
	assert.True(t, utf8.Valid(plaintext))
	assert.Equal(t, originalMsg, plaintext)

	bobSessionWithAlice, exists, err := bobStore.SessionStore().Load(ctx, aliceAddress)
	assert.NoError(t, err)
	assert.True(t, exists)
	version, err = bobSessionWithAlice.Version()
	assert.NoError(t, err)
	assert.Equal(t, uint32(message.PreKyberCiphertextVersion), version)

	bobResponse := []byte("Who watches the watchers?")
	bobOutgoing, err := bobSession.EncryptMessage(ctx, bobResponse)
	assert.NoError(t, err)
	assert.Equal(t, message.WhisperType, bobOutgoing.Type())

	aliceDecrypted, err := aliceSession.DecryptMessage(ctx, random, bobOutgoing)
	assert.NoError(t, err)
	assert.True(t, utf8.Valid(aliceDecrypted))
	assert.Equal(t, bobResponse, aliceDecrypted)

	testInteraction(t, aliceSession, bobSession)

	aliceStore = testInMemProtocolStore(t, random)

	bobPreKeyPair, err = curve.GenerateKeyPair(random)
	require.NoError(t, err)
	bobSignedPreKeyPair, err = curve.GenerateKeyPair(random)
	require.NoError(t, err)

	bobSignedPreKeyPublic = bobSignedPreKeyPair.PublicKey().Bytes()
	bobSignedPreKeySignature, err = bobStore.IdentityStore().KeyPair(ctx).PrivateKey().Sign(random, bobSignedPreKeyPublic)
	assert.NoError(t, err)

	preKeyID = prekey.ID(31337)
	signedPreKeyID = prekey.ID(22)

	bobPreKeyBundle = &prekey.Bundle{
		RegistrationID:        bobStore.IdentityStore().LocalRegistrationID(ctx),
		DeviceID:              1,
		PreKeyID:              pointer.To(preKeyID + 1),
		PreKeyPublic:          bobPreKeyPair.PublicKey(),
		SignedPreKeyID:        signedPreKeyID + 1,
		SignedPreKeyPublic:    bobSignedPreKeyPair.PublicKey(),
		SignedPreKeySignature: bobSignedPreKeySignature,
		IdentityKey:           bobStore.IdentityStore().KeyPair(ctx).IdentityKey(),
	}

	assert.NoError(t, bobStore.PreKeyStore().Store(ctx, preKeyID+1, prekey.NewPreKey(preKeyID+1, bobPreKeyPair)))
	assert.NoError(t, bobStore.SignedPreKeyStore().Store(ctx, signedPreKeyID+1, prekey.NewSigned(signedPreKeyID+1, 42, bobSignedPreKeyPair, bobSignedPreKeySignature)))

	aliceSession = &session.Session{
		RemoteAddress:    bobAddress,
		SessionStore:     aliceStore.SessionStore(),
		IdentityKeyStore: aliceStore.IdentityStore(),
	}
	assert.NoError(t, aliceSession.ProcessPreKeyBundle(ctx, random, bobPreKeyBundle))

	outgoingMsg, err = aliceSession.EncryptMessage(ctx, originalMsg)
	assert.NoError(t, err)
	_, err = bobSession.DecryptMessage(ctx, random, outgoingMsg)
	assert.True(t, perrors.IsErrUntrustedIdentity(err))

	overwrote, err := bobStore.IdentityStore().Store(ctx, aliceAddress, aliceStore.IdentityStore().KeyPair(ctx).IdentityKey())
	assert.NoError(t, err)
	assert.True(t, overwrote)

	decrypted, err := bobSession.DecryptMessage(ctx, random, outgoingMsg)
	assert.NoError(t, err)
	assert.True(t, utf8.Valid(decrypted))
	assert.Equal(t, originalMsg, decrypted)

	// Sign pre-key with wrong key.
	bobPreKeyBundle = &prekey.Bundle{
		RegistrationID:        bobStore.IdentityStore().LocalRegistrationID(ctx),
		DeviceID:              1,
		PreKeyID:              pointer.To(preKeyID),
		PreKeyPublic:          bobPreKeyPair.PublicKey(),
		SignedPreKeyID:        signedPreKeyID,
		SignedPreKeyPublic:    bobSignedPreKeyPair.PublicKey(),
		SignedPreKeySignature: bobSignedPreKeySignature,
		IdentityKey:           aliceStore.IdentityStore().KeyPair(ctx).IdentityKey(),
	}
	assert.Error(t, aliceSession.ProcessPreKeyBundle(ctx, random, bobPreKeyBundle))

}

func testInteraction(t *testing.T, aliceSession, bobSession *session.Session) {
	alicePlaintext := []byte("It's rabbit season")
	aliceMessage, err := aliceSession.EncryptMessage(ctx, alicePlaintext)
	assert.NoError(t, err)
	assert.Equal(t, message.WhisperType, aliceMessage.Type())
	msg, err := bobSession.DecryptMessage(ctx, random, aliceMessage)
	assert.NoError(t, err)
	assert.True(t, utf8.Valid(msg))
	assert.Equal(t, alicePlaintext, msg)

	bobPlaintext := []byte("It's duck season")
	bobMessage, err := bobSession.EncryptMessage(ctx, bobPlaintext)
	assert.NoError(t, err)
	assert.Equal(t, message.WhisperType, bobMessage.Type())
	msg, err = aliceSession.DecryptMessage(ctx, random, bobMessage)
	assert.NoError(t, err)
	assert.True(t, utf8.Valid(msg))
	assert.Equal(t, bobPlaintext, msg)

	for i := 0; i < 10; i++ {
		alicePlaintext := []byte(fmt.Sprintf("A->B message %d", i))
		aliceMessage, err := aliceSession.EncryptMessage(ctx, alicePlaintext)
		assert.NoError(t, err)
		assert.Equal(t, message.WhisperType, aliceMessage.Type())
		msg, err := bobSession.DecryptMessage(ctx, random, aliceMessage)
		assert.NoError(t, err)
		assert.True(t, utf8.Valid(msg))
		assert.Equal(t, alicePlaintext, msg)
	}

	for i := 0; i < 10; i++ {
		bobPlaintext := []byte(fmt.Sprintf("B->A message %d", i))
		bobMessage, err := bobSession.EncryptMessage(ctx, bobPlaintext)
		assert.NoError(t, err)
		assert.Equal(t, message.WhisperType, bobMessage.Type())
		msg, err := aliceSession.DecryptMessage(ctx, random, bobMessage)
		assert.NoError(t, err)
		assert.True(t, utf8.Valid(msg))
		assert.Equal(t, bobPlaintext, msg)
	}

	type msgPair struct {
		plaintext  []byte
		ciphertext message.Ciphertext
	}
	aliceOOOMessages := make([]msgPair, 0, 10)
	for i := 0; i < 10; i++ {
		alicePlaintext := []byte(fmt.Sprintf("A->B OOO message %d", i))
		aliceMessage, err := aliceSession.EncryptMessage(ctx, alicePlaintext)
		assert.NoError(t, err)
		aliceOOOMessages = append(aliceOOOMessages, msgPair{
			plaintext:  alicePlaintext,
			ciphertext: aliceMessage,
		})
	}

	for i := 0; i < 10; i++ {
		alicePlaintext := []byte(fmt.Sprintf("A->B post-OOO message %d", i))
		aliceMessage, err := aliceSession.EncryptMessage(ctx, alicePlaintext)
		assert.NoError(t, err)
		assert.Equal(t, message.WhisperType, aliceMessage.Type())
		msg, err := bobSession.DecryptMessage(ctx, random, aliceMessage)
		assert.NoError(t, err)
		assert.True(t, utf8.Valid(msg))
		assert.Equal(t, alicePlaintext, msg)
	}

	for i := 0; i < 10; i++ {
		bobPlaintext := []byte(fmt.Sprintf("B->A post-OOO message %d", i))
		bobMessage, err := bobSession.EncryptMessage(ctx, bobPlaintext)
		assert.NoError(t, err)
		assert.Equal(t, message.WhisperType, bobMessage.Type())
		msg, err := aliceSession.DecryptMessage(ctx, random, bobMessage)
		assert.NoError(t, err)
		assert.True(t, utf8.Valid(msg))
		assert.Equal(t, bobPlaintext, msg)
	}

	for _, aliceOOOMsg := range aliceOOOMessages {
		msg, err := bobSession.DecryptMessage(ctx, random, aliceOOOMsg.ciphertext)
		assert.NoError(t, err)
		assert.True(t, utf8.Valid(msg))
		assert.Equal(t, aliceOOOMsg.plaintext, msg)
	}
}

func TestChainJumpOverLimit_Remote(t *testing.T) {
	aliceAddress := address.Address{
		Name:     "+14151111111",
		DeviceID: 1,
	}
	bobAddress := address.Address{
		Name:     "+14151111112",
		DeviceID: 1,
	}

	aliceStore := testInMemProtocolStore(t, random)
	bobStore := testInMemProtocolStore(t, random)

	bobPreKeyPair, err := curve.GenerateKeyPair(random)
	require.NoError(t, err)
	bobSignedPreKeyPair, err := curve.GenerateKeyPair(random)
	require.NoError(t, err)

	bobSignedPreKeyPublic := bobSignedPreKeyPair.PublicKey().Bytes()
	bobSignedPreKeySignature, err := bobStore.IdentityStore().KeyPair(ctx).PrivateKey().Sign(random, bobSignedPreKeyPublic)
	assert.NoError(t, err)

	preKeyID := prekey.ID(31337)
	signedPreKeyID := prekey.ID(22)

	bobPreKeyBundle := &prekey.Bundle{
		RegistrationID:        bobStore.IdentityStore().LocalRegistrationID(ctx),
		DeviceID:              1,
		PreKeyID:              pointer.To(preKeyID),
		PreKeyPublic:          bobPreKeyPair.PublicKey(),
		SignedPreKeyID:        signedPreKeyID,
		SignedPreKeyPublic:    bobSignedPreKeyPair.PublicKey(),
		SignedPreKeySignature: bobSignedPreKeySignature,
		IdentityKey:           bobStore.IdentityStore().KeyPair(ctx).IdentityKey(),
	}

	aliceSession := &session.Session{
		RemoteAddress:    bobAddress,
		SessionStore:     aliceStore.SessionStore(),
		IdentityKeyStore: aliceStore.IdentityStore(),
	}
	assert.NoError(t, aliceSession.ProcessPreKeyBundle(ctx, random, bobPreKeyBundle))

	assert.NoError(t, bobStore.PreKeyStore().Store(ctx, preKeyID, prekey.NewPreKey(preKeyID, bobPreKeyPair)))
	assert.NoError(t, bobStore.SignedPreKeyStore().Store(ctx, signedPreKeyID, prekey.NewSigned(signedPreKeyID, 42, bobSignedPreKeyPair, bobSignedPreKeySignature)))

	msg := []byte("Yet another message for you")
	for i := 0; i < session.MaxJumps+1; i++ {
		_, err := aliceSession.EncryptMessage(ctx, msg)
		assert.NoError(t, err)
	}

	tooFar, err := aliceSession.EncryptMessage(ctx, []byte("Now you have gone too far"))
	assert.NoError(t, err)

	bobSession := &session.Session{
		RemoteAddress:     aliceAddress,
		SessionStore:      bobStore.SessionStore(),
		PreKeyStore:       bobStore.PreKeyStore(),
		SignedPreKeyStore: bobStore.SignedPreKeyStore(),
		IdentityKeyStore:  bobStore.IdentityStore(),
	}

	_, err = bobSession.DecryptMessage(ctx, random, tooFar)
	assert.Error(t, err)
}

func TestChainJumpOverLimit_Self(t *testing.T) {
	a1Address := address.Address{
		Name:     "+14151111111",
		DeviceID: 1,
	}
	a2Address := address.Address{
		Name:     "+14151111111",
		DeviceID: 2,
	}

	a1Store := testInMemProtocolStore(t, random)
	a2Store := a1Store

	a2PreKeyPair, err := curve.GenerateKeyPair(random)
	require.NoError(t, err)
	a2SignedPreKeyPair, err := curve.GenerateKeyPair(random)
	require.NoError(t, err)

	a2SignedPreKeyPublic := a2SignedPreKeyPair.PublicKey().Bytes()
	a2SignedPreKeySignature, err := a2Store.IdentityStore().KeyPair(ctx).PrivateKey().Sign(random, a2SignedPreKeyPublic)

	preKeyID := prekey.ID(31337)
	signedPreKeyID := prekey.ID(22)

	a2PreKeyBundle := &prekey.Bundle{
		RegistrationID:        a2Store.IdentityStore().LocalRegistrationID(ctx),
		DeviceID:              1,
		PreKeyID:              pointer.To(preKeyID),
		PreKeyPublic:          a2PreKeyPair.PublicKey(),
		SignedPreKeyID:        signedPreKeyID,
		SignedPreKeyPublic:    a2SignedPreKeyPair.PublicKey(),
		SignedPreKeySignature: a2SignedPreKeySignature,
		IdentityKey:           a2Store.IdentityStore().KeyPair(ctx).IdentityKey(),
	}

	a1Session := &session.Session{
		RemoteAddress:    a2Address,
		SessionStore:     a1Store.SessionStore(),
		IdentityKeyStore: a1Store.IdentityStore(),
	}
	assert.NoError(t, a1Session.ProcessPreKeyBundle(ctx, random, a2PreKeyBundle))

	assert.NoError(t, a2Store.PreKeyStore().Store(ctx, preKeyID, prekey.NewPreKey(preKeyID, a2PreKeyPair)))
	assert.NoError(t, a2Store.SignedPreKeyStore().Store(ctx, signedPreKeyID, prekey.NewSigned(signedPreKeyID, 42, a2SignedPreKeyPair, a2SignedPreKeySignature)))

	msg := []byte("Yet another message for yourself")
	for i := 0; i < session.MaxJumps+1; i++ {
		_, err := a1Session.EncryptMessage(ctx, msg)
		assert.NoError(t, err)
	}

	msg = []byte("This is the song that never ends")
	tooFar, err := a1Session.EncryptMessage(ctx, msg)
	assert.NoError(t, err)

	a2Session := &session.Session{
		RemoteAddress:     a1Address,
		SessionStore:      a2Store.SessionStore(),
		PreKeyStore:       a2Store.PreKeyStore(),
		SignedPreKeyStore: a2Store.SignedPreKeyStore(),
		IdentityKeyStore:  a2Store.IdentityStore(),
	}

	plaintext, err := a2Session.DecryptMessage(ctx, random, tooFar)
	assert.NoError(t, err)
	assert.True(t, utf8.Valid(plaintext))
	assert.Equal(t, msg, plaintext)
}

func TestBadSignedPreKeySignature(t *testing.T) {
	bobAddress := address.Address{
		Name:     "+14151111112",
		DeviceID: 1,
	}

	aliceStore := testInMemProtocolStore(t, random)
	bobStore := testInMemProtocolStore(t, random)

	bobPreKeyPair, err := curve.GenerateKeyPair(random)
	require.NoError(t, err)
	bobSignedPreKeyPair, err := curve.GenerateKeyPair(random)
	require.NoError(t, err)

	bobSignedPreKeyPublic := bobSignedPreKeyPair.PublicKey().Bytes()
	bobSignedPreKeySignature, err := bobStore.IdentityStore().KeyPair(ctx).PrivateKey().Sign(random, bobSignedPreKeyPublic)
	assert.NoError(t, err)

	preKeyID := prekey.ID(31337)
	signedPreKeyID := prekey.ID(22)

	aliceSession := &session.Session{
		RemoteAddress:    bobAddress,
		SessionStore:     aliceStore.SessionStore(),
		IdentityKeyStore: aliceStore.IdentityStore(),
	}

	bobPreKeyBundle := &prekey.Bundle{
		RegistrationID:        bobStore.IdentityStore().LocalRegistrationID(ctx),
		DeviceID:              1,
		PreKeyID:              pointer.To(preKeyID),
		PreKeyPublic:          bobPreKeyPair.PublicKey(),
		SignedPreKeyID:        signedPreKeyID,
		SignedPreKeyPublic:    bobSignedPreKeyPair.PublicKey(),
		SignedPreKeySignature: nil,
		IdentityKey:           bobStore.IdentityStore().KeyPair(ctx).IdentityKey(),
	}

	badSignature := make([]byte, len(bobSignedPreKeySignature))
	for i := 0; i < 8*len(bobSignedPreKeySignature); i++ {
		copy(badSignature, bobSignedPreKeySignature)

		badSignature[i/8] ^= 0x01 << (i % 8)

		bobPreKeyBundle.SignedPreKeySignature = badSignature

		assert.Error(t, aliceSession.ProcessPreKeyBundle(ctx, random, bobPreKeyBundle))
	}

	bobPreKeyBundle.SignedPreKeySignature = bobSignedPreKeySignature

	assert.NoError(t, aliceSession.ProcessPreKeyBundle(ctx, random, bobPreKeyBundle))
}

func TestRepeatBundleMessage(t *testing.T) {
	aliceAddress := address.Address{
		Name:     "+14151111111",
		DeviceID: 1,
	}
	bobAddress := address.Address{
		Name:     "+14151111112",
		DeviceID: 1,
	}

	aliceStore := testInMemProtocolStore(t, random)
	bobStore := testInMemProtocolStore(t, random)

	bobPreKeyPair, err := curve.GenerateKeyPair(random)
	require.NoError(t, err)
	bobSignedPreKeyPair, err := curve.GenerateKeyPair(random)
	require.NoError(t, err)

	bobSignedPreKeyPublic := bobSignedPreKeyPair.PublicKey().Bytes()
	bobSignedPreKeySignature, err := bobStore.IdentityStore().KeyPair(ctx).PrivateKey().Sign(random, bobSignedPreKeyPublic)
	assert.NoError(t, err)

	preKeyID := prekey.ID(31337)
	signedPreKeyID := prekey.ID(22)

	bobPreKeyBundle := &prekey.Bundle{
		RegistrationID:        bobStore.IdentityStore().LocalRegistrationID(ctx),
		DeviceID:              1,
		PreKeyID:              pointer.To(preKeyID),
		PreKeyPublic:          bobPreKeyPair.PublicKey(),
		SignedPreKeyID:        signedPreKeyID,
		SignedPreKeyPublic:    bobSignedPreKeyPair.PublicKey(),
		SignedPreKeySignature: bobSignedPreKeySignature,
		IdentityKey:           bobStore.IdentityStore().KeyPair(ctx).IdentityKey(),
	}

	aliceSession := &session.Session{
		RemoteAddress:    bobAddress,
		SessionStore:     aliceStore.SessionStore(),
		IdentityKeyStore: aliceStore.IdentityStore(),
	}
	assert.NoError(t, aliceSession.ProcessPreKeyBundle(ctx, random, bobPreKeyBundle))

	aliceSessionWithBob, exists, err := aliceStore.SessionStore().Load(ctx, bobAddress)
	assert.NoError(t, err)
	assert.True(t, exists)
	version, err := aliceSessionWithBob.Version()
	assert.NoError(t, err)
	assert.Equal(t, uint32(message.PreKyberCiphertextVersion), version)

	originalMsg := []byte("L'homme est condamné à être libre")
	outgoingMsg1, err := aliceSession.EncryptMessage(ctx, originalMsg)
	assert.NoError(t, err)
	assert.Equal(t, message.PreKeyType, outgoingMsg1.Type())
	outgoingMsg2, err := aliceSession.EncryptMessage(ctx, originalMsg)
	assert.NoError(t, err)
	assert.Equal(t, message.PreKeyType, outgoingMsg2.Type())

	incomingMsg, err := message.NewPreKeyFromBytes(outgoingMsg1.Bytes())
	assert.NoError(t, err)

	assert.NoError(t, bobStore.PreKeyStore().Store(ctx, preKeyID, prekey.NewPreKey(preKeyID, bobPreKeyPair)))
	assert.NoError(t, bobStore.SignedPreKeyStore().Store(ctx, signedPreKeyID, prekey.NewSigned(signedPreKeyID, 42, bobSignedPreKeyPair, bobSignedPreKeySignature)))

	bobSession := &session.Session{
		RemoteAddress:     aliceAddress,
		SessionStore:      bobStore.SessionStore(),
		PreKeyStore:       bobStore.PreKeyStore(),
		SignedPreKeyStore: bobStore.SignedPreKeyStore(),
		IdentityKeyStore:  bobStore.IdentityStore(),
	}

	plaintext, err := bobSession.DecryptMessage(ctx, random, incomingMsg)
	assert.NoError(t, err)
	assert.True(t, utf8.Valid(plaintext))
	assert.Equal(t, originalMsg, plaintext)

	bobOutgoing, err := bobSession.EncryptMessage(ctx, originalMsg)
	assert.NoError(t, err)
	assert.Equal(t, message.WhisperType, bobOutgoing.Type())
	aliceDecrypts, err := aliceSession.DecryptMessage(ctx, random, bobOutgoing)
	assert.NoError(t, err)
	assert.True(t, utf8.Valid(aliceDecrypts))
	assert.Equal(t, originalMsg, aliceDecrypts)

	incomingMsg2, err := message.NewPreKeyFromBytes(outgoingMsg2.Bytes())
	assert.NoError(t, err)

	plaintext, err = bobSession.DecryptMessage(ctx, random, incomingMsg2)
	assert.NoError(t, err)
	assert.True(t, utf8.Valid(plaintext))
	assert.Equal(t, originalMsg, plaintext)

	bobOutgoing, err = bobSession.EncryptMessage(ctx, originalMsg)
	assert.NoError(t, err)
	assert.Equal(t, message.WhisperType, bobOutgoing.Type())
	aliceDecrypts, err = aliceSession.DecryptMessage(ctx, random, bobOutgoing)
	assert.NoError(t, err)
	assert.True(t, utf8.Valid(aliceDecrypts))
	assert.Equal(t, originalMsg, aliceDecrypts)
}

func TestOptionalOneTimePreKey(t *testing.T) {
	aliceAddress := address.Address{
		Name:     "+14151111111",
		DeviceID: 1,
	}
	bobAddress := address.Address{
		Name:     "+14151111112",
		DeviceID: 1,
	}

	aliceStore := testInMemProtocolStore(t, random)
	bobStore := testInMemProtocolStore(t, random)

	bobSignedPreKeyPair, err := curve.GenerateKeyPair(random)
	require.NoError(t, err)

	bobSignedPreKeyPublic := bobSignedPreKeyPair.PublicKey().Bytes()
	bobSignedPreKeySignature, err := bobStore.IdentityStore().KeyPair(ctx).PrivateKey().Sign(random, bobSignedPreKeyPublic)
	assert.NoError(t, err)

	signedPreKeyID := prekey.ID(22)

	bobPreKeyBundle := &prekey.Bundle{
		RegistrationID:        bobStore.IdentityStore().LocalRegistrationID(ctx),
		DeviceID:              1,
		PreKeyID:              nil,
		PreKeyPublic:          nil,
		SignedPreKeyID:        signedPreKeyID,
		SignedPreKeyPublic:    bobSignedPreKeyPair.PublicKey(),
		SignedPreKeySignature: bobSignedPreKeySignature,
		IdentityKey:           bobStore.IdentityStore().KeyPair(ctx).IdentityKey(),
	}

	aliceSession := &session.Session{
		RemoteAddress:    bobAddress,
		SessionStore:     aliceStore.SessionStore(),
		IdentityKeyStore: aliceStore.IdentityStore(),
	}
	assert.NoError(t, aliceSession.ProcessPreKeyBundle(ctx, random, bobPreKeyBundle))

	aliceSessionWithBob, exists, err := aliceStore.SessionStore().Load(ctx, bobAddress)
	assert.NoError(t, err)
	assert.True(t, exists)
	version, err := aliceSessionWithBob.Version()
	assert.NoError(t, err)
	assert.Equal(t, uint32(message.PreKyberCiphertextVersion), version)

	originalMsg := []byte("L'homme est condamné à être libre")
	outgoingMsg, err := aliceSession.EncryptMessage(ctx, originalMsg)
	assert.NoError(t, err)
	assert.Equal(t, message.PreKeyType, outgoingMsg.Type())

	incomingMsg, err := message.NewPreKeyFromBytes(outgoingMsg.Bytes())
	assert.NoError(t, err)

	assert.NoError(t, bobStore.SignedPreKeyStore().Store(ctx, signedPreKeyID, prekey.NewSigned(signedPreKeyID, 42, bobSignedPreKeyPair, bobSignedPreKeySignature)))

	bobSession := &session.Session{
		RemoteAddress:     aliceAddress,
		SessionStore:      bobStore.SessionStore(),
		PreKeyStore:       bobStore.PreKeyStore(),
		SignedPreKeyStore: bobStore.SignedPreKeyStore(),
		IdentityKeyStore:  bobStore.IdentityStore(),
	}
	plaintext, err := bobSession.DecryptMessage(ctx, random, incomingMsg)
	assert.NoError(t, err)
	assert.True(t, utf8.Valid(plaintext))
	assert.Equal(t, originalMsg, plaintext)
}

func TestBasicSessionV3(t *testing.T) {
	aliceRecord, bobRecord := testInitRecordsV3(t, random)

	aliceAddress := address.Address{
		Name:     "+14159999999",
		DeviceID: 1,
	}
	bobAddress := address.Address{
		Name:     "+14158888888",
		DeviceID: 1,
	}

	aliceStore := testInMemProtocolStore(t, random)
	bobStore := testInMemProtocolStore(t, random)

	assert.NoError(t, aliceStore.SessionStore().Store(ctx, bobAddress, aliceRecord))
	assert.NoError(t, bobStore.SessionStore().Store(ctx, aliceAddress, bobRecord))

	aliceSession := &session.Session{
		RemoteAddress:    bobAddress,
		SessionStore:     aliceStore.SessionStore(),
		IdentityKeyStore: aliceStore.IdentityStore(),
	}
	bobSession := &session.Session{
		RemoteAddress:     aliceAddress,
		SessionStore:      bobStore.SessionStore(),
		PreKeyStore:       bobStore.PreKeyStore(),
		SignedPreKeyStore: bobStore.SignedPreKeyStore(),
		IdentityKeyStore:  bobStore.IdentityStore(),
	}

	alicePlaintext := []byte("This is Alice's message")
	aliceCiphertext, err := aliceSession.EncryptMessage(ctx, alicePlaintext)
	assert.NoError(t, err)
	bobDecrypted, err := bobSession.DecryptMessage(ctx, random, aliceCiphertext)
	assert.NoError(t, err)
	assert.True(t, utf8.Valid(bobDecrypted))
	assert.Equal(t, alicePlaintext, bobDecrypted)

	type pair struct {
		plaintext  []byte
		ciphertext message.Ciphertext
	}

	aliceMessages := make([]pair, 50)
	for i := range aliceMessages {
		plaintext := []byte(fmt.Sprintf("смерть за смерть %d", i))
		ciphertext, err := aliceSession.EncryptMessage(ctx, plaintext)
		assert.NoError(t, err)

		aliceMessages[i] = pair{
			plaintext:  plaintext,
			ciphertext: ciphertext,
		}
	}
	mathrand.Shuffle(len(aliceMessages), func(i, j int) {
		aliceMessages[i], aliceMessages[j] = aliceMessages[j], aliceMessages[i]
	})

	for i := 0; i < len(aliceMessages)/2; i++ {
		plaintext, err := bobSession.DecryptMessage(ctx, random, aliceMessages[i].ciphertext)
		assert.NoError(t, err)
		assert.True(t, utf8.Valid(plaintext))
		assert.Equal(t, aliceMessages[i].plaintext, plaintext)
	}

	bobMessages := make([]pair, 50)
	for i := range bobMessages {
		plaintext := []byte(fmt.Sprintf("Relax in the safety of your own delusions. %d", i))
		ciphertext, err := bobSession.EncryptMessage(ctx, plaintext)
		assert.NoError(t, err)

		bobMessages[i] = pair{
			plaintext:  plaintext,
			ciphertext: ciphertext,
		}
	}
	mathrand.Shuffle(len(bobMessages), func(i, j int) {
		bobMessages[i], bobMessages[j] = bobMessages[j], bobMessages[i]
	})

	for i := 0; i < len(bobMessages)/2; i++ {
		plaintext, err := aliceSession.DecryptMessage(ctx, random, bobMessages[i].ciphertext)
		assert.NoError(t, err)
		assert.True(t, utf8.Valid(plaintext))
		assert.Equal(t, bobMessages[i].plaintext, plaintext)
	}

	for i := len(aliceMessages) / 2; i < len(aliceMessages); i++ {
		plaintext, err := bobSession.DecryptMessage(ctx, random, aliceMessages[i].ciphertext)
		assert.NoError(t, err)
		assert.True(t, utf8.Valid(plaintext))
		assert.Equal(t, aliceMessages[i].plaintext, plaintext)
	}

	for i := len(bobMessages) / 2; i < len(bobMessages); i++ {
		plaintext, err := aliceSession.DecryptMessage(ctx, random, bobMessages[i].ciphertext)
		assert.NoError(t, err)
		assert.True(t, utf8.Valid(plaintext))
		assert.Equal(t, bobMessages[i].plaintext, plaintext)
	}
}
