package tests

import (
	"bytes"
	"fmt"
	"io"
	mathrand "math/rand"
	"sort"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/RTann/libsignal-go/protocol/address"
	"github.com/RTann/libsignal-go/protocol/distribution"
	"github.com/RTann/libsignal-go/protocol/message"
	"github.com/RTann/libsignal-go/protocol/perrors"
	"github.com/RTann/libsignal-go/protocol/session"
)

func TestGroupNoSendSession(t *testing.T) {
	senderAddress := address.Address{
		Name:     "+14159999111",
		DeviceID: 1,
	}
	distributionID := distribution.MustParse("d1d1d1d1-7000-11eb-b32a-33b8a8a487a6")

	aliceStore := testInMemProtocolStore(t, random)

	aliceSession := &session.GroupSession{
		SenderAddress:  senderAddress,
		DistID:         distributionID,
		SenderKeyStore: aliceStore.GroupStore(),
	}
	_, err := aliceSession.EncryptMessage(ctx, random, []byte("space camp?"))
	assert.Error(t, err)
}

func TestGroupNoRecvSession(t *testing.T) {
	senderAddress := address.Address{
		Name:     "+14159999111",
		DeviceID: 1,
	}
	distributionID := distribution.MustParse("d1d1d1d1-7000-11eb-b32a-33b8a8a487a6")

	aliceStore := testInMemProtocolStore(t, random)
	bobStore := testInMemProtocolStore(t, random)

	aliceSession := session.GroupSession{
		SenderAddress:  senderAddress,
		DistID:         distributionID,
		SenderKeyStore: aliceStore.GroupStore(),
	}
	_, err := aliceSession.NewSenderKeyDistribution(ctx, random)
	assert.NoError(t, err)

	aliceCiphertext, err := aliceSession.EncryptMessage(ctx, random, []byte("space camp?"))
	assert.NoError(t, err)

	bobSession := &session.GroupSession{
		SenderAddress:  senderAddress,
		SenderKeyStore: bobStore.GroupStore(),
	}
	_, err = bobSession.DecryptMessage(ctx, aliceCiphertext)
	assert.Error(t, err)
}

func TestGroupBasic(t *testing.T) {
	senderAddress := address.Address{
		Name:     "+14159999111",
		DeviceID: 1,
	}
	distributionID := distribution.MustParse("d1d1d1d1-7000-11eb-b32a-33b8a8a487a6")

	aliceStore := testInMemProtocolStore(t, random)
	bobStore := testInMemProtocolStore(t, random)

	aliceSession := session.GroupSession{
		SenderAddress:  senderAddress,
		DistID:         distributionID,
		SenderKeyStore: aliceStore.GroupStore(),
	}
	sentDistributionMsg, err := aliceSession.NewSenderKeyDistribution(ctx, random)
	assert.NoError(t, err)

	recvDistributionMsg, err := message.NewSenderKeyDistributionFromBytes(sentDistributionMsg.Bytes())
	assert.NoError(t, err)

	originalMsg := []byte("space camp?")
	aliceCiphertext, err := aliceSession.EncryptMessage(ctx, random, originalMsg)
	assert.NoError(t, err)

	bobSession := &session.GroupSession{
		SenderAddress:  senderAddress,
		SenderKeyStore: bobStore.GroupStore(),
	}
	err = bobSession.ProcessSenderKeyDistribution(ctx, recvDistributionMsg)
	assert.NoError(t, err)

	bobPlaintext, err := bobSession.DecryptMessage(ctx, aliceCiphertext)
	assert.NoError(t, err)
	assert.True(t, utf8.Valid(bobPlaintext))
	assert.Equal(t, originalMsg, bobPlaintext)
}

func TestGroupLargeMessages(t *testing.T) {
	senderAddress := address.Address{
		Name:     "+14159999111",
		DeviceID: 1,
	}
	distributionID := distribution.MustParse("d1d1d1d1-7000-11eb-b32a-33b8a8a487a6")

	aliceStore := testInMemProtocolStore(t, random)
	bobStore := testInMemProtocolStore(t, random)

	aliceSession := session.GroupSession{
		SenderAddress:  senderAddress,
		DistID:         distributionID,
		SenderKeyStore: aliceStore.GroupStore(),
	}
	sentDistributionMsg, err := aliceSession.NewSenderKeyDistribution(ctx, random)
	assert.NoError(t, err)

	recvDistributionMsg, err := message.NewSenderKeyDistributionFromBytes(sentDistributionMsg.Bytes())
	assert.NoError(t, err)

	largeMsg := make([]byte, 1024)
	_, err = io.ReadFull(random, largeMsg)
	require.NoError(t, err)

	aliceCiphertext, err := aliceSession.EncryptMessage(ctx, random, largeMsg)
	assert.NoError(t, err)

	bobSession := &session.GroupSession{
		SenderAddress:  senderAddress,
		SenderKeyStore: bobStore.GroupStore(),
	}
	err = bobSession.ProcessSenderKeyDistribution(ctx, recvDistributionMsg)
	assert.NoError(t, err)

	bobPlaintext, err := bobSession.DecryptMessage(ctx, aliceCiphertext)
	assert.NoError(t, err)
	assert.Equal(t, largeMsg, bobPlaintext)
}

func TestGroupBasicRatchet(t *testing.T) {
	senderAddress := address.Address{
		Name:     "+14159999111",
		DeviceID: 1,
	}
	distributionID := distribution.MustParse("d1d1d1d1-7000-11eb-b32a-33b8a8a487a6")

	aliceStore := testInMemProtocolStore(t, random)
	bobStore := testInMemProtocolStore(t, random)

	aliceSession := session.GroupSession{
		SenderAddress:  senderAddress,
		DistID:         distributionID,
		SenderKeyStore: aliceStore.GroupStore(),
	}
	sentDistributionMsg, err := aliceSession.NewSenderKeyDistribution(ctx, random)
	assert.NoError(t, err)

	recvDistributionMsg, err := message.NewSenderKeyDistributionFromBytes(sentDistributionMsg.Bytes())
	assert.NoError(t, err)

	bobSession := &session.GroupSession{
		SenderAddress:  senderAddress,
		SenderKeyStore: bobStore.GroupStore(),
	}
	err = bobSession.ProcessSenderKeyDistribution(ctx, recvDistributionMsg)
	assert.NoError(t, err)

	aliceCiphertext1, err := aliceSession.EncryptMessage(ctx, random, []byte("swim camp"))
	assert.NoError(t, err)
	aliceCiphertext2, err := aliceSession.EncryptMessage(ctx, random, []byte("robot camp"))
	assert.NoError(t, err)
	aliceCiphertext3, err := aliceSession.EncryptMessage(ctx, random, []byte("ninja camp"))
	assert.NoError(t, err)

	bobPlaintext1, err := bobSession.DecryptMessage(ctx, aliceCiphertext1)
	assert.NoError(t, err)
	assert.True(t, utf8.Valid(bobPlaintext1))
	assert.Equal(t, []byte("swim camp"), bobPlaintext1)

	_, err = bobSession.DecryptMessage(ctx, aliceCiphertext1)
	assert.Error(t, err)
	assert.Equal(t, perrors.ErrDuplicateMessage, err)

	bobPlaintext3, err := bobSession.DecryptMessage(ctx, aliceCiphertext3)
	assert.NoError(t, err)
	assert.True(t, utf8.Valid(bobPlaintext3))
	assert.Equal(t, []byte("ninja camp"), bobPlaintext3)

	bobPlaintext2, err := bobSession.DecryptMessage(ctx, aliceCiphertext2)
	assert.NoError(t, err)
	assert.True(t, utf8.Valid(bobPlaintext2))
	assert.Equal(t, []byte("robot camp"), bobPlaintext2)
}

func TestGroupLateJoin(t *testing.T) {
	senderAddress := address.Address{
		Name:     "+14159999111",
		DeviceID: 1,
	}
	distributionID := distribution.MustParse("d1d1d1d1-7000-11eb-b32a-33b8a8a487a6")

	aliceStore := testInMemProtocolStore(t, random)
	bobStore := testInMemProtocolStore(t, random)

	aliceSession := session.GroupSession{
		SenderAddress:  senderAddress,
		DistID:         distributionID,
		SenderKeyStore: aliceStore.GroupStore(),
	}
	sentDistributionMsg, err := aliceSession.NewSenderKeyDistribution(ctx, random)
	assert.NoError(t, err)

	recvDistributionMsg, err := message.NewSenderKeyDistributionFromBytes(sentDistributionMsg.Bytes())
	assert.NoError(t, err)

	for i := 0; i < 100; i++ {
		msg := fmt.Sprintf("nefarious plotting %d/100", i)
		_, err := aliceSession.EncryptMessage(ctx, random, []byte(msg))
		assert.NoError(t, err)
	}

	bobSession := &session.GroupSession{
		SenderAddress:  senderAddress,
		SenderKeyStore: bobStore.GroupStore(),
	}
	err = bobSession.ProcessSenderKeyDistribution(ctx, recvDistributionMsg)
	assert.NoError(t, err)

	msg := []byte("welcome bob")
	aliceCiphertext, err := aliceSession.EncryptMessage(ctx, random, msg)
	assert.NoError(t, err)

	bobPlaintext, err := bobSession.DecryptMessage(ctx, aliceCiphertext)
	assert.NoError(t, err)
	assert.True(t, utf8.Valid(bobPlaintext))
	assert.Equal(t, msg, bobPlaintext)
}

func TestGroupOutOfOrder(t *testing.T) {
	senderAddress := address.Address{
		Name:     "+14159999111",
		DeviceID: 1,
	}
	distributionID := distribution.MustParse("d1d1d1d1-7000-11eb-b32a-33b8a8a487a6")

	aliceStore := testInMemProtocolStore(t, random)
	bobStore := testInMemProtocolStore(t, random)

	aliceSession := session.GroupSession{
		SenderAddress:  senderAddress,
		DistID:         distributionID,
		SenderKeyStore: aliceStore.GroupStore(),
	}
	sentDistributionMsg, err := aliceSession.NewSenderKeyDistribution(ctx, random)
	assert.NoError(t, err)

	recvDistributionMsg, err := message.NewSenderKeyDistributionFromBytes(sentDistributionMsg.Bytes())
	assert.NoError(t, err)

	bobSession := &session.GroupSession{
		SenderAddress:  senderAddress,
		SenderKeyStore: bobStore.GroupStore(),
	}
	err = bobSession.ProcessSenderKeyDistribution(ctx, recvDistributionMsg)
	assert.NoError(t, err)

	ciphertexts := make([]*message.SenderKey, 0, 100)
	for i := 0; i < len(ciphertexts); i++ {
		msg := fmt.Sprintf("nefarious plotting %d/100", i)
		ciphertext, err := aliceSession.EncryptMessage(ctx, random, []byte(msg))
		assert.NoError(t, err)
		ciphertexts = append(ciphertexts, ciphertext)
	}
	mathrand.Shuffle(len(ciphertexts), func(i, j int) {
		ciphertexts[i], ciphertexts[j] = ciphertexts[j], ciphertexts[i]
	})

	plaintexts := make([][]byte, 0, len(ciphertexts))
	for _, ciphertext := range ciphertexts {
		plaintext, err := bobSession.DecryptMessage(ctx, ciphertext)
		assert.NoError(t, err)
		plaintexts = append(plaintexts, plaintext)
	}
	sort.Slice(plaintexts, func(i, j int) bool {
		return bytes.Compare(plaintexts[i], plaintexts[j]) < 0
	})

	for i, plaintext := range plaintexts {
		assert.True(t, utf8.Valid(plaintext))
		msg := fmt.Sprintf("nefarious plotting %d/100", i)
		assert.Equal(t, []byte(msg), plaintext)
	}
}

func TestGroupTooFarInFuture(t *testing.T) {
	senderAddress := address.Address{
		Name:     "+14159999111",
		DeviceID: 1,
	}
	distributionID := distribution.MustParse("d1d1d1d1-7000-11eb-b32a-33b8a8a487a6")

	aliceStore := testInMemProtocolStore(t, random)
	bobStore := testInMemProtocolStore(t, random)

	aliceSession := session.GroupSession{
		SenderAddress:  senderAddress,
		DistID:         distributionID,
		SenderKeyStore: aliceStore.GroupStore(),
	}
	sentDistributionMsg, err := aliceSession.NewSenderKeyDistribution(ctx, random)
	assert.NoError(t, err)

	recvDistributionMsg, err := message.NewSenderKeyDistributionFromBytes(sentDistributionMsg.Bytes())
	assert.NoError(t, err)

	bobSession := &session.GroupSession{
		SenderAddress:  senderAddress,
		SenderKeyStore: bobStore.GroupStore(),
	}
	err = bobSession.ProcessSenderKeyDistribution(ctx, recvDistributionMsg)
	assert.NoError(t, err)

	for i := 0; i < session.MaxJumps+1; i++ {
		_, err = aliceSession.EncryptMessage(ctx, random, []byte(fmt.Sprintf("nefarious plotting %d", i)))
		assert.NoError(t, err)
	}

	aliceCiphertext, err := aliceSession.EncryptMessage(ctx, random, []byte("you got the plan?"))
	assert.NoError(t, err)

	_, err = bobSession.DecryptMessage(ctx, aliceCiphertext)
	assert.Error(t, err)
}

func TestGroupMessageKeyLimit(t *testing.T) {
	senderAddress := address.Address{
		Name:     "+14159999111",
		DeviceID: 1,
	}
	distributionID := distribution.MustParse("d1d1d1d1-7000-11eb-b32a-33b8a8a487a6")

	aliceStore := testInMemProtocolStore(t, random)
	bobStore := testInMemProtocolStore(t, random)

	aliceSession := session.GroupSession{
		SenderAddress:  senderAddress,
		DistID:         distributionID,
		SenderKeyStore: aliceStore.GroupStore(),
	}
	sentDistributionMsg, err := aliceSession.NewSenderKeyDistribution(ctx, random)
	assert.NoError(t, err)

	recvDistributionMsg, err := message.NewSenderKeyDistributionFromBytes(sentDistributionMsg.Bytes())
	assert.NoError(t, err)

	bobSession := &session.GroupSession{
		SenderAddress:  senderAddress,
		SenderKeyStore: bobStore.GroupStore(),
	}
	err = bobSession.ProcessSenderKeyDistribution(ctx, recvDistributionMsg)
	assert.NoError(t, err)

	ciphertexts := make([]*message.SenderKey, 0, 2010)
	msg := []byte("too many messages")
	for i := 0; i < 2010; i++ {
		ciphertext, err := aliceSession.EncryptMessage(ctx, random, msg)
		assert.NoError(t, err)
		ciphertexts = append(ciphertexts, ciphertext)
	}

	bobPlaintext, err := bobSession.DecryptMessage(ctx, ciphertexts[1000])
	assert.NoError(t, err)
	assert.True(t, utf8.Valid(bobPlaintext))
	assert.Equal(t, []byte("too many messages"), bobPlaintext)

	bobPlaintext, err = bobSession.DecryptMessage(ctx, ciphertexts[2009])
	assert.NoError(t, err)
	assert.True(t, utf8.Valid(bobPlaintext))
	assert.Equal(t, []byte("too many messages"), bobPlaintext)

	_, err = bobSession.DecryptMessage(ctx, ciphertexts[0])
	assert.Error(t, err)
}
