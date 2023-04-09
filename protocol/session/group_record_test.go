package session

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/RTann/libsignal-go/protocol/curve"
	"github.com/RTann/libsignal-go/protocol/senderkey"
)

var _ suite.TestingSuite = (*groupRecordTestSuite)(nil)

type groupRecordTestSuite struct {
	suite.Suite

	record *GroupRecord
}

func (s *groupRecordTestSuite) SetupTest() {
	s.record = NewGroupRecord()
}

func TestGroupRecordTestSuite(t *testing.T) {
	suite.Run(t, new(groupRecordTestSuite))
}

func (s *groupRecordTestSuite) TestAddSingleState() {
	r := recordKey{
		chainID:   1,
		chainKey:  testChainKey(1),
		publicKey: s.testPublicKey(),
	}

	s.addStates(r)
	s.Len(s.record.states, 1)
	s.assertChainKey(r)
}

func (s *groupRecordTestSuite) TestAddSecondState() {
	r1 := recordKey{
		chainID:   1,
		chainKey:  testChainKey(1),
		publicKey: s.testPublicKey(),
	}
	r2 := recordKey{
		chainID:   2,
		chainKey:  testChainKey(2),
		publicKey: s.testPublicKey(),
	}

	s.addStates(r1, r2)

	s.Len(s.record.states, 2)
	s.assertChainKey(r1)
	s.assertChainKey(r2)
}

func (s *groupRecordTestSuite) TestExceedMax() {
	s.Equal(5, maxSenderKeyStates)

	rs := []recordKey{
		{
			chainID:   1,
			chainKey:  testChainKey(1),
			publicKey: s.testPublicKey(),
		},
		{
			chainID:   2,
			chainKey:  testChainKey(2),
			publicKey: s.testPublicKey(),
		},
		{
			chainID:   3,
			chainKey:  testChainKey(3),
			publicKey: s.testPublicKey(),
		},
		{
			chainID:   4,
			chainKey:  testChainKey(4),
			publicKey: s.testPublicKey(),
		},
		{
			chainID:   5,
			chainKey:  testChainKey(5),
			publicKey: s.testPublicKey(),
		},
		{
			chainID:   6,
			chainKey:  testChainKey(6),
			publicKey: s.testPublicKey(),
		},
	}

	s.addStates(rs[:5]...)
	s.assertOrder(rs[:5]...)

	s.addStates(rs[5])
	s.assertOrder(rs[1:]...)
}

func (s *groupRecordTestSuite) TestSameChainIDAndPublicKey() {
	r1 := recordKey{
		chainID:   1,
		chainKey:  testChainKey(1),
		publicKey: s.testPublicKey(),
	}
	r2 := recordKey{
		chainID:   r1.chainID,
		chainKey:  testChainKey(2),
		publicKey: r1.publicKey,
	}

	s.addStates(r1, r2)

	s.Len(s.record.states, 1)
	s.assertChainKey(r1)
}

func (s *groupRecordTestSuite) TestSameChainIDDifferentPublicKey() {
	r1 := recordKey{
		chainID:   1,
		chainKey:  testChainKey(1),
		publicKey: s.testPublicKey(),
	}
	r2 := recordKey{
		chainID:   r1.chainID,
		chainKey:  testChainKey(2),
		publicKey: s.testPublicKey(),
	}

	s.addStates(r1, r2)

	s.Len(s.record.states, 1)
	s.assertChainKey(r2)
}

func (s *groupRecordTestSuite) TestUpdateState() {
	r1 := recordKey{
		chainID:   1,
		chainKey:  testChainKey(1),
		publicKey: s.testPublicKey(),
	}
	r2 := recordKey{
		chainID:   2,
		chainKey:  testChainKey(2),
		publicKey: s.testPublicKey(),
	}

	s.addStates(r1, r2)
	s.assertOrder(r1, r2)

	r1.chainKey = testChainKey(3)
	s.addStates(r1)
	s.assertOrder(r2, r1)
}

func (s *groupRecordTestSuite) testPublicKey() curve.PublicKey {
	pair, err := curve.GenerateKeyPair(rand.Reader)
	s.Require().NoError(err)

	return pair.PublicKey()
}

func testChainKey(i uint8) []byte {
	chainKey := make([]byte, senderkey.ChainKeySize)
	chainKey[0] = i
	return chainKey
}

func (s *groupRecordTestSuite) addStates(rs ...recordKey) {
	var err error
	for _, r := range rs {
		err = s.record.AddState(NewGroupState(GroupStateConfig{
			MessageVersion: 1,
			ChainID:        r.chainID,
			Iteration:      1,
			ChainKey:       r.chainKey,
			SignatureKey:   r.publicKey,
		}))
		s.Require().NoError(err)
	}
}

func (s *groupRecordTestSuite) assertChainKey(r recordKey) {
	state := s.record.StateForChainID(r.chainID)
	s.Require().NotNil(state)

	foundChainKey := state.SenderChainKey()
	s.Equal(r.chainKey, foundChainKey.Seed())

	var matchingState *GroupState
	for _, state := range s.record.states {
		if state.ChainID() == r.chainID {
			publicKey, err := state.PublicSigningKey()
			s.Require().NoError(err)

			if publicKey.Equal(r.publicKey) {
				s.Nil(matchingState)
				matchingState = state
			}
		}
	}

	s.Require().NotNil(matchingState)
	s.Equal(r.chainKey, matchingState.SenderChainKey().Seed())
}

type recordKey struct {
	chainID   uint32
	chainKey  []byte
	publicKey curve.PublicKey
}

func (s *groupRecordTestSuite) assertOrder(rs ...recordKey) {
	s.Equal(len(rs), len(s.record.states))

	for i, state := range s.record.states {
		publicKey, err := state.PublicSigningKey()
		s.Require().NoError(err)

		s.Equal(rs[i].chainID, state.ChainID())
		s.True(publicKey.Equal(rs[i].publicKey))
	}
}
