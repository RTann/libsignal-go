package session

import (
	"github.com/RTann/libsignal-go/protocol/curve"
	v1 "github.com/RTann/libsignal-go/protocol/generated/v1"
	"github.com/RTann/libsignal-go/protocol/senderkey"
)

// GroupState represents a group session's state.
type GroupState struct {
	state *v1.SenderKeyStateStructure
}

type GroupStateConfig struct {
	MessageVersion      uint8
	ChainID             uint32
	Iteration           uint32
	ChainKey            []byte
	SignatureKey        curve.PublicKey
	SignaturePrivateKey curve.PrivateKey
}

func NewGroupState(cfg GroupStateConfig) *GroupState {
	var private []byte
	if cfg.SignaturePrivateKey != nil {
		private = cfg.SignaturePrivateKey.Bytes()
	}

	seed := make([]byte, len(cfg.ChainKey))
	copy(seed, cfg.ChainKey)

	return &GroupState{
		state: &v1.SenderKeyStateStructure{
			MessageVersion: uint32(cfg.MessageVersion),
			ChainId:        cfg.ChainID,
			SenderChainKey: &v1.SenderKeyStateStructure_SenderChainKey{
				Iteration: cfg.Iteration,
				Seed:      seed,
			},
			SenderSigningKey: &v1.SenderKeyStateStructure_SenderSigningKey{
				Public:  cfg.SignatureKey.Bytes(),
				Private: private,
			},
		},
	}
}

func (s *GroupState) Version() uint32 {
	switch v := s.state.GetMessageVersion(); v {
	case 0:
		return 3
	default:
		return v
	}
}

func (s *GroupState) ChainID() uint32 {
	return s.state.GetChainId()
}

func (s *GroupState) SenderChainKey() senderkey.ChainKey {
	chainKey := s.state.GetSenderChainKey()
	return senderkey.NewChainKey(chainKey.GetSeed(), chainKey.GetIteration())
}

func (s *GroupState) SetSenderChainKey(chainKey senderkey.ChainKey) {
	s.state.SenderChainKey = &v1.SenderKeyStateStructure_SenderChainKey{
		Iteration: chainKey.Iteration(),
		Seed:      chainKey.Seed(),
	}
}

func (s *GroupState) PrivateSigningKey() (curve.PrivateKey, error) {
	return curve.NewPrivateKey(s.state.GetSenderSigningKey().GetPrivate())
}

func (s *GroupState) PublicSigningKey() (curve.PublicKey, error) {
	return curve.NewPublicKey(s.state.GetSenderSigningKey().GetPublic())
}

func (s *GroupState) AddMessageKey(key senderkey.MessageKey) {
	msgKeys := &v1.SenderKeyStateStructure_SenderMessageKey{
		Iteration: key.Iteration(),
		Seed:      key.Seed(),
	}
	s.state.SenderMessageKeys = append(s.state.GetSenderMessageKeys(), msgKeys)
	if len(s.state.GetSenderMessageKeys()) > maxMessageKeys {
		s.state.GetSenderMessageKeys()[0] = nil
		s.state.SenderMessageKeys = s.state.GetSenderMessageKeys()[1:]
	}
}

func (s *GroupState) RemoveMessageKeys(iteration uint32) (senderkey.MessageKey, bool, error) {
	var messageKey *v1.SenderKeyStateStructure_SenderMessageKey
	idx := -1
	for i, key := range s.state.GetSenderMessageKeys() {
		if key.GetIteration() == iteration {
			messageKey = key
			idx = i
			break
		}
	}

	if idx < 0 {
		return senderkey.MessageKey{}, false, nil
	}

	derived, err := senderkey.DeriveMessageKey(messageKey.GetSeed(), messageKey.GetIteration())
	if err != nil {
		return senderkey.MessageKey{}, false, err
	}

	s.state.GetSenderMessageKeys()[idx] = nil
	s.state.SenderMessageKeys = append(s.state.GetSenderMessageKeys()[:idx], s.state.GetSenderMessageKeys()[idx+1:]...)

	return derived, true, nil
}
