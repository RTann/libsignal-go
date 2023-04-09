package session

import (
	"bytes"
	"errors"

	"google.golang.org/protobuf/proto"

	"github.com/RTann/libsignal-go/protocol/curve"
	v1 "github.com/RTann/libsignal-go/protocol/generated/v1"
	"github.com/RTann/libsignal-go/protocol/identity"
	"github.com/RTann/libsignal-go/protocol/internal/pointer"
	"github.com/RTann/libsignal-go/protocol/prekey"
	"github.com/RTann/libsignal-go/protocol/ratchet"
)

const (
	maxReceiverChains = 5
	maxArchivedStates = 40

	maxMessageKeys = 2000
)

var discontinuityBytes = []byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}

// State represents a session's state.
type State struct {
	session *v1.SessionStructure
}

func NewState(session *v1.SessionStructure) *State {
	return &State{
		session: session,
	}
}

func (s *State) Clone() *State {
	session := proto.Clone(s.session)
	return NewState(session.(*v1.SessionStructure))
}

func (s *State) SetAliceBaseKey(key []byte) {
	s.session.AliceBaseKey = key
}

func (s *State) AliceBaseKey() []byte {
	return s.session.GetAliceBaseKey()
}

func (s *State) Version() uint32 {
	v := s.session.GetSessionVersion()
	if v == 0 {
		return uint32(2)
	}

	return v
}

func (s *State) RemoteIdentityKey() (identity.Key, bool, error) {
	remoteBytes := s.session.GetRemoteIdentityPublic()
	if len(remoteBytes) == 0 {
		return identity.Key{}, false, nil
	}

	remoteKey, err := identity.NewKey(remoteBytes)
	if err != nil {
		return identity.Key{}, false, err
	}

	return remoteKey, true, nil
}

func (s *State) LocalIdentityKey() (identity.Key, error) {
	return identity.NewKey(s.session.GetLocalIdentityPublic())
}

func (s *State) SessionWithSelf() (bool, error) {
	remote, exists, err := s.RemoteIdentityKey()
	if err != nil {
		return false, err
	}
	if exists {
		local, err := s.LocalIdentityKey()
		if err != nil {
			return false, err
		}

		return remote.Equal(local), nil
	}

	return false, nil
}

func (s *State) SetPreviousCounter(counter uint32) {
	s.session.PreviousCounter = counter
}

func (s *State) PreviousCounter() uint32 {
	return s.session.GetPreviousCounter()
}

func (s *State) SetRootKey(key ratchet.RootKey) {
	s.session.RootKey = key.Bytes()
}

func (s *State) RootKey() (ratchet.RootKey, error) {
	return ratchet.NewRootKey(s.session.GetRootKey())
}

func (s *State) SenderRatchetPrivateKey() (curve.PrivateKey, error) {
	chain := s.session.GetSenderChain()
	if chain == nil {
		return nil, errors.New("missing sender chain")
	}

	ratchetKey, err := curve.NewPrivateKey(chain.GetSenderRatchetKeyPrivate())
	if err != nil {
		return nil, err
	}

	return ratchetKey, nil
}

func (s *State) SenderRatchetKey() (curve.PublicKey, error) {
	chain := s.session.GetSenderChain()
	if chain == nil {
		return nil, errors.New("missing sender chain")
	}

	ratchetKey, err := curve.NewPublicKey(chain.GetSenderRatchetKey())
	if err != nil {
		return nil, err
	}

	return ratchetKey, nil
}

func (s *State) ReceiverChain(sender curve.PublicKey) (int, *v1.SessionStructure_Chain) {
	key := sender.Bytes()
	for i, chain := range s.session.GetReceiverChains() {
		if bytes.Equal(chain.GetSenderRatchetKey(), key) {
			return i, chain
		}
	}

	return -1, nil
}

func (s *State) SetReceiverChainKey(sender curve.PublicKey, chainKey ratchet.ChainKey) error {
	idx, chain := s.ReceiverChain(sender)
	if idx < 0 {
		return errors.New("SetReceiverChainKey called for non-existent chain")
	}

	chain.ChainKey = &v1.SessionStructure_Chain_ChainKey{
		Index: chainKey.Index(),
		Key:   chainKey.Key(),
	}

	s.session.GetReceiverChains()[idx] = chain

	return nil
}

func (s *State) ReceiverChainKey(sender curve.PublicKey) (ratchet.ChainKey, bool, error) {
	idx, chain := s.ReceiverChain(sender)
	if idx < 0 {
		return ratchet.ChainKey{}, false, nil
	}

	chainKey, err := ratchet.NewChainKey(chain.GetChainKey().GetKey(), chain.GetChainKey().GetIndex())
	if err != nil {
		return ratchet.ChainKey{}, false, err
	}

	return chainKey, true, nil
}

func (s *State) AddReceiverChain(sender curve.PublicKey, chainKey ratchet.ChainKey) {
	chain := &v1.SessionStructure_Chain{
		SenderRatchetKey: sender.Bytes(),
		ChainKey: &v1.SessionStructure_Chain_ChainKey{
			Index: chainKey.Index(),
			Key:   chainKey.Key(),
		},
	}
	s.session.ReceiverChains = append(s.session.GetReceiverChains(), chain)

	if len(s.session.GetReceiverChains()) > maxReceiverChains {
		s.session.GetReceiverChains()[0] = nil
		s.session.ReceiverChains = s.session.GetReceiverChains()[1:]
	}
}

func (s *State) SetSenderChain(sender *curve.KeyPair, nextChainKey ratchet.ChainKey) {
	s.session.SenderChain = &v1.SessionStructure_Chain{
		SenderRatchetKey:        sender.PublicKey().Bytes(),
		SenderRatchetKeyPrivate: sender.PrivateKey().Bytes(),
		ChainKey: &v1.SessionStructure_Chain_ChainKey{
			Index: nextChainKey.Index(),
			Key:   nextChainKey.Key(),
		},
	}
}

func (s *State) SenderChainKey() (ratchet.ChainKey, error) {
	senderChain := s.session.GetSenderChain()
	if senderChain == nil {
		return ratchet.ChainKey{}, errors.New("missing sender chain")
	}

	chainKey := senderChain.GetChainKey()
	if chainKey == nil {
		return ratchet.ChainKey{}, errors.New("missing sender chain key")
	}

	return ratchet.NewChainKey(chainKey.GetKey(), chainKey.GetIndex())
}

func (s *State) SetSenderChainKey(nextChainKey ratchet.ChainKey) {
	chainKey := &v1.SessionStructure_Chain_ChainKey{
		Index: nextChainKey.Index(),
		Key:   nextChainKey.Key(),
	}

	senderChain := s.session.GetSenderChain()
	if senderChain != nil {
		senderChain.ChainKey = chainKey
		return
	}

	s.session.SenderChain = &v1.SessionStructure_Chain{
		ChainKey: chainKey,
	}
}

func (s *State) SetMessageKeys(sender curve.PublicKey, messageKeys ratchet.MessageKeys) error {
	newKeys := &v1.SessionStructure_Chain_MessageKey{
		Index:     messageKeys.Counter(),
		CipherKey: messageKeys.CipherKey(),
		MacKey:    messageKeys.MACKey(),
		Iv:        messageKeys.IV(),
	}

	idx, chain := s.ReceiverChain(sender)
	if idx < 0 {
		return errors.New("SetMessageKeys called for non-existent chain")
	}
	chain.MessageKeys = append(chain.GetMessageKeys(), newKeys)
	if len(chain.GetMessageKeys()) > maxMessageKeys {
		chain.GetMessageKeys()[0] = nil
		chain.MessageKeys = chain.GetMessageKeys()[1:]
	}

	s.session.GetReceiverChains()[idx] = chain

	return nil
}

func (s *State) MessageKeys(sender curve.PublicKey, counter uint32) (ratchet.MessageKeys, bool, error) {
	idx, chain := s.ReceiverChain(sender)
	if idx < 0 {
		return ratchet.MessageKeys{}, false, nil
	}

	var err error
	var found bool
	var messageKeys ratchet.MessageKeys
	filtered := chain.GetMessageKeys()[:0]
	for _, key := range chain.GetMessageKeys() {
		if key.GetIndex() == counter {
			found = true
			messageKeys, err = ratchet.NewMessageKeys(key.GetCipherKey(), key.GetMacKey(), key.GetIv(), counter)
			key = nil
			continue
		}

		filtered = append(filtered, key)
	}

	chain.MessageKeys = filtered

	return messageKeys, found, err
}

func (s *State) SetUnacknowledgedPreKeyMessage(preKeyID *prekey.ID, signedPreKeyID prekey.ID, baseKey curve.PublicKey) {
	pending := &v1.SessionStructure_PendingPreKey{
		SignedPreKeyId: int32(signedPreKeyID),
		BaseKey:        baseKey.Bytes(),
	}
	if preKeyID != nil {
		pending.PreKeyId = uint32(*preKeyID)
	}

	s.session.PendingPreKey = pending
}

func (s *State) ClearUnacknowledgedPreKeyMessage() {
	s.session.PendingPreKey = nil
}

type UnacknowledgedPreKeyMessageItems struct {
	preKeyID       *prekey.ID
	signedPreKeyID prekey.ID
	baseKey        curve.PublicKey
}

func (u UnacknowledgedPreKeyMessageItems) PreKeyID() *prekey.ID {
	return u.preKeyID
}

func (u UnacknowledgedPreKeyMessageItems) SignedPreKeyID() prekey.ID {
	return u.signedPreKeyID
}

func (u UnacknowledgedPreKeyMessageItems) BaseKey() curve.PublicKey {
	return u.baseKey
}

func (s *State) UnacknowledgedPreKeyMessages() (*UnacknowledgedPreKeyMessageItems, error) {
	pendingPreKey := s.session.GetPendingPreKey()
	if pendingPreKey == nil {
		return nil, nil
	}

	key, err := curve.NewPublicKey(pendingPreKey.GetBaseKey())
	if err != nil {
		return nil, err
	}

	u := &UnacknowledgedPreKeyMessageItems{
		signedPreKeyID: prekey.ID(pendingPreKey.GetSignedPreKeyId()),
		baseKey:        key,
	}

	if preKeyID := pendingPreKey.GetPreKeyId(); preKeyID != 0 {
		u.preKeyID = pointer.To(prekey.ID(preKeyID))
	}

	return u, nil
}

func (s *State) SetRemoteRegistrationID(id uint32) {
	s.session.RemoteRegistrationId = id
}

func (s *State) SetLocalRegistrationID(id uint32) {
	s.session.LocalRegistrationId = id
}

func (s *State) LocalRegistrationID() uint32 {
	return s.session.LocalRegistrationId
}

func (s *State) Bytes() []byte {
	b, _ := proto.Marshal(s.session)
	return b
}
