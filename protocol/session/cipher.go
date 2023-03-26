package session

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/golang/glog"

	"github.com/RTann/libsignal-go/protocol/crypto"
	"github.com/RTann/libsignal-go/protocol/curve"
	"github.com/RTann/libsignal-go/protocol/direction"
	"github.com/RTann/libsignal-go/protocol/message"
	"github.com/RTann/libsignal-go/protocol/perrors"
	"github.com/RTann/libsignal-go/protocol/ratchet"
)

const MaxJumps = 25_000

// EncryptMessage encrypts the plaintext message.
func (s *Session) EncryptMessage(ctx context.Context, plaintext []byte) (message.Ciphertext, error) {
	record, exists, err := s.SessionStore.Load(ctx, s.RemoteAddress)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, perrors.ErrSessionNotFound(s.RemoteAddress)
	}

	state := record.State()
	if state == nil {
		return nil, perrors.ErrSessionNotFound(s.RemoteAddress)
	}

	chainKey, err := state.SenderChainKey()
	if err != nil {
		return nil, err
	}
	messageKeys, err := chainKey.MessageKeys()
	if err != nil {
		return nil, err
	}

	senderEphemeral, err := state.SenderRatchetKey()
	if err != nil {
		return nil, err
	}
	previousCounter := state.PreviousCounter()
	version := uint8(state.Version())

	localIdentityKey, err := state.LocalIdentityKey()
	if err != nil {
		return nil, err
	}
	theirIdentityKey, exists, err := state.RemoteIdentityKey()
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("no remote identity key for %s", s.RemoteAddress)
	}

	ciphertext, err := crypto.AESCBCEncrypt(messageKeys.CipherKey(), messageKeys.IV(), plaintext)
	if err != nil {
		return nil, err
	}

	msg, err := message.NewSignal(message.SignalConfig{
		Version:             version,
		MACKey:              messageKeys.MACKey(),
		SenderRatchetKey:    senderEphemeral,
		PreviousCounter:     previousCounter,
		Counter:             chainKey.Index(),
		Ciphertext:          ciphertext,
		SenderIdentityKey:   localIdentityKey,
		ReceiverIdentityKey: theirIdentityKey,
	})
	if err != nil {
		return nil, err
	}

	items, err := state.UnacknowledgedPreKeyMessages()
	if err != nil {
		return nil, err
	}

	// If there are unacknowledged pre-key messages, return a pre-key message instead.
	if items != nil {
		msg, err = message.NewPreKey(message.PreKeyConfig{
			Version:        version,
			RegistrationID: state.LocalRegistrationID(),
			PreKeyID:       items.PreKeyID(),
			SignedPreKeyID: items.SignedPreKeyID(),
			BaseKey:        items.BaseKey(),
			IdentityKey:    localIdentityKey,
			Message:        msg.(*message.Signal),
		})
		if err != nil {
			return nil, err
		}
	}

	state.SetSenderChainKey(chainKey.Next())

	trusted, err := s.IdentityKeyStore.IsTrustedIdentity(ctx, s.RemoteAddress, theirIdentityKey, direction.Sending)
	if err != nil {
		return nil, err
	}
	if !trusted {
		glog.Warningf("Identity key %s is not trusted for remote address %s", hex.EncodeToString(theirIdentityKey.PublicKey().KeyBytes()), s.RemoteAddress)
		return nil, perrors.ErrUntrustedIdentity(s.RemoteAddress)
	}

	if _, err := s.IdentityKeyStore.Store(ctx, s.RemoteAddress, theirIdentityKey); err != nil {
		return nil, err
	}
	if err := s.SessionStore.Store(ctx, s.RemoteAddress, record); err != nil {
		return nil, err
	}

	return msg, nil
}

// DecryptMessage decrypts the ciphertext message.
func (s *Session) DecryptMessage(ctx context.Context, random io.Reader, ciphertext message.Ciphertext) ([]byte, error) {
	switch msg := ciphertext.(type) {
	case *message.PreKey:
		return s.decryptPreKey(ctx, random, msg)
	case *message.Signal:
		return s.decryptSignal(ctx, random, msg)
	default:
		return nil, fmt.Errorf("DecryptMessage cannot be used to decrypt %v messages", msg.Type())
	}
}

func (s *Session) decryptPreKey(ctx context.Context, random io.Reader, ciphertext *message.PreKey) ([]byte, error) {
	record, exists, err := s.SessionStore.Load(ctx, s.RemoteAddress)
	if err != nil {
		return nil, err
	}
	if !exists {
		// New "fresh" record.
		record = NewRecord(nil)
	}

	preKeyID, err := s.ProcessPreKey(ctx, record, ciphertext)
	if err != nil {
		return nil, err
	}

	plaintext, err := s.decryptMessage(random, record, ciphertext.Type(), ciphertext.Message())
	if err != nil {
		return nil, err
	}

	err = s.SessionStore.Store(ctx, s.RemoteAddress, record)
	if err != nil {
		return nil, err
	}

	if preKeyID != nil {
		err := s.PreKeyStore.Delete(ctx, *preKeyID)
		if err != nil {
			return nil, err
		}
	}

	return plaintext, nil
}

func (s *Session) decryptSignal(ctx context.Context, random io.Reader, ciphertext *message.Signal) ([]byte, error) {
	record, exists, err := s.SessionStore.Load(ctx, s.RemoteAddress)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, perrors.ErrSessionNotFound(s.RemoteAddress)
	}

	plaintext, err := s.decryptMessage(random, record, ciphertext.Type(), ciphertext)

	if record.State() == nil {
		return nil, errors.New("successfully decrypted; must have a current state")
	}
	theirIdentityKey, exists, err := record.State().RemoteIdentityKey()
	if err != nil || !exists {
		return nil, errors.New("successfully decrypted; must have a remote identity key")
	}

	trusted, err := s.IdentityKeyStore.IsTrustedIdentity(ctx, s.RemoteAddress, theirIdentityKey, direction.Receiving)
	if err != nil {
		return nil, err
	}
	if !trusted {
		glog.Warningf("Identity key %s is not trusted for remote address %v", hex.EncodeToString(theirIdentityKey.Bytes()), s.RemoteAddress)
		return nil, perrors.ErrUntrustedIdentity(s.RemoteAddress)
	}

	_, err = s.IdentityKeyStore.Store(ctx, s.RemoteAddress, theirIdentityKey)
	if err != nil {
		return nil, err
	}

	err = s.SessionStore.Store(ctx, s.RemoteAddress, record)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

type updatedState struct {
	idx       int
	state     *State
	plaintext []byte
}

func (s *Session) decryptMessage(random io.Reader, record *Record, typ message.CiphertextType, ciphertext *message.Signal) ([]byte, error) {
	if record.State() != nil {
		currentState := record.State().Clone()
		plaintext, err := s.decryptMessageSession(random, currentState, ciphertext)
		switch {
		case errors.Is(err, nil):
			glog.Infof("decrypted %v message from %v with current session state", typ, s.RemoteAddress)
			record.SetSessionState(currentState)
			return plaintext, nil
		case errors.Is(err, perrors.ErrDuplicateMessage):
			return nil, err
		default:
		}
	}

	previousStates, err := record.PreviousStates()
	if err != nil {
		return nil, err
	}

	var state *updatedState

	for i, previous := range previousStates {
		plaintext, err := s.decryptMessageSession(random, previous, ciphertext)
		switch {
		case errors.Is(err, nil):
			glog.Infof("decrypted %v message from %v with PREVIOUS session state", typ, s.RemoteAddress)
			state = &updatedState{
				idx:       i,
				state:     previous,
				plaintext: plaintext,
			}
			break
		case errors.Is(err, perrors.ErrDuplicateMessage):
			return nil, err
		default:
		}
	}

	if state != nil {
		record.PromoteOldState(state.idx, state.state)
		return state.plaintext, nil
	}

	if record.State() != nil {
		glog.Errorf("no valid session for recipient %v (previous states: %d)", s.RemoteAddress, len(previousStates))
	} else {
		glog.Errorf("no valid session for recipient %v (no current session state, previous states: %d)", s.RemoteAddress, len(previousStates))
	}

	return nil, errors.New("decryption failed: invalid message")
}

func (s *Session) decryptMessageSession(random io.Reader, state *State, ciphertext *message.Signal) ([]byte, error) {
	if state.session.GetSenderChain() == nil {
		return nil, errors.New("no session available to decrypt")
	}

	ciphertextVersion := ciphertext.Version()
	if uint32(ciphertextVersion) != state.Version() {
		return nil, fmt.Errorf("unrecognized message version: %d", ciphertextVersion)
	}

	theirEphemeral := ciphertext.SenderRatchetKey()
	counter := ciphertext.Counter()
	chainKey, err := s.chainKey(random, state, theirEphemeral)
	if err != nil {
		return nil, err
	}
	messageKeys, err := s.messageKey(state, theirEphemeral, chainKey, counter)
	if err != nil {
		return nil, err
	}

	theirIdentityKey, found, err := state.RemoteIdentityKey()
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("cannot decrypt without remote identity key")
	}

	localIdentityKey, err := state.LocalIdentityKey()
	if err != nil {
		return nil, err
	}

	valid, err := ciphertext.VerifyMAC(messageKeys.MACKey(), theirIdentityKey, localIdentityKey)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, errors.New("MAC verification failed")
	}

	plaintext, err := crypto.AESCBCDecrypt(messageKeys.CipherKey(), messageKeys.IV(), ciphertext.Message())
	if err != nil {
		return nil, err
	}

	state.ClearUnacknowledgedPreKeyMessage()

	return plaintext, nil
}

func (s *Session) chainKey(random io.Reader, state *State, theirEphemeral curve.PublicKey) (ratchet.ChainKey, error) {
	chain, exists, err := state.ReceiverChainKey(theirEphemeral)
	if err != nil {
		return ratchet.ChainKey{}, err
	}
	if exists {
		return chain, nil
	}

	glog.Infof("%v creating new chains", s.RemoteAddress)

	rootKey, err := state.RootKey()
	if err != nil {
		return ratchet.ChainKey{}, err
	}
	ourEphemeral, err := state.SenderRatchetPrivateKey()
	if err != nil {
		return ratchet.ChainKey{}, err
	}

	receiverRootKey, receiverChainKey, err := rootKey.CreateChain(ourEphemeral, theirEphemeral)
	if err != nil {
		return ratchet.ChainKey{}, err
	}

	ourNewEphemeral, err := curve.GenerateKeyPair(random)
	if err != nil {
		return ratchet.ChainKey{}, err
	}

	senderRootKey, senderChainKey, err := receiverRootKey.CreateChain(ourNewEphemeral.PrivateKey(), theirEphemeral)
	if err != nil {
		return ratchet.ChainKey{}, err
	}

	currentSenderChainKey, err := state.SenderChainKey()
	if err != nil {
		return ratchet.ChainKey{}, err
	}

	state.SetRootKey(senderRootKey)
	state.AddReceiverChain(theirEphemeral, receiverChainKey)

	previousIdx := uint32(0)
	if currentIdx := currentSenderChainKey.Index(); currentIdx > 0 {
		previousIdx = currentIdx - 1
	}
	state.SetPreviousCounter(previousIdx)
	state.SetSenderChain(ourNewEphemeral, senderChainKey)

	return receiverChainKey, nil
}

func (s *Session) messageKey(state *State, theirEphemeral curve.PublicKey, chainKey ratchet.ChainKey, counter uint32) (ratchet.MessageKeys, error) {
	chainIdx := chainKey.Index()
	if chainIdx > counter {
		if keys, found, err := state.MessageKeys(theirEphemeral, counter); err != nil {
			return ratchet.MessageKeys{}, err
		} else if found {
			return keys, nil
		}

		glog.Warningf("%v Duplicate message for counter: %d", s.RemoteAddress, counter)
		return ratchet.MessageKeys{}, perrors.ErrDuplicateMessage
	}

	jump := counter - chainIdx
	if jump > MaxJumps {
		sessionWithSelf, err := state.SessionWithSelf()
		if err != nil {
			return ratchet.MessageKeys{}, err
		}
		if sessionWithSelf {
			glog.Infof("%v Jumping ahead %d messages (index: %d, counter: %d)", s.RemoteAddress, jump, chainIdx, counter)
		} else {
			glog.Errorf("%v Exceeded future message limit: %d, index: %d, counter: %d", s.RemoteAddress, MaxJumps, chainIdx, counter)
			return ratchet.MessageKeys{}, errors.New("message from too far in the future")
		}
	}

	for chainKey.Index() < counter {
		messageKeys, err := chainKey.MessageKeys()
		if err != nil {
			return ratchet.MessageKeys{}, err
		}
		if err := state.SetMessageKeys(theirEphemeral, messageKeys); err != nil {
			return ratchet.MessageKeys{}, err
		}
		chainKey = chainKey.Next()
	}

	err := state.SetReceiverChainKey(theirEphemeral, chainKey)
	if err != nil {
		return ratchet.MessageKeys{}, err
	}

	return chainKey.MessageKeys()
}
