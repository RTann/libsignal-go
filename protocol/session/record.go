package session

import (
	"crypto/subtle"

	"github.com/golang/glog"
	"google.golang.org/protobuf/proto"

	"github.com/RTann/libsignal-go/protocol/curve"
	v1 "github.com/RTann/libsignal-go/protocol/generated/v1"
	"github.com/RTann/libsignal-go/protocol/identity"
	"github.com/RTann/libsignal-go/protocol/perrors"
	"github.com/RTann/libsignal-go/protocol/ratchet"
)

// Record holds a record of a session's current and past states.
type Record struct {
	currentSession   *State
	previousSessions [][]byte
}

// NewRecord creates a new Record with current session set to the given state.
// Set state to `nil` for a "fresh" record.
func NewRecord(state *State) *Record {
	return &Record{
		currentSession:   state,
		previousSessions: make([][]byte, 0, maxArchivedStates),
	}
}

func NewRecordBytes(bytes []byte) (*Record, error) {
	var session v1.SessionStructure
	err := proto.Unmarshal(bytes, &session)
	if err != nil {
		return nil, err
	}

	return &Record{
		currentSession: NewState(&session),
	}, nil
}

func (r *Record) State() *State {
	return r.currentSession
}

func (r *Record) Version() (uint32, error) {
	state := r.State()
	if state == nil {
		return 0, perrors.ErrNoCurrentSession
	}

	return state.Version(), nil
}

func (r *Record) PreviousStates() ([]*State, error) {
	states := make([]*State, 0, len(r.previousSessions))
	for _, state := range r.previousSessions {
		session := new(v1.SessionStructure)
		err := proto.Unmarshal(state, session)
		if err != nil {
			return nil, err
		}
		states = append(states, NewState(session))
	}
	return states, nil
}

func (r *Record) SetSessionState(session *State) {
	r.currentSession = session
}

func (r *Record) HasSessionState(version uint32, aliceBaseKey []byte) (bool, error) {
	if r.currentSession != nil &&
		version == r.currentSession.Version() &&
		subtle.ConstantTimeCompare(aliceBaseKey, r.currentSession.AliceBaseKey()) == 1 {
		return true, nil
	}

	previousStates, err := r.PreviousStates()
	if err != nil {
		return false, err
	}
	for _, previous := range previousStates {
		if version == previous.Version() && subtle.ConstantTimeCompare(aliceBaseKey, previous.AliceBaseKey()) == 1 {
			return true, nil
		}
	}

	return false, nil
}

func (r *Record) PromoteOldState(idx int, state *State) {
	if idx < 0 || idx >= len(r.previousSessions) {
		return
	}
	r.previousSessions[idx] = nil
	r.previousSessions = append(r.previousSessions[:idx], r.previousSessions[idx+1:]...)
	r.PromoteState(state)
}

func (r *Record) PromoteState(state *State) {
	r.ArchiveCurrentState()
	r.currentSession = state
}

func (r *Record) ArchiveCurrentState() {
	if r.currentSession == nil {
		glog.Infoln("skipping archive; current session state is fresh")
		return
	}

	if len(r.previousSessions) >= maxArchivedStates {
		r.previousSessions = r.previousSessions[1:]
	}

	r.previousSessions = append(r.previousSessions, r.currentSession.Bytes())
}

func (r *Record) LocalIdentityKey() (identity.Key, error) {
	state := r.State()
	if state == nil {
		return identity.Key{}, perrors.ErrNoCurrentSession
	}

	return state.LocalIdentityKey()
}

func (r *Record) RemoteIdentityKey() (identity.Key, bool, error) {
	state := r.State()
	if state == nil {
		return identity.Key{}, false, perrors.ErrNoCurrentSession
	}

	return state.RemoteIdentityKey()
}

func (r *Record) ReceiverChainKey(sender curve.PublicKey) (ratchet.ChainKey, bool, error) {
	state := r.State()
	if state == nil {
		return ratchet.ChainKey{}, false, perrors.ErrNoCurrentSession
	}

	return state.ReceiverChainKey(sender)
}

func (r *Record) SenderChainKey() (ratchet.ChainKey, error) {
	state := r.State()
	if state == nil {
		return ratchet.ChainKey{}, perrors.ErrNoCurrentSession
	}

	return state.SenderChainKey()
}
