package session

import (
	"errors"

	"github.com/golang/glog"

	"github.com/RTann/libsignal-go/protocol/curve"
)

const maxSenderKeyStates = 5

type GroupRecord struct {
	states []*GroupState
}

func NewGroupRecord() *GroupRecord {
	return &GroupRecord{
		states: make([]*GroupState, 0, maxSenderKeyStates),
	}
}

func (g *GroupRecord) State() (*GroupState, error) {
	if len(g.states) == 0 {
		return nil, errors.New("empty sender key state")
	}

	return g.states[0], nil
}

func (g *GroupRecord) StateForChainID(chainID uint32) *GroupState {
	for _, state := range g.states {
		if chainID == state.ChainID() {
			return state
		}
	}

	return nil
}

func (g *GroupRecord) AddState(state *GroupState) error {
	signingKey, err := state.PublicSigningKey()
	if err != nil {
		return err
	}

	existing, removed := g.RemoveState(state.ChainID(), signingKey)

	if g.RemoveStates(state.ChainID()) > 0 {
		glog.Warningf("Removed a matching chain_id (%d) found with a different public key", state.ChainID())
	}

	if !removed {
		existing = state
	}

	if len(g.states) >= maxSenderKeyStates {
		g.states[0] = nil
		g.states = g.states[1:]
	}

	g.states = append(g.states, existing)

	return nil
}

func (g *GroupRecord) RemoveState(chainID uint32, signatureKey curve.PublicKey) (*GroupState, bool) {
	idx := -1
	for i, state := range g.states {
		publicKey, err := state.PublicSigningKey()
		if err != nil {
			continue
		}
		if state.ChainID() == chainID && signatureKey.Equal(publicKey) {
			idx = i
			break
		}
	}

	if idx < 0 {
		return nil, false
	}

	state := g.states[idx]
	g.states = append(g.states[:idx], g.states[idx+1:]...)

	return state, true
}

func (g *GroupRecord) RemoveStates(chainID uint32) int {
	length := len(g.states)
	filtered := g.states[:0]
	for _, state := range g.states {
		if state.ChainID() == chainID {
			continue
		}

		filtered = append(filtered, state)
	}
	// TODO: set remaining to nil?
	g.states = filtered

	return length - len(filtered)
}
