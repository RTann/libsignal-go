package session

import "errors"

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

func (g *GroupRecord) AddState(state *GroupState) {
	
}
