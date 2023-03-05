package fingerprint

// Displayable represents a string representation of a fingerprint.
type Displayable struct {
	local  string
	remote string
}

// NewDisplayable creates a new displayable fingerprint.
func NewDisplayable(local, remote []byte) (*Displayable, error) {
	encodedLocal, err := encode(local)
	if err != nil {
		return nil, err
	}
	encodedRemote, err := encode(remote)
	if err != nil {
		return nil, err
	}

	return &Displayable{
		local:  encodedLocal,
		remote: encodedRemote,
	}, nil
}

func (d *Displayable) String() string {
	if d.local < d.remote {
		return d.local + d.remote
	}

	return d.remote + d.local
}
