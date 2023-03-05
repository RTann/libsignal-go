// Package direction contains the possible directions of protocol messages.
package direction

// Direction is a protocol message direction.
type Direction int

const (
	Sending = iota + 1
	Receiving
)
