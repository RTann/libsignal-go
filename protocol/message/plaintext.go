// TODO: This is incomplete.

package message

import (
	"errors"
	"fmt"
)

const (
	plaintextContextIdentifier = 0xC0
	paddingBoundary            = 0x80
)

var _ Ciphertext = (*Plaintext)(nil)

// Plaintext represents a plaintext message.
type Plaintext struct {
	serialized []byte
}

func NewPlaintextFromBytes(bytes []byte) (*Plaintext, error) {
	if len(bytes) == 0 {
		return nil, errors.New("message too short")
	}

	if bytes[0] != plaintextContextIdentifier {
		return nil, fmt.Errorf("unsupported message version: %d != %d", uint32(bytes[0]), uint32(plaintextContextIdentifier))
	}

	return &Plaintext{
		serialized: bytes,
	}, nil
}

func (*Plaintext) Type() CiphertextType {
	return PlaintextType
}

func (p *Plaintext) Bytes() []byte {
	return p.serialized
}

func (p *Plaintext) Message() []byte {
	return p.serialized[1:]
}
