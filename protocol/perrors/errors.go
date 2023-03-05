// Package perrors defines protocol errors.
package perrors

import (
	"errors"
	"fmt"

	"github.com/RTann/libsignal-go/protocol/address"
)

var (
	ErrDuplicateMessage = errors.New("duplicate message")
	ErrNoCurrentSession = errors.New("no current session")
)

var (
	_ error = (*errInvalidKeyLength)(nil)
	_ error = (*errSessionNotFound)(nil)
	_ error = (*errUntrustedIdentity)(nil)
)

type errInvalidKeyLength struct {
	expected int
	got      int
}

func ErrInvalidKeyLength(expected, got int) error {
	return errInvalidKeyLength{
		expected: expected,
		got:      got,
	}
}

func (e errInvalidKeyLength) Error() string {
	return fmt.Sprintf("invalid key length: %d != %d", e.got, e.expected)
}

type errSessionNotFound struct {
	remoteAddress address.Address
}

func ErrSessionNotFound(remoteAddress address.Address) error {
	return errSessionNotFound{
		remoteAddress: remoteAddress,
	}
}

func (e errSessionNotFound) Error() string {
	return "session with " + e.remoteAddress.String() + " not found"
}

type errUntrustedIdentity struct {
	remoteAddress address.Address
}

func ErrUntrustedIdentity(remoteAddress address.Address) error {
	return errUntrustedIdentity{
		remoteAddress: remoteAddress,
	}
}

func IsErrUntrustedIdentity(e error) bool {
	_, ok := e.(errUntrustedIdentity)
	return ok
}

func (e errUntrustedIdentity) Error() string {
	return "untrusted identity for address " + e.remoteAddress.String()
}
