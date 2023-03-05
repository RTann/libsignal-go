package message

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/RTann/libsignal-go/protocol/identity"
	"github.com/RTann/libsignal-go/protocol/perrors"
)

const (
	macKeySize = 32
	macSize    = 8
)

// HMAC calculates a message authentication code for the
// given message and keys via the Keyed-Hash Message Authentication Code.
func HMAC(macKey []byte, senderIdentityKey, receiverIdentityKey identity.Key, message []byte) ([]byte, error) {
	if len(macKey) != macKeySize {
		return nil, perrors.ErrInvalidKeyLength(macKeySize, len(macKey))
	}

	hash := hmac.New(sha256.New, macKey)
	hash.Write(senderIdentityKey.Bytes())
	hash.Write(receiverIdentityKey.Bytes())
	hash.Write(message)

	mac := make([]byte, 0, sha256.Size)
	return hash.Sum(mac)[:macSize], nil
}
