package prekey

import (
	"github.com/RTann/libsignal-go/protocol/address"
	"github.com/RTann/libsignal-go/protocol/curve"
	"github.com/RTann/libsignal-go/protocol/identity"
	"github.com/RTann/libsignal-go/protocol/kem"
)

// Bundle represents a pre-key bundle as defined by the X3DH protocol.
//
// See https://signal.org/docs/specifications/x3dh/#sending-the-initial-message for more information.
type Bundle struct {
	RegistrationID        uint32
	DeviceID              address.DeviceID
	PreKeyID              *ID
	PreKeyPublic          curve.PublicKey
	SignedPreKeyID        ID
	SignedPreKeyPublic    curve.PublicKey
	SignedPreKeySignature []byte
	IdentityKey           identity.Key
	KyberPreKeyID         *ID
	KyberPreKeyPublic     kem.PublicKey
	KyberSignature        []byte
}
