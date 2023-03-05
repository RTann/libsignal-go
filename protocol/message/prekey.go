package message

import (
	"bytes"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/RTann/libsignal-go/protocol/curve"
	v1 "github.com/RTann/libsignal-go/protocol/generated/v1"
	"github.com/RTann/libsignal-go/protocol/identity"
	"github.com/RTann/libsignal-go/protocol/internal/pointer"
	"github.com/RTann/libsignal-go/protocol/prekey"
)

var _ Ciphertext = (*PreKey)(nil)

// PreKey represents a pre-key message.
type PreKey struct {
	messageVersion byte
	registrationID uint32
	preKeyID       *prekey.ID
	signedPreKeyID prekey.ID
	baseKey        curve.PublicKey
	identityKey    identity.Key
	message        *Signal
	serialized     []byte
}

func NewPreKey(
	messageVersion uint8,
	registrationID uint32,
	preKeyID *prekey.ID,
	signedPreKeyID prekey.ID,
	baseKey curve.PublicKey,
	identityKey identity.Key,
	signalMessage *Signal,
) (Ciphertext, error) {
	message, err := proto.Marshal(&v1.PreKeySignalMessage{
		RegistrationId: pointer.To(registrationID),
		PreKeyId:       (*uint32)(preKeyID),
		SignedPreKeyId: pointer.To(uint32(signedPreKeyID)),
		BaseKey:        baseKey.Bytes(),
		IdentityKey:    identityKey.Bytes(),
		Message:        signalMessage.Bytes(),
	})
	if err != nil {
		return nil, err
	}

	versionPrefix := ((messageVersion & 0xF) << 4) | CiphertextVersion

	serialized := bytes.NewBuffer(make([]byte, 0, 1+len(message)))
	serialized.WriteByte(versionPrefix)
	serialized.Write(message)

	return &PreKey{
		messageVersion: messageVersion,
		registrationID: registrationID,
		preKeyID:       preKeyID,
		signedPreKeyID: signedPreKeyID,
		baseKey:        baseKey,
		identityKey:    identityKey,
		message:        signalMessage,
		serialized:     serialized.Bytes(),
	}, nil
}

func NewPreKeyFromBytes(bytes []byte) (Ciphertext, error) {
	if len(bytes) == 0 {
		return nil, errors.New("message too short")
	}

	messageVersion := bytes[0] >> 4
	if int(messageVersion) != CiphertextVersion {
		return nil, fmt.Errorf("unsupported message version: %d != %d", int(messageVersion), CiphertextVersion)
	}

	var message v1.PreKeySignalMessage
	err := proto.Unmarshal(bytes[1:], &message)
	if err != nil {
		return nil, err
	}

	baseKey, err := curve.NewPublicKey(message.GetBaseKey())
	if err != nil {
		return nil, err
	}
	identityKey, err := identity.NewKeyFromBytes(message.GetIdentityKey())
	if err != nil {
		return nil, err
	}
	signalMessage, err := NewSignalMessageFromBytes(message.GetMessage())
	if err != nil {
		return nil, err
	}

	return &PreKey{
		messageVersion: messageVersion,
		registrationID: message.GetRegistrationId(),
		preKeyID:       pointer.To(prekey.ID(message.GetPreKeyId())),
		signedPreKeyID: prekey.ID(message.GetSignedPreKeyId()),
		baseKey:        baseKey,
		identityKey:    identityKey,
		message:        signalMessage.(*Signal),
		serialized:     bytes,
	}, nil
}

func (*PreKey) Type() CiphertextType {
	return PreKeyType
}

func (p *PreKey) Bytes() []byte {
	return p.serialized
}

func (p *PreKey) Version() uint8 {
	return p.messageVersion
}

func (p *PreKey) RegistrationID() uint32 {
	return p.registrationID
}

func (p *PreKey) PreKeyID() *prekey.ID {
	return p.preKeyID
}

func (p *PreKey) SignedPreKeyID() prekey.ID {
	return p.signedPreKeyID
}

func (p *PreKey) BaseKey() curve.PublicKey {
	return p.baseKey
}

func (p *PreKey) BaseKeyBytes() []byte {
	return p.baseKey.Bytes()
}

func (p *PreKey) IdentityKey() identity.Key {
	return p.identityKey
}

func (p *PreKey) Message() *Signal {
	return p.message
}
