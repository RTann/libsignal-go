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
	Version        uint8
	RegistrationID uint32
	PreKeyID       *prekey.ID
	SignedPreKeyID prekey.ID
	BaseKey        curve.PublicKey
	IdentityKey    identity.Key
	Message        *Signal
	serialized     []byte
}

type PreKeyConfig struct {
	Version        uint8
	RegistrationID uint32
	PreKeyID       *prekey.ID
	SignedPreKeyID prekey.ID
	BaseKey        curve.PublicKey
	IdentityKey    identity.Key
	Message        *Signal
}

func NewPreKey(cfg PreKeyConfig) (Ciphertext, error) {
	message, err := proto.Marshal(&v1.PreKeySignalMessage{
		RegistrationId: pointer.To(cfg.RegistrationID),
		PreKeyId:       (*uint32)(cfg.PreKeyID),
		SignedPreKeyId: pointer.To(uint32(cfg.SignedPreKeyID)),
		BaseKey:        cfg.BaseKey.Bytes(),
		IdentityKey:    cfg.IdentityKey.Bytes(),
		Message:        cfg.Message.Bytes(),
	})
	if err != nil {
		return nil, err
	}

	versionPrefix := ((cfg.Version & 0xF) << 4) | CiphertextVersion

	serialized := bytes.NewBuffer(make([]byte, 0, 1+len(message)))
	serialized.WriteByte(versionPrefix)
	serialized.Write(message)

	return &PreKey{
		Version:        cfg.Version,
		RegistrationID: cfg.RegistrationID,
		PreKeyID:       cfg.PreKeyID,
		SignedPreKeyID: cfg.SignedPreKeyID,
		BaseKey:        cfg.BaseKey,
		IdentityKey:    cfg.IdentityKey,
		Message:        cfg.Message,
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
	identityKey, err := identity.NewKey(message.GetIdentityKey())
	if err != nil {
		return nil, err
	}
	signalMessage, err := NewSignalFromBytes(message.GetMessage())
	if err != nil {
		return nil, err
	}

	return &PreKey{
		Version:        messageVersion,
		RegistrationID: message.GetRegistrationId(),
		PreKeyID:       pointer.To(prekey.ID(message.GetPreKeyId())),
		SignedPreKeyID: prekey.ID(message.GetSignedPreKeyId()),
		BaseKey:        baseKey,
		IdentityKey:    identityKey,
		Message:        signalMessage.(*Signal),
		serialized:     bytes,
	}, nil
}

func (*PreKey) Type() CiphertextType {
	return PreKeyType
}

func (p *PreKey) Bytes() []byte {
	return p.serialized
}
