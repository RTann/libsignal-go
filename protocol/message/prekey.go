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
	version         uint8
	registrationID  uint32
	preKeyID        *prekey.ID
	signedPreKeyID  prekey.ID
	kyberPreKeyID   *prekey.ID
	kyberCiphertext []byte
	baseKey         curve.PublicKey
	identityKey     identity.Key
	message         *Signal
	serialized      []byte
}

// PreKeyConfig represents the configuration for a PreKey message.
type PreKeyConfig struct {
	Version         uint8
	RegistrationID  uint32
	PreKeyID        *prekey.ID
	SignedPreKeyID  prekey.ID
	KyberPreKeyID   *prekey.ID
	KyberCiphertext []byte
	BaseKey         curve.PublicKey
	IdentityKey     identity.Key
	Message         *Signal
}

func NewPreKey(cfg PreKeyConfig) (Ciphertext, error) {
	message, err := proto.Marshal(&v1.PreKeySignalMessage{
		RegistrationId:  &cfg.RegistrationID,
		PreKeyId:        (*uint32)(cfg.PreKeyID),
		SignedPreKeyId:  (*uint32)(&cfg.SignedPreKeyID),
		KyberPreKeyId:   (*uint32)(cfg.KyberPreKeyID),
		KyberCiphertext: cfg.KyberCiphertext,
		BaseKey:         cfg.BaseKey.Bytes(),
		IdentityKey:     cfg.IdentityKey.Bytes(),
		Message:         cfg.Message.Bytes(),
	})
	if err != nil {
		return nil, err
	}

	versionPrefix := ((cfg.Version & 0xF) << 4) | CiphertextVersion

	serialized := bytes.NewBuffer(make([]byte, 0, 1+len(message)))
	serialized.WriteByte(versionPrefix)
	serialized.Write(message)

	return &PreKey{
		version:         cfg.Version,
		registrationID:  cfg.RegistrationID,
		preKeyID:        cfg.PreKeyID,
		signedPreKeyID:  cfg.SignedPreKeyID,
		kyberPreKeyID:   cfg.KyberPreKeyID,
		kyberCiphertext: cfg.KyberCiphertext,
		baseKey:         cfg.BaseKey,
		identityKey:     cfg.IdentityKey,
		message:         cfg.Message,
		serialized:      serialized.Bytes(),
	}, nil
}

func NewPreKeyFromBytes(bytes []byte) (Ciphertext, error) {
	if len(bytes) == 0 {
		return nil, errors.New("message too short")
	}

	version := bytes[0] >> 4
	if int(version) < PreKyberCiphertextVersion {
		return nil, fmt.Errorf("unsupported message version: %d < %d", version, PreKyberCiphertextVersion)
	}
	if int(version) > CiphertextVersion {
		return nil, fmt.Errorf("unsupport message version: %d > %d", version, CiphertextVersion)
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
	msg, err := NewSignalFromBytes(message.GetMessage())
	if err != nil {
		return nil, err
	}
	if message.SignedPreKeyId == nil {
		return nil, errors.New("signed pre key ID must be populated")
	}

	var kyberPreKeyID *prekey.ID
	kyberCiphertext := message.GetKyberCiphertext()
	switch {
	case message.KyberPreKeyId != nil && kyberCiphertext != nil:
		kyberPreKeyID = pointer.To(prekey.ID(message.GetKyberPreKeyId()))
	case message.KyberPreKeyId == nil && kyberCiphertext == nil:
		if version > PreKyberCiphertextVersion {
			return nil, fmt.Errorf("Kyber pre key ID must be present for this message version: %d", version)
		}
	default:
		return nil, errors.New("both or neither of Kyber pre key ID and Kyber ciphertext must be present")
	}

	var preKeyID *prekey.ID
	if message.PreKeyId != nil {
		preKeyID = pointer.To(prekey.ID(message.GetPreKeyId()))
	}

	return &PreKey{
		version:         version,
		registrationID:  message.GetRegistrationId(),
		preKeyID:        preKeyID,
		signedPreKeyID:  prekey.ID(message.GetSignedPreKeyId()),
		kyberPreKeyID:   kyberPreKeyID,
		kyberCiphertext: kyberCiphertext,
		baseKey:         baseKey,
		identityKey:     identityKey,
		message:         msg.(*Signal),
		serialized:      bytes,
	}, nil
}

func (*PreKey) Type() CiphertextType {
	return PreKeyType
}

func (p *PreKey) Bytes() []byte {
	return p.serialized
}

func (p *PreKey) Version() uint8 {
	return p.version
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

func (p *PreKey) KyberPreKeyID() *prekey.ID {
	return p.kyberPreKeyID
}

func (p *PreKey) KyberCiphertext() []byte {
	return p.kyberCiphertext
}

func (p *PreKey) BaseKey() curve.PublicKey {
	return p.baseKey
}

func (p *PreKey) IdentityKey() identity.Key {
	return p.identityKey
}

func (p *PreKey) Message() *Signal {
	return p.message
}
