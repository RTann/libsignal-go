package message

import (
	"bytes"
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/golang/glog"
	"google.golang.org/protobuf/proto"

	"github.com/RTann/libsignal-go/protocol/curve"
	v1 "github.com/RTann/libsignal-go/protocol/generated/v1"
	"github.com/RTann/libsignal-go/protocol/identity"
)

var _ Ciphertext = (*Signal)(nil)

// Signal represents a typical ciphertext message.
type Signal struct {
	version          uint8
	senderRatchetKey curve.PublicKey
	previousCounter  uint32
	counter          uint32
	ciphertext       []byte
	serialized       []byte
}

// SignalConfig represents the configuration for a Signal message.
type SignalConfig struct {
	Version             uint8
	MACKey              []byte
	SenderRatchetKey    curve.PublicKey
	PreviousCounter     uint32
	Counter             uint32
	Ciphertext          []byte
	SenderIdentityKey   identity.Key
	ReceiverIdentityKey identity.Key
}

func NewSignal(cfg SignalConfig) (Ciphertext, error) {
	message, err := proto.Marshal(&v1.SignalMessage{
		RatchetKey:      cfg.SenderRatchetKey.Bytes(),
		Counter:         &cfg.Counter,
		PreviousCounter: &cfg.PreviousCounter,
		Ciphertext:      cfg.Ciphertext,
	})
	if err != nil {
		return nil, err
	}

	versionPrefix := ((cfg.Version & 0xF) << 4) | CiphertextVersion
	serialized := bytes.NewBuffer(make([]byte, 0, 1+len(message)+macSize))
	serialized.WriteByte(versionPrefix)
	serialized.Write(message)

	mac, err := mac(cfg.MACKey, cfg.SenderIdentityKey, cfg.ReceiverIdentityKey, serialized.Bytes())
	if err != nil {
		return nil, err
	}

	serialized.Write(mac)

	return &Signal{
		version:          cfg.Version,
		senderRatchetKey: cfg.SenderRatchetKey,
		previousCounter:  cfg.PreviousCounter,
		counter:          cfg.Counter,
		ciphertext:       cfg.Ciphertext,
		serialized:       serialized.Bytes(),
	}, nil
}

func NewSignalFromBytes(bytes []byte) (Ciphertext, error) {
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

	var message v1.SignalMessage
	err := proto.Unmarshal(bytes[1:len(bytes)-macSize], &message)
	if err != nil {
		return nil, err
	}

	senderRatchetKey, err := curve.NewPublicKey(message.GetRatchetKey())
	if err != nil {
		return nil, err
	}

	return &Signal{
		version:          version,
		senderRatchetKey: senderRatchetKey,
		previousCounter:  message.GetPreviousCounter(),
		counter:          message.GetCounter(),
		ciphertext:       message.GetCiphertext(),
		serialized:       bytes,
	}, nil
}

func (*Signal) Type() CiphertextType {
	return WhisperType
}

func (s *Signal) Bytes() []byte {
	return s.serialized
}

func (s *Signal) Message() []byte {
	return s.ciphertext
}

func (s *Signal) Version() uint8 {
	return s.version
}

func (s *Signal) SenderRatchetKey() curve.PublicKey {
	return s.senderRatchetKey
}

func (s *Signal) Counter() uint32 {
	return s.counter
}

// VerifyMAC verifies the message authentication code (MAC) sent with the signal message
// matches our computed MAC.
//
// The MAC is expected to be an HMAC.
func (s *Signal) VerifyMAC(macKey []byte, senderIdentityKey, receiverIdentityKey identity.Key) (bool, error) {
	ourMAC, err := mac(macKey, senderIdentityKey, receiverIdentityKey, s.serialized[:len(s.serialized)-macSize])
	if err != nil {
		return false, err
	}
	theirMAC := s.serialized[len(s.serialized)-macSize:]
	equal := hmac.Equal(ourMAC, theirMAC)
	if !equal {
		glog.Warningf("Bad Mac! Their Mac: %s Our Mac: %s", hex.EncodeToString(theirMAC), hex.EncodeToString(ourMAC))
	}

	return equal, nil
}
