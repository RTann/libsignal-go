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
	"github.com/RTann/libsignal-go/protocol/internal/pointer"
)

var _ Ciphertext = (*Signal)(nil)

// Signal represents a typical ciphertext message.
type Signal struct {
	Version          uint8
	SenderRatchetKey curve.PublicKey
	Counter          uint32
	PreviousCounter  uint32
	Ciphertext       []byte
	serialized       []byte
}

type SignalConfig struct {
	Version          uint8
	MacKey           []byte
	SenderRatchetKey curve.PublicKey
	Counter          uint32
	PreviousCounter  uint32
	Ciphertext       []byte
	SenderIdentity   identity.Key
	ReceiverIdentity identity.Key
}

func NewSignal(cfg SignalConfig) (Ciphertext, error) {
	message, err := proto.Marshal(&v1.SignalMessage{
		RatchetKey:      cfg.SenderRatchetKey.Bytes(),
		Counter:         pointer.To(cfg.Counter),
		PreviousCounter: pointer.To(cfg.PreviousCounter),
		Ciphertext:      cfg.Ciphertext,
	})
	if err != nil {
		return nil, err
	}

	versionPrefix := ((cfg.Version & 0xF) << 4) | CiphertextVersion
	serialized := bytes.NewBuffer(make([]byte, 0, 1+len(message)+macSize))
	serialized.WriteByte(versionPrefix)
	serialized.Write(message)

	mac, err := mac(cfg.MacKey, cfg.SenderIdentity, cfg.ReceiverIdentity, serialized.Bytes())
	if err != nil {
		return nil, err
	}

	serialized.Write(mac)

	return &Signal{
		Version:          cfg.Version,
		SenderRatchetKey: cfg.SenderRatchetKey,
		Counter:          cfg.Counter,
		PreviousCounter:  cfg.PreviousCounter,
		Ciphertext:       cfg.Ciphertext,
		serialized:       serialized.Bytes(),
	}, nil
}

func NewSignalFromBytes(bytes []byte) (Ciphertext, error) {
	if len(bytes) == 0 {
		return nil, errors.New("message too short")
	}

	messageVersion := bytes[0] >> 4
	if int(messageVersion) != CiphertextVersion {
		return nil, fmt.Errorf("unsupported message version: %d != %d", int(messageVersion), CiphertextVersion)
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
		Version:          messageVersion,
		SenderRatchetKey: senderRatchetKey,
		Counter:          message.GetCounter(),
		PreviousCounter:  message.GetPreviousCounter(),
		Ciphertext:       message.GetCiphertext(),
		serialized:       bytes,
	}, nil
}

func (*Signal) Type() CiphertextType {
	return WhisperType
}

func (s *Signal) Bytes() []byte {
	return s.serialized
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
