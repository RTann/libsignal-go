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
	messageVersion  uint8
	senderRachetKey curve.PublicKey
	previousCounter uint32
	counter         uint32
	ciphertext      []byte
	serialized      []byte
}

func NewSignal(
	messageVersion uint8,
	macKey []byte,
	senderRatchetKey curve.PublicKey,
	counter,
	previousCounter uint32,
	ciphertext []byte,
	senderIdentityKey,
	receiverIdentityKey identity.Key,
) (Ciphertext, error) {
	message, err := proto.Marshal(&v1.SignalMessage{
		RatchetKey:      senderRatchetKey.Bytes(),
		Counter:         pointer.To(counter),
		PreviousCounter: pointer.To(previousCounter),
		Ciphertext:      ciphertext,
	})
	if err != nil {
		return nil, err
	}

	versionPrefix := ((messageVersion & 0xF) << 4) | CiphertextVersion
	serialized := bytes.NewBuffer(make([]byte, 0, 1+len(message)+macSize))
	serialized.WriteByte(versionPrefix)
	serialized.Write(message)

	mac, err := HMAC(macKey, senderIdentityKey, receiverIdentityKey, serialized.Bytes())
	if err != nil {
		return nil, err
	}

	serialized.Write(mac)

	return &Signal{
		messageVersion:  messageVersion,
		senderRachetKey: senderRatchetKey,
		previousCounter: previousCounter,
		counter:         counter,
		ciphertext:      ciphertext,
		serialized:      serialized.Bytes(),
	}, nil
}

func NewSignalMessageFromBytes(bytes []byte) (Ciphertext, error) {
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
		messageVersion:  messageVersion,
		senderRachetKey: senderRatchetKey,
		previousCounter: message.GetPreviousCounter(),
		counter:         message.GetCounter(),
		ciphertext:      message.GetCiphertext(),
		serialized:      bytes,
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
	return s.messageVersion
}

func (s *Signal) SenderRatchetKey() curve.PublicKey {
	return s.senderRachetKey
}

func (s *Signal) Counter() uint32 {
	return s.counter
}

// VerifyMAC verifies the message authentication code (MAC) sent with the signal message
// matches our computed MAC.
//
// The MAC is expected to be an HMAC.
func (s *Signal) VerifyMAC(macKey []byte, senderIdentityKey, receiverIdentityKey identity.Key) (bool, error) {
	ourMAC, err := HMAC(macKey, senderIdentityKey, receiverIdentityKey, s.serialized[:len(s.serialized)-macSize])
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
