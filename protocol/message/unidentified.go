package message

import (
	"google.golang.org/protobuf/proto"

	"github.com/RTann/libsignal-go/protocol/curve"
	v1 "github.com/RTann/libsignal-go/protocol/generated/v1"
	"github.com/RTann/libsignal-go/protocol/internal/pointer"
	"github.com/RTann/libsignal-go/protocol/sealedsender"
)

const (
	SealedSenderV1 = 1
	SealedSenderV2 = 2
)

type UnidentifiedSender interface {
	version() int
}

var (
	_ UnidentifiedSender = (*UnidentifiedSenderV1)(nil)
	_ UnidentifiedSender = (*UnidentifiedSenderV2)(nil)
)

type UnidentifiedSenderV1 struct {
	publicEphemeral curve.PublicKey
	encryptedStatic []byte
	encryptedMsg    []byte
}

func (UnidentifiedSenderV1) version() int {
	return SealedSenderV1
}

type UnidentifiedSenderV2 struct {
	publicEphemeral curve.PublicKey
	encryptedMsgKey []byte
	authNTag        []byte
	encryptedMsg    []byte
}

func (UnidentifiedSenderV2) version() int {
	return SealedSenderV2
}

type UnidentifiedSenderContent struct {
	contents   []byte
	sender     *sealedsender.SenderCertificate
	msgType    CiphertextType
	hint       sealedsender.ContentHint
	groupID    []byte
	serialized []byte
}

type UnidentifiedSenderContentConfig struct {
	MsgType  CiphertextType
	Sender   *sealedsender.SenderCertificate
	Contents []byte
	Hint     sealedsender.ContentHint
	GroupID  []byte
}

func NewUnidentifiedSenderContent(cfg UnidentifiedSenderContentConfig) (*UnidentifiedSenderContent, error) {
	serialized, err := proto.Marshal(&v1.UnidentifiedSenderMessage_Message{
		Type:              unidentifiedMessageType(cfg.MsgType),
		SenderCertificate: cfg.Sender.Bytes(),
		Content:           cfg.Contents,
		ContentHint:       contentHint(cfg.Hint),
		GroupId:           cfg.GroupID,
	})
	if err != nil {
		return nil, err
	}

	return &UnidentifiedSenderContent{
		contents:   cfg.Contents,
		sender:     cfg.Sender,
		msgType:    cfg.MsgType,
		hint:       cfg.Hint,
		groupID:    cfg.GroupID,
		serialized: serialized,
	}, nil
}

func (u *UnidentifiedSenderContent) Bytes() []byte {
	return u.serialized
}

func unidentifiedMessageType(typ CiphertextType) *v1.UnidentifiedSenderMessage_Message_Type {
	switch typ {
	case WhisperType:
		return pointer.To(v1.UnidentifiedSenderMessage_Message_MESSAGE)
	case PreKeyType:
		return pointer.To(v1.UnidentifiedSenderMessage_Message_PREKEY_MESSAGE)
	case SenderKeyType:
		return pointer.To(v1.UnidentifiedSenderMessage_Message_SENDERKEY_MESSAGE)
	case PlaintextType:
		return pointer.To(v1.UnidentifiedSenderMessage_Message_PLAINTEXT_CONTENT)
	default:
		panic("TODO")
	}
}

func contentHint(hint sealedsender.ContentHint) *v1.UnidentifiedSenderMessage_Message_ContentHint {
	switch hint {
	case sealedsender.ResendableContentHint:
		return pointer.To(v1.UnidentifiedSenderMessage_Message_RESENDABLE)
	case sealedsender.ImplicitContentHint:
		return pointer.To(v1.UnidentifiedSenderMessage_Message_IMPLICIT)
	default:
		return nil
	}
}
