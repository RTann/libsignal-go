package session

import (
	"context"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/RTann/libsignal-go/protocol/crypto/aes"
	"github.com/RTann/libsignal-go/protocol/curve"
	"github.com/RTann/libsignal-go/protocol/direction"
	v1 "github.com/RTann/libsignal-go/protocol/generated/v1"
	"github.com/RTann/libsignal-go/protocol/message"
	"github.com/RTann/libsignal-go/protocol/perrors"
	"github.com/RTann/libsignal-go/protocol/sealedsender"
	sealedsenderv1 "github.com/RTann/libsignal-go/protocol/sealedsender/v1"
)

type SealedSenderSessionV1 struct {
	session *Session
	senderCert *sealedsender.SenderCertificate
}

func (s *SealedSenderSessionV1) EncryptMessage(ctx context.Context, rand io.Reader, plaintext []byte) ([]byte, error) {
	ciphertext, err := s.session.EncryptMessage(ctx, plaintext)
	if err != nil {
		return nil, err
	}

	msg, err := message.NewUnidentifiedSenderContent(message.UnidentifiedSenderContentConfig{
		MsgType:  ciphertext.Type(),
		Sender:   s.senderCert,
		Contents: ciphertext.Bytes(),
		Hint:     sealedsender.DefaultContentHint,
		GroupID:  nil,
	})
	if err != nil {
		return nil, err
	}

	return s.encryptMessage(ctx, rand, msg.Bytes())
}

func (s *SealedSenderSessionV1) encryptMessage(ctx context.Context, rand io.Reader, content []byte) ([]byte, error) {
	ourIdentity := s.session.IdentityKeyStore.KeyPair(ctx)
	theirIdentity, exists, err := s.session.IdentityKeyStore.Load(ctx, s.session.RemoteAddress)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, perrors.ErrSessionNotFound(s.session.RemoteAddress)
	}

	ourKeyPair, err := curve.GenerateKeyPair(rand)
	if err != nil {
		return nil, err
	}

	keys, err := sealedsenderv1.DeriveEphemeralKeys(ourKeyPair, theirIdentity.PublicKey(), direction.Sending)
	if err != nil {
		return nil, err
	}

	ephemeralCiphertext, err := aes.CTRHMACSHA256Encrypt(keys.CipherKey(), keys.MACKey(), ourIdentity.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}

	staticKeys, err := sealedsenderv1.DeriveStaticKeys(ourIdentity, theirIdentity.PublicKey(), keys.ChainKey(), ephemeralCiphertext)
	if err != nil {
		return nil, err
	}

	ciphertext, err := aes.CTRHMACSHA256Encrypt(staticKeys.CipherKey(), staticKeys.MACKey(), content)
	if err != nil {
		return nil, err
	}

	version := sealedsenderv1.Version | (sealedsenderv1.Version << 4)
	msg, err := proto.Marshal(&v1.UnidentifiedSenderMessage{
		EphemeralPublic:  ourKeyPair.PublicKey().Bytes(),
		EncryptedStatic:  ephemeralCiphertext,
		EncryptedMessage: ciphertext,
	})
	if err != nil {
		return nil, err
	}

	serialized := make([]byte, 0, len(msg)+1)
	copy(serialized, []byte{version})
	copy(serialized, msg)

	return serialized, nil
}
