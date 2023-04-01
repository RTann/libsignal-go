package sealedsender

import (
	"io"

	"github.com/golang/glog"
	"google.golang.org/protobuf/proto"

	"github.com/RTann/libsignal-go/protocol/address"
	"github.com/RTann/libsignal-go/protocol/curve"
	v1 "github.com/RTann/libsignal-go/protocol/generated/v1"
)

var revokedKeyIDS = []uint32{
	0xDEADC357,
}

type ServerCertificate struct {
	keyID       uint32
	key         curve.PublicKey
	certificate []byte
	signature   []byte
	serialized  []byte
}

type ServerCertificateConfig struct {
	KeyID     uint32
	Key       curve.PublicKey
	TrustRoot curve.PrivateKey
}

func NewServerCertificate(random io.Reader, cfg ServerCertificateConfig) (*ServerCertificate, error) {
	certificate, err := proto.Marshal(&v1.ServerCertificate_Certificate{
		Id:  &cfg.KeyID,
		Key: cfg.Key.Bytes(),
	})
	if err != nil {
		return nil, err
	}

	signature, err := cfg.TrustRoot.Sign(random, certificate)
	if err != nil {
		return nil, err
	}

	serialized, err := proto.Marshal(&v1.ServerCertificate{
		Certificate: certificate,
		Signature:   signature,
	})
	if err != nil {
		return nil, err
	}

	return &ServerCertificate{
		keyID:       cfg.KeyID,
		key:         cfg.Key,
		certificate: certificate,
		signature:   signature,
		serialized:  serialized,
	}, nil
}

func (s *ServerCertificate) Validate(trustRoot curve.PublicKey) (bool, error) {
	for _, revokedKeyID := range revokedKeyIDS {
		if revokedKeyID == s.keyID {
			glog.Errorf("received server certificate with revoked ID %d", s.keyID)
			return false, nil
		}
	}

	return trustRoot.VerifySignature(s.signature, s.certificate)
}

func (s *ServerCertificate) KeyID() uint32 {
	return s.keyID
}

func (s *ServerCertificate) PublicKey() curve.PublicKey {
	return s.key
}

func (s *ServerCertificate) Certificate() []byte {
	return s.certificate
}

func (s *ServerCertificate) Signature() []byte {
	return s.signature
}

func (s *ServerCertificate) Bytes() []byte {
	return s.serialized
}

func (s *ServerCertificate) proto() *v1.ServerCertificate {
	return &v1.ServerCertificate{
		Certificate: s.certificate,
		Signature:   s.signature,
	}
}

type SenderCertificate struct {
	senderUUID     string
	senderE164     string
	senderDeviceID address.DeviceID
	key            curve.PublicKey
	signer         *ServerCertificate
	certificate    []byte
	signature      []byte
	expiration     uint64
	serialized     []byte
}

type SenderCertificateConfig struct {
	SenderUUID     string
	SenderE164     string
	SenderDeviceID address.DeviceID
	Key            curve.PublicKey
	Signer         *ServerCertificate
	SignerKey      curve.PrivateKey
	Expiration     uint64
}

func NewSenderCertificate(random io.Reader, cfg SenderCertificateConfig) (*SenderCertificate, error) {
	certificate, err := proto.Marshal(&v1.SenderCertificate_Certificate{
		SenderE164:   &cfg.SenderE164,
		SenderUuid:   &cfg.SenderUUID,
		SenderDevice: (*uint32)(&cfg.SenderDeviceID),
		Expires:      &cfg.Expiration,
		IdentityKey:  cfg.Key.Bytes(),
		Signer:       cfg.Signer.proto(),
	})
	if err != nil {
		return nil, err
	}

	signature, err := cfg.SignerKey.Sign(random, certificate)
	if err != nil {
		return nil, err
	}

	serialized, err := proto.Marshal(&v1.SenderCertificate{
		Certificate: certificate,
		Signature:   signature,
	})
	if err != nil {
		return nil, err
	}

	return &SenderCertificate{
		senderUUID:     cfg.SenderUUID,
		senderE164:     cfg.SenderE164,
		senderDeviceID: cfg.SenderDeviceID,
		key:            cfg.Key,
		signer:         cfg.Signer,
		certificate:    certificate,
		signature:      signature,
		expiration:     cfg.Expiration,
		serialized:     serialized,
	}, nil
}

func (s *SenderCertificate) Validate(trustRoot curve.PublicKey, validationTime uint64) (bool, error) {
	validServer, err := s.signer.Validate(trustRoot)
	if err != nil {
		return false, err
	}
	if !validServer {
		glog.Errorln("received server certificate not signed by trust root")
		return false, nil
	}

	validSender, err := s.signer.PublicKey().VerifySignature(s.signature, s.certificate)
	if err != nil {
		return false, err
	}
	if !validSender {
		glog.Errorln("received sender certificate not signed by server")
		return false, nil
	}

	if validationTime > s.expiration {
		glog.Errorf("received expired sender certificate (expiration: %d, validation_time: %d)", s.expiration, validationTime)
		return false, nil
	}

	return true, nil
}

func (s *SenderCertificate) Signer() *ServerCertificate {
	return s.signer
}

func (s *SenderCertificate) Key() curve.PublicKey {
	return s.key
}

func (s *SenderCertificate) Bytes() []byte {
	return s.serialized
}
