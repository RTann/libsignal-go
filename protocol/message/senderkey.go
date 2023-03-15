package message

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/RTann/libsignal-go/protocol/curve"
	"github.com/RTann/libsignal-go/protocol/distribution"
	v1 "github.com/RTann/libsignal-go/protocol/generated/v1"
	"github.com/RTann/libsignal-go/protocol/internal/pointer"
	"github.com/RTann/libsignal-go/protocol/perrors"
)

var _ Ciphertext = (*SenderKey)(nil)

type SenderKey struct {
	messageVersion uint8
	distributionID distribution.ID
	chainID        uint32
	iteration      uint32
	ciphertext     []byte
	serialized     []byte
}

func NewSenderKey(
	random io.Reader,
	messageVersion uint8,
	distributionID distribution.ID,
	chainID,
	iteration uint32,
	ciphertext []byte,
	signatureKey curve.PrivateKey,
) (*SenderKey, error) {
	message, err := proto.Marshal(&v1.SenderKeyMessage{
		DistributionUuid: []byte(distributionID.String()),
		ChainId:          pointer.To(chainID),
		Iteration:        pointer.To(iteration),
		Ciphertext:       ciphertext,
	})
	if err != nil {
		return nil, err
	}

	versionPrefix := ((messageVersion & 0xF) << 4) | SenderKeyVersion

	serialized := bytes.NewBuffer(make([]byte, 0, 1+len(message)+64))
	serialized.WriteByte(versionPrefix)
	serialized.Write(message)

	signature, err := signatureKey.Sign(random, serialized.Bytes())
	if err != nil {
		return nil, err
	}
	serialized.Write(signature)

	return &SenderKey{
		messageVersion: SenderKeyVersion,
		distributionID: distributionID,
		chainID:        chainID,
		iteration:      iteration,
		ciphertext:     ciphertext,
		serialized:     serialized.Bytes(),
	}, nil
}

func (*SenderKey) Type() CiphertextType {
	return SenderKeyType
}

func (s *SenderKey) Bytes() []byte {
	return s.serialized
}

func (s *SenderKey) Version() uint8 {
	return s.messageVersion
}

func (s *SenderKey) DistributionID() distribution.ID {
	return s.distributionID
}

func (s *SenderKey) ChainID() uint32 {
	return s.chainID
}

func (s *SenderKey) Iteration() uint32 {
	return s.iteration
}

func (s *SenderKey) Message() []byte {
	return s.ciphertext
}

func (s *SenderKey) VerifySignature(signatureKey curve.PublicKey) (bool, error) {
	idx := len(s.serialized) - 64
	return signatureKey.VerifySignature(s.serialized[idx:], s.serialized[:idx])
}

type SenderKeyDistribution struct {
	messageVersion uint8
	distributionID distribution.ID
	chainID        uint32
	iteration      uint32
	chainKey       []byte
	signingKey     curve.PublicKey
	serialized     []byte
}

func NewSenderKeyDistribution(
	messageVersion uint8,
	distributionID distribution.ID,
	chainID,
	iteration uint32,
	chainKey []byte,
	signingKey curve.PublicKey,
) (*SenderKeyDistribution, error) {
	message, err := proto.Marshal(&v1.SenderKeyDistributionMessage{
		DistributionUuid: []byte(distributionID.String()),
		ChainId:          pointer.To(chainID),
		Iteration:        pointer.To(iteration),
		ChainKey:         chainKey,
		SigningKey:       signingKey.Bytes(),
	})
	if err != nil {
		return nil, err
	}

	versionPrefix := ((messageVersion & 0xF) << 4) | SenderKeyVersion

	serialized := bytes.NewBuffer(make([]byte, 0, 1+len(message)))
	serialized.WriteByte(versionPrefix)
	serialized.Write(message)

	return &SenderKeyDistribution{
		messageVersion: messageVersion,
		distributionID: distributionID,
		chainID:        chainID,
		iteration:      iteration,
		chainKey:       chainKey,
		signingKey:     signingKey,
		serialized:     serialized.Bytes(),
	}, nil
}

func NewSenderKeyDistributionFromBytes(bytes []byte) (*SenderKeyDistribution, error) {
	// Message must contain key + chain key.
	if len(bytes) < 1+32+32 {
		return nil, errors.New("message too short")
	}

	messageVersion := bytes[0] >> 4
	if messageVersion < SenderKeyVersion {
		return nil, fmt.Errorf("unsupported message version: %d != %d", int(messageVersion), SenderKeyVersion)
	}

	var message v1.SenderKeyDistributionMessage
	err := proto.Unmarshal(bytes[1:], &message)
	if err != nil {
		return nil, err
	}

	distributionID, err := distribution.ParseBytes(message.GetDistributionUuid())
	if err != nil {
		return nil, err
	}
	chainID := message.GetChainId()
	iteration := message.GetIteration()
	chainKey := message.GetChainKey()
	if len(chainKey) != 32 {
		return nil, perrors.ErrInvalidKeyLength(32, len(chainKey))
	}
	signingKey, err := curve.NewPublicKey(message.GetSigningKey())
	if err != nil {
		return nil, err
	}

	return &SenderKeyDistribution{
		messageVersion: messageVersion,
		distributionID: distributionID,
		chainID:        chainID,
		iteration:      iteration,
		chainKey:       chainKey,
		signingKey:     signingKey,
		serialized:     bytes,
	}, nil
}

func (s *SenderKeyDistribution) Bytes() []byte {
	return s.serialized
}

func (s *SenderKeyDistribution) Version() uint8 {
	return s.messageVersion
}

func (s *SenderKeyDistribution) DistributionID() distribution.ID {
	return s.distributionID
}

func (s *SenderKeyDistribution) ChainID() uint32 {
	return s.chainID
}

func (s *SenderKeyDistribution) Iteration() uint32 {
	return s.iteration
}

func (s *SenderKeyDistribution) ChainKey() []byte {
	return s.chainKey
}

func (s *SenderKeyDistribution) SigningKey() curve.PublicKey {
	return s.signingKey
}
