// TODO: This is incomplete.

package message

import (
	"bytes"
	"io"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/RTann/libsignal-go/protocol/curve"
	v1 "github.com/RTann/libsignal-go/protocol/generated/v1"
	"github.com/RTann/libsignal-go/protocol/internal/pointer"
)

var _ Ciphertext = (*SenderKey)(nil)

type SenderKey struct {
	messageVersion uint8
	distributionID uuid.UUID
	chainID        uint32
	iteration      uint32
	ciphertext     []byte
	serialized     []byte
}

func NewSenderKey(
	random io.Reader,
	messageVersion uint8,
	distributionID uuid.UUID,
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

func (s *SenderKey) VerifySignature(signatureKey curve.PublicKey) (bool, error) {
	idx := len(s.serialized) - 64
	return signatureKey.VerifySignature(s.serialized[idx:], s.serialized[:idx])
}

type SenderKeyDistribution struct {
	messageVersion uint8
	distributionID uuid.UUID
	chainID        uint32
	iteration      uint32
	chainKey       []byte
	signingKey     curve.PublicKey
	serialized     []byte
}

func NewSenderKeyDistribution(
	messageVersion uint8,
	distributionID uuid.UUID,
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
