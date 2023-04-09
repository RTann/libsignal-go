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
	"github.com/RTann/libsignal-go/protocol/perrors"
)

var _ Ciphertext = (*SenderKey)(nil)

// SenderKey represents a sender key message
// for group messaging.
type SenderKey struct {
	version    uint8
	distID     distribution.ID
	chainID    uint32
	iteration  uint32
	ciphertext []byte
	serialized []byte
}

// SenderKeyConfig represents the configuration for a SenderKey message.
type SenderKeyConfig struct {
	Version      uint8
	DistID       distribution.ID
	ChainID      uint32
	Iteration    uint32
	Ciphertext   []byte
	SignatureKey curve.PrivateKey
}

func NewSenderKey(random io.Reader, cfg SenderKeyConfig) (*SenderKey, error) {
	message, err := proto.Marshal(&v1.SenderKeyMessage{
		DistributionUuid: []byte(cfg.DistID.String()),
		ChainId:          &cfg.ChainID,
		Iteration:        &cfg.Iteration,
		Ciphertext:       cfg.Ciphertext,
	})
	if err != nil {
		return nil, err
	}

	versionPrefix := ((cfg.Version & 0xF) << 4) | SenderKeyVersion

	serialized := bytes.NewBuffer(make([]byte, 0, 1+len(message)+curve.SignatureSize))
	serialized.WriteByte(versionPrefix)
	serialized.Write(message)

	signature, err := cfg.SignatureKey.Sign(random, serialized.Bytes())
	if err != nil {
		return nil, err
	}
	serialized.Write(signature)

	return &SenderKey{
		version:    SenderKeyVersion,
		distID:     cfg.DistID,
		chainID:    cfg.ChainID,
		iteration:  cfg.Iteration,
		ciphertext: cfg.Ciphertext,
		serialized: serialized.Bytes(),
	}, nil
}

func NewSenderKeyFromBytes(bytes []byte) (*SenderKey, error) {
	if len(bytes) < 1+curve.SignatureSize {
		return nil, errors.New("message too short")
	}

	version := bytes[0] >> 4
	if int(version) != SenderKeyVersion {
		return nil, fmt.Errorf("unsupported message version: %d != %d", int(version), SenderKeyVersion)
	}

	var message v1.SenderKeyMessage
	err := proto.Unmarshal(bytes[1:len(bytes)-curve.SignatureSize], &message)
	if err != nil {
		return nil, err
	}

	distID, err := distribution.ParseBytes(message.GetDistributionUuid())
	if err != nil {
		return nil, err
	}

	return &SenderKey{
		version:    version,
		distID:     distID,
		chainID:    message.GetChainId(),
		iteration:  message.GetIteration(),
		ciphertext: message.GetCiphertext(),
		serialized: bytes,
	}, nil
}

func (*SenderKey) Type() CiphertextType {
	return SenderKeyType
}

func (s *SenderKey) Bytes() []byte {
	return s.serialized
}

func (s *SenderKey) Version() uint8 {
	return s.version
}

func (s *SenderKey) DistributionID() distribution.ID {
	return s.distID
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

// VerifySignature verifies the signature is a valid signature
// of the messages by the public key.
func (s *SenderKey) VerifySignature(signatureKey curve.PublicKey) (bool, error) {
	idx := len(s.serialized) - curve.SignatureSize
	return signatureKey.VerifySignature(s.serialized[idx:], s.serialized[:idx])
}

// SenderKeyDistribution represents a sender key distribution
// message for group messaging.
type SenderKeyDistribution struct {
	version    uint8
	distID     distribution.ID
	chainID    uint32
	iteration  uint32
	chainKey   []byte
	signingKey curve.PublicKey
	serialized []byte
}

// SenderKeyDistConfig represents the configuration for
// a SenderKeyDistribution message.
type SenderKeyDistConfig struct {
	Version    uint8
	DistID     distribution.ID
	ChainID    uint32
	Iteration  uint32
	ChainKey   []byte
	SigningKey curve.PublicKey
}

func NewSenderKeyDistribution(cfg SenderKeyDistConfig) (*SenderKeyDistribution, error) {
	message, err := proto.Marshal(&v1.SenderKeyDistributionMessage{
		DistributionUuid: []byte(cfg.DistID.String()),
		ChainId:          &cfg.ChainID,
		Iteration:        &cfg.Iteration,
		ChainKey:         cfg.ChainKey,
		SigningKey:       cfg.SigningKey.Bytes(),
	})
	if err != nil {
		return nil, err
	}

	versionPrefix := ((cfg.Version & 0xF) << 4) | SenderKeyVersion

	serialized := bytes.NewBuffer(make([]byte, 0, 1+len(message)))
	serialized.WriteByte(versionPrefix)
	serialized.Write(message)

	return &SenderKeyDistribution{
		version:    cfg.Version,
		distID:     cfg.DistID,
		chainID:    cfg.ChainID,
		iteration:  cfg.Iteration,
		chainKey:   cfg.ChainKey,
		signingKey: cfg.SigningKey,
		serialized: serialized.Bytes(),
	}, nil
}

func NewSenderKeyDistributionFromBytes(bytes []byte) (*SenderKeyDistribution, error) {
	// Message must contain key + chain key.
	if len(bytes) < 1+32+32 {
		return nil, errors.New("message too short")
	}

	messageVersion := bytes[0] >> 4
	if messageVersion != SenderKeyVersion {
		return nil, fmt.Errorf("unsupported message version: %d != %d", int(messageVersion), SenderKeyVersion)
	}

	var message v1.SenderKeyDistributionMessage
	err := proto.Unmarshal(bytes[1:], &message)
	if err != nil {
		return nil, err
	}

	distID, err := distribution.ParseBytes(message.GetDistributionUuid())
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
		version:    messageVersion,
		distID:     distID,
		chainID:    chainID,
		iteration:  iteration,
		chainKey:   chainKey,
		signingKey: signingKey,
		serialized: bytes,
	}, nil
}

func (s *SenderKeyDistribution) Bytes() []byte {
	return s.serialized
}

func (s *SenderKeyDistribution) Version() uint8 {
	return s.version
}

func (s *SenderKeyDistribution) DistributionID() distribution.ID {
	return s.distID
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
