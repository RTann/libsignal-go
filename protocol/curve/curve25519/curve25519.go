// Package curve25519 implements the XEd25519 signature scheme.
//
// See https://signal.org/docs/specifications/xeddsa/#curve25519 for more information.
package curve25519

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"io"

	"filippo.io/edwards25519"

	"github.com/RTann/libsignal-go/protocol/perrors"
)

const (
	PrivateKeySize = 32
	PublicKeySize  = 32
	SignatureSize  = ed25519.SignatureSize
	randomSize     = 64
)

var (
	hashPrefix = []byte{
		0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	}
)

// PrivateKey represents a Montgomery private key used for the XEdDSA scheme.
type PrivateKey struct {
	privateKey []byte
	publicKey  []byte
	scalarKey  *edwards25519.Scalar
	ecdhKey    *ecdh.PrivateKey
}

// GeneratePrivateKey generates a random private key.
//
// It is recommended to use a cryptographic random reader.
// If random is nil, then [crypto/rand.Reader] is used.
func GeneratePrivateKey(random io.Reader) (*PrivateKey, error) {
	if random == nil {
		random = rand.Reader
	}

	key := make([]byte, PrivateKeySize)
	_, err := io.ReadFull(random, key)
	if err != nil {
		return nil, err
	}

	return NewPrivateKey(key)
}

// NewPrivateKey creates a new private key based on the given input.
func NewPrivateKey(key []byte) (*PrivateKey, error) {
	if len(key) != PrivateKeySize {
		return nil, perrors.ErrInvalidKeyLength(PrivateKeySize, len(key))
	}

	scalarKey, err := edwards25519.NewScalar().SetBytesWithClamping(key)
	if err != nil {
		return nil, err
	}

	// No need to clamp here, as ECDH will take care of it.
	ecdhKey, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil {
		return nil, err
	}

	privateKey := make([]byte, PrivateKeySize)
	copy(privateKey, key)
	// Clamp the given private key.
	// See step 2 in https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5.
	privateKey[0] &= 248
	privateKey[31] &= 63
	privateKey[31] |= 64

	return &PrivateKey{
		privateKey: privateKey,
		publicKey:  xtou(scalarKey),
		scalarKey:  scalarKey,
		ecdhKey:    ecdhKey,
	}, nil
}

// Bytes returns a copy of the private key.
func (p *PrivateKey) Bytes() []byte {
	bytes := make([]byte, PrivateKeySize)
	copy(bytes, p.privateKey)
	return bytes
}

// PublicKeyBytes returns the public key in the form of a Montgomery u-point.
func (p *PrivateKey) PublicKeyBytes() []byte {
	bytes := make([]byte, PublicKeySize)
	copy(bytes, p.publicKey)
	return bytes
}

// Agreement computes the ECDH shared key between the private key and
// the given public key.
func (p *PrivateKey) Agreement(key []byte) ([]byte, error) {
	if len(key) != PublicKeySize {
		return nil, perrors.ErrInvalidKeyLength(PublicKeySize, len(key))
	}

	publicKey, err := ecdh.X25519().NewPublicKey(key)
	if err != nil {
		return nil, err
	}

	return p.ecdhKey.ECDH(publicKey)
}

// Sign calculates an XEdDSA signature using the X25519 private key, directly.
//
// The calculated signature is a valid ed25519 signature.
//
// It is recommended to use a cryptographic random reader.
// If random is nil, then [crypto/rand.Reader] is used.
func (p *PrivateKey) Sign(random io.Reader, messages ...[]byte) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}

	Z := make([]byte, randomSize)
	_, err := io.ReadFull(random, Z)
	if err != nil {
		return nil, err
	}

	a := p.scalarKey.Bytes()
	A := new(edwards25519.Point).ScalarBaseMult(p.scalarKey).Bytes()

	digest := make([]byte, 0, sha512.Size)
	hash := sha512.New()

	hash.Write(hashPrefix)
	hash.Write(a)
	for _, message := range messages {
		hash.Write(message)
	}
	hash.Write(Z)

	digest = hash.Sum(digest)
	r, err := edwards25519.NewScalar().SetUniformBytes(digest)
	if err != nil {
		return nil, err
	}
	R := new(edwards25519.Point).ScalarBaseMult(r).Bytes()

	digest = digest[:0]
	hash.Reset()

	hash.Write(R)
	hash.Write(A)
	for _, message := range messages {
		hash.Write(message)
	}

	digest = hash.Sum(digest)
	h, err := edwards25519.NewScalar().SetUniformBytes(digest)
	if err != nil {
		return nil, err
	}

	s := edwards25519.NewScalar().MultiplyAdd(p.scalarKey, h, r).Bytes()

	signBit := A[31] & 0b1000_0000

	signature := make([]byte, SignatureSize)
	copy(signature[:32], R)
	copy(signature[32:], s)
	signature[63] &= 0b0111_1111
	signature[63] |= signBit

	return signature, nil
}

// VerifySignature verifies the signature is a valid signature
// for the messages by the public key.
//
// It is expected the given public key is Montgomery u-point.
func VerifySignature(publicKey []byte, signature []byte, messages ...[]byte) (bool, error) {
	y, err := utoy(publicKey, (signature[63]&0b1000_0000) == 0)
	if err != nil {
		return false, err
	}

	// According to the spec, the signature's sign is supposed to be fixed to zero.
	// Sign does not enforce this, so we enforce it here.
	sig := make([]byte, 64)
	copy(sig, signature)
	sig[63] &= 0b0111_1111

	var msg []byte
	for _, message := range messages {
		msg = append(msg, message...)
	}

	return ed25519.Verify(y, msg, sig), nil
}
