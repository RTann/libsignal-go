// Package message defines protocol messages.
package message

//go:generate stringer -type=CiphertextType

// CiphertextType represents a protocol message type.
type CiphertextType int

const (
	WhisperType   CiphertextType = 2
	PreKeyType    CiphertextType = 3
	SenderKeyType CiphertextType = 7
	PlaintextType CiphertextType = 8
)

const (
	// CiphertextVersion is the current version of ciphertext messages.
	CiphertextVersion = 4
	// PreKyberCiphertextVersion is the last ciphertext version prior to Kyber support.
	PreKyberCiphertextVersion = 3
	// SenderKeyVersion is the current version of sender-key messages.
	SenderKeyVersion = 3
)

// Ciphertext defines a ciphertext message.
type Ciphertext interface {
	// Type is the CiphertextType of the message.
	Type() CiphertextType
	// Bytes returns an encoding of the Ciphertext message.
	Bytes() []byte
}

// Version returns the current ciphertext version when kyber is true.
// Otherwise, it returns the last pre-kyber ciphertext version.
func Version(kyber bool) uint32 {
	if kyber {
		return CiphertextVersion
	}
	return PreKyberCiphertextVersion
}
