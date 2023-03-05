// Package fingerprint defines a protocol user's unique fingerprint.
package fingerprint

import (
	"crypto/sha512"
	"fmt"

	"github.com/RTann/libsignal-go/protocol/identity"
)

var fingerprintVersion = []byte{0x00, 0x00}

// Fingerprint represents a user's unique fingerprint.
type Fingerprint struct {
	displayable *Displayable
	scannable   *Scannable
}

// New creates a new fingerprint.
func New(
	version,
	iterations uint32,
	localID []byte,
	localKey identity.Key,
	remoteID []byte,
	remoteKey identity.Key,
) (*Fingerprint, error) {
	localFingerprint, err := fingerprint(iterations, localID, localKey)
	if err != nil {
		return nil, err
	}
	remoteFingerprint, err := fingerprint(iterations, remoteID, remoteKey)
	if err != nil {
		return nil, err
	}

	displayable, err := NewDisplayable(localFingerprint, remoteFingerprint)
	if err != nil {
		return nil, err
	}
	scannable, err := NewScannable(version, localFingerprint, remoteFingerprint)
	if err != nil {
		return nil, err
	}

	return &Fingerprint{
		displayable: displayable,
		scannable:   scannable,
	}, nil
}

// fingerprint generates a fingerprint for the user identified by the ID and key.
func fingerprint(iterations uint32, localID []byte, localKey identity.Key) ([]byte, error) {
	if iterations <= 1 || iterations > 1_000_000 {
		return nil, fmt.Errorf("invalid iterations: %d", iterations)
	}

	localKeyBytes := localKey.Bytes()

	checksum := make([]byte, 0, sha512.Size)

	// iteration 0.
	hash := sha512.New()
	hash.Write(fingerprintVersion)
	hash.Write(localKeyBytes)
	hash.Write(localID)
	hash.Write(localKeyBytes)
	checksum = hash.Sum(checksum)

	for i := uint32(1); i < iterations; i++ {
		hash.Reset()
		hash.Write(checksum)
		hash.Write(localKeyBytes)
		checksum = checksum[:0]
		checksum = hash.Sum(checksum)
	}

	return checksum, nil
}

func (f *Fingerprint) String() string {
	return f.displayable.String()
}
