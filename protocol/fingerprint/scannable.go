package fingerprint

import (
	"crypto/subtle"
	"fmt"

	"google.golang.org/protobuf/proto"

	v1 "github.com/RTann/libsignal-go/protocol/generated/v1"
	"github.com/RTann/libsignal-go/protocol/internal/pointer"
)

// Scannable represents a fingerprint to be displayed on a QR code.
type Scannable struct {
	version uint32
	local   []byte
	remote  []byte
}

// NewScannable creates a new scannable fingerprint.
func NewScannable(version uint32, local, remote []byte) (Scannable, error) {
	if len(local) < 32 {
		return Scannable{}, fmt.Errorf("invalid local fingerprint length: %d < 32", len(local))
	}
	if len(remote) < 32 {
		return Scannable{}, fmt.Errorf("invalid remote fingerprint length: %d < 32", len(remote))
	}

	return Scannable{
		version: version,
		local:   local[:32],
		remote:  remote[:32],
	}, nil
}

// Bytes returns an encoding of the scannable fingerprint.
func (s *Scannable) Bytes() ([]byte, error) {
	combined := v1.CombinedFingerprints{
		Version: pointer.To(s.version),
		LocalFingerprint: &v1.LogicalFingerprint{
			Content: s.local,
		},
		RemoteFingerprint: &v1.LogicalFingerprint{
			Content: s.remote,
		},
	}

	bytes, err := proto.Marshal(&combined)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

// Compare compares a scanned QR code with the expected fingerprint.
func (s *Scannable) Compare(scanned []byte) (bool, error) {
	var combined v1.CombinedFingerprints
	if err := proto.Unmarshal(scanned, &combined); err != nil {
		return false, err
	}

	theirVersion := combined.GetVersion()
	if theirVersion != s.version {
		return false, fmt.Errorf("fingerprint version mismatch: %d != %d", theirVersion, s.version)
	}

	same1 := subtle.ConstantTimeCompare(s.local, combined.GetRemoteFingerprint().GetContent()) == 1
	same2 := subtle.ConstantTimeCompare(s.remote, combined.GetLocalFingerprint().GetContent()) == 1

	return same1 && same2, nil
}
