package fingerprint

import (
	"fmt"
	"strings"
)

func encode(bytes []byte) (string, error) {
	if len(bytes) < 30 {
		return "", fmt.Errorf("encoding too short: %d < 30", len(bytes))
	}

	uint64FromChunk := func(chunk [5]byte) uint64 {
		return uint64(chunk[0]&0xFF)<<32 |
			uint64(chunk[1]&0xFF)<<24 |
			uint64(chunk[2]&0xFF)<<16 |
			uint64(chunk[3]&0xFF)<<8 |
			uint64(chunk[4]&0xFF)
	}
	encodeChunk := func(chunk [5]byte) string {
		return fmt.Sprintf("%05d", uint64FromChunk(chunk)%100_000)
	}

	var encoding strings.Builder
	encoding.WriteString(encodeChunk([5]byte(bytes[:5])))
	encoding.WriteString(encodeChunk([5]byte(bytes[5:10])))
	encoding.WriteString(encodeChunk([5]byte(bytes[10:15])))
	encoding.WriteString(encodeChunk([5]byte(bytes[15:20])))
	encoding.WriteString(encodeChunk([5]byte(bytes[20:25])))
	encoding.WriteString(encodeChunk([5]byte(bytes[25:30])))

	return encoding.String(), nil
}
