package fingerprint

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScannable(t *testing.T) {
	l := []byte{
		0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
		0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
		0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
	}
	r := []byte{
		0xBA, 0xBA, 0xBA, 0xBA, 0xBA, 0xBA, 0xBA, 0xBA, 0xBA, 0xBA, 0xBA,
		0xBA, 0xBA, 0xBA, 0xBA, 0xBA, 0xBA, 0xBA, 0xBA, 0xBA, 0xBA, 0xBA,
		0xBA, 0xBA, 0xBA, 0xBA, 0xBA, 0xBA, 0xBA, 0xBA, 0xBA, 0xBA,
	}

	scannable, err := NewScannable(2, l, r)
	require.NoError(t, err)
	scannableBytes, err := scannable.Bytes()
	require.NoError(t, err)

	var expected strings.Builder
	expected.WriteString("080212220a20")
	for i := 0; i < 32; i++ {
		expected.WriteString("12")
	}
	expected.WriteString("1a220a20")
	for i := 0; i < 32; i++ {
		expected.WriteString("ba")
	}

	assert.Equal(t, expected.String(), hex.EncodeToString(scannableBytes))
}
