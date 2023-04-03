package aes

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPKCS7Pad(t *testing.T) {
	testcases := []struct {
		plaintext string
		padding   []byte
	}{
		{
			plaintext: "",
			padding: []byte{
				0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
				0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
			},
		},
		{
			plaintext: "H",
			padding: []byte{
				0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
				0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
			},
		},
		{
			plaintext: "He",
			padding: []byte{
				0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E,
				0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E,
			},
		},
		{
			plaintext: "Hel",
			padding: []byte{
				0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
				0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
			},
		},
		{
			plaintext: "Hell",
			padding: []byte{
				0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
				0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
			},
		},
		{
			plaintext: "Hello",
			padding: []byte{
				0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
				0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
			},
		},
		{
			plaintext: "Hello,",
			padding: []byte{
				0x0A, 0x0A, 0x0A, 0x0A, 0x0A,
				0x0A, 0x0A, 0x0A, 0x0A, 0x0A,
			},
		},
		{
			plaintext: "Hello, ",
			padding: []byte{
				0x09, 0x09, 0x09, 0x09, 0x09,
				0x09, 0x09, 0x09, 0x09,
			},
		},
		{
			plaintext: "Hello, W",
			padding: []byte{
				0x08, 0x08, 0x08, 0x08,
				0x08, 0x08, 0x08, 0x08,
			},
		},
		{
			plaintext: "Hello, Wo",
			padding: []byte{
				0x07, 0x07, 0x07, 0x07,
				0x07, 0x07, 0x07,
			},
		},
		{
			plaintext: "Hello, Wor",
			padding: []byte{
				0x06, 0x06, 0x06,
				0x06, 0x06, 0x06,
			},
		},
		{
			plaintext: "Hello, Worl",
			padding: []byte{
				0x05, 0x05, 0x05,
				0x05, 0x05,
			},
		},
		{
			plaintext: "Hello, World",
			padding: []byte{
				0x04, 0x04,
				0x04, 0x04,
			},
		},
		{
			plaintext: "Hello, World!",
			padding: []byte{
				0x03, 0x03,
				0x03,
			},
		},
		{
			plaintext: "Hello, World! ",
			padding: []byte{
				0x02,
				0x02,
			},
		},
		{
			plaintext: "Hello, World! :",
			padding: []byte{
				0x01,
			},
		},
		{
			plaintext: "Hello, World! :)",
			padding: []byte{
				0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
				0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
			},
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.plaintext, func(t *testing.T) {
			padded := append([]byte(testcase.plaintext), testcase.padding...)
			assert.Equal(t, padded, pkcs7pad([]byte(testcase.plaintext)))
			unpadded, err := pkcs7unpad(padded)
			assert.NoError(t, err)
			assert.Equal(t, testcase.plaintext, string(unpadded))
		})
	}
}

func TestCBC(t *testing.T) {
	key, err := hex.DecodeString("4e22eb16d964779994222e82192ce9f747da72dc4abe49dfdeeb71d0ffe3796e")
	require.NoError(t, err)
	iv, err := hex.DecodeString("6f8a557ddc0a140c878063a6d5f31d3d")
	require.NoError(t, err)
	plaintext, err := hex.DecodeString("30736294a124482a4159")
	require.NoError(t, err)

	ciphertext, err := CBCEncrypt(key, iv, plaintext)
	assert.NoError(t, err)
	assert.Equal(t, "dd3f573ab4508b9ed0e45e0baf5608f3", hex.EncodeToString(ciphertext))

	recovered, err := CBCDecrypt(key, iv, ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(plaintext), hex.EncodeToString(recovered))

	// Invalid padding
	_, err = CBCDecrypt(key, iv, recovered)
	assert.Error(t, err)
	_, err = CBCDecrypt(key, ciphertext, ciphertext)
	assert.Error(t, err)

	badIV, err := hex.DecodeString("ef8a557ddc0a140c878063a6d5f31d3d")
	require.NoError(t, err)

	recovered, err = CBCDecrypt(key, badIV, ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, "b0736294a124482a4159", hex.EncodeToString(recovered))
	assert.NotEqual(t, hex.EncodeToString(plaintext), hex.EncodeToString(recovered))
}
