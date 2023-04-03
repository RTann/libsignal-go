// Package aes implements AES functions used by the protocol.
package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// CBCEncrypt encrypts a plaintext message via
// AES encryption in cipher block chaining mode.
func CBCEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// cipher.NewCBCEncrypter panics if this does not hold,
	// so it's best to check here.
	if len(iv) != aes.BlockSize {
		return nil, errors.New("IV length must equal block size")
	}

	aescbc := cipher.NewCBCEncrypter(block, iv)

	// Plaintext must be padded to the next whole block.
	plaintext = pkcs7pad(plaintext)
	ciphertext := make([]byte, len(plaintext))
	aescbc.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

// CBCDecrypt decrypts a ciphertext message via
// AES encryption in cipher block chaining mode.
func CBCDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext length must be a non-zero multiple of the block size")
	}

	// cipher.NewCBCEncrypter panics if this does not hold,
	// so it's best to check here.
	if len(iv) != aes.BlockSize {
		return nil, errors.New("IV length must equal block size")
	}

	aescbc := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))
	aescbc.CryptBlocks(plaintext, ciphertext)

	return pkcs7unpad(plaintext)
}

// pkcs7pad implements PKCS #7 padding rules.
//
// See https://www.rfc-editor.org/rfc/rfc2315 Section 10.3 and
// https://www.ibm.com/docs/en/zos/2.4.0?topic=rules-pkcs-padding-method
// for more information.
func pkcs7pad(plaintext []byte) []byte {
	n := aes.BlockSize - (len(plaintext) % aes.BlockSize)

	return append(plaintext, bytes.Repeat([]byte{byte(n)}, n)...)
}

// pkcs7unpad unpads plaintext which adhered to PKS #7 padding rules.
func pkcs7unpad(plaintext []byte) ([]byte, error) {
	length := len(plaintext)
	n := int(plaintext[length-1])

	if n < 1 || n > aes.BlockSize {
		return nil, errors.New("invalid padding")
	}

	return plaintext[:length-n], nil
}
