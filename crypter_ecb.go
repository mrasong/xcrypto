// Copyright © 2022 mrasong <i@mrasong.com>

package xcrypto

import (
	"encoding/base64"
)

// ECBCrypter cbc crypter
type ECBCrypter struct {
	key       []byte
	blockSize int
	padding   string
}

// NewECBCrypter return *ECBCrypter
func NewECBCrypter(c *Crypto) *ECBCrypter {
	return &ECBCrypter{
		key:       c.key,
		blockSize: c.blockSize,
		padding:   c.padding,
	}
}

// Encrypt encrypt plaintext to ciphertext
func (c *ECBCrypter) Encrypt(plaintext []byte) (CipherData, error) {
	var ciphertext []byte
	return ciphertext, nil
}

// DecryptFromBase64 encrypt plaintext to ciphertext string
func (c *ECBCrypter) DecryptFromBase64(str string) (CipherData, error) {
	var ciphertext CipherData
	plaintext, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return ciphertext, err
	}

	return c.Decrypt(plaintext)
}

// Decrypt decrypt ciphertext to plaintext
func (c *ECBCrypter) Decrypt(ciphertext []byte) (CipherData, error) {
	var plaintext CipherData
	return plaintext, nil
}
