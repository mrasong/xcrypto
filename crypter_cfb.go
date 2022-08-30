// Copyright © 2022 mrasong <i@mrasong.com>

package xcrypto

import (
	"encoding/base64"
)

// CFBCrypter cbc crypter
type CFBCrypter struct {
	key       []byte
	blockSize int
	padding   string
}

// NewCFBCrypter return *CFBCrypter
func NewCFBCrypter(c *Crypto) *CFBCrypter {
	return &CFBCrypter{
		key:       c.key,
		blockSize: c.blockSize,
		padding:   c.padding,
	}
}

// Encrypt encrypt plaintext to ciphertext
func (c *CFBCrypter) Encrypt(plaintext []byte) (CipherData, error) {
	var ciphertext []byte
	return ciphertext, nil
}

// DecryptFromBase64 encrypt plaintext to ciphertext string
func (c *CFBCrypter) DecryptFromBase64(str string) (CipherData, error) {
	var ciphertext CipherData
	plaintext, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return ciphertext, err
	}

	return c.Decrypt(plaintext)
}

// Decrypt decrypt ciphertext to plaintext
func (c *CFBCrypter) Decrypt(ciphertext []byte) (CipherData, error) {
	var plaintext CipherData
	return plaintext, nil
}
