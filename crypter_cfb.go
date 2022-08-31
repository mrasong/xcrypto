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
func (c *CFBCrypter) Encrypt(plaintext []byte) (Data, error) {
	var ciphertext Data
	return ciphertext, nil
}

// DecryptFromBase64 encrypt plaintext to ciphertext string
func (c *CFBCrypter) DecryptFromBase64(str string) (Data, error) {
	var plaintext, ciphertext Data
	ciphertext, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return plaintext, err
	}

	return c.Decrypt(ciphertext)
}

// Decrypt decrypt ciphertext to plaintext
func (c *CFBCrypter) Decrypt(ciphertext []byte) (Data, error) {
	var plaintext Data
	return plaintext, nil
}
