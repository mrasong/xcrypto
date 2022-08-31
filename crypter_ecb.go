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
func (c *ECBCrypter) Encrypt(plaintext []byte) (Data, error) {
	var ciphertext Data
	return ciphertext, nil
}

// DecryptFromBase64 encrypt plaintext to ciphertext string
func (c *ECBCrypter) DecryptFromBase64(str string) (Data, error) {
	var plaintext, ciphertext Data
	ciphertext, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return plaintext, err
	}

	return c.Decrypt(ciphertext)
}

// Decrypt decrypt ciphertext to plaintext
func (c *ECBCrypter) Decrypt(ciphertext []byte) (Data, error) {
	var plaintext Data
	return plaintext, nil
}
