// Copyright © 2022 mrasong <i@mrasong.com>

package xcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

// ECBCrypter cbc crypter
type ECBCrypter struct {
	key     []byte
	padding string
}

// NewECBCrypter return *ECBCrypter
func NewECBCrypter(key []byte, padding string) *ECBCrypter {
	return &ECBCrypter{
		key:     key,
		padding: padding,
	}
}

// Encrypt encrypt plaintext to ciphertext
func (c *ECBCrypter) Encrypt(plaintext []byte) (Data, error) {
	var ciphertext Data
	plaintext = Padding(c.padding, plaintext)

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return ciphertext, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext = make([]byte, BlockSize+len(plaintext))
	iv := ciphertext[:BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return ciphertext, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

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
