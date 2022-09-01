// Copyright © 2022 mrasong <i@mrasong.com>

package xcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// CFBCrypter cbc crypter
type CFBCrypter struct {
	key     []byte
	padding string
}

// NewCFBCrypter return *CFBCrypter
func NewCFBCrypter(key []byte, padding string) *CFBCrypter {
	return &CFBCrypter{
		key:     key,
		padding: padding,
	}
}

// Encrypt encrypt plaintext to ciphertext
func (c *CFBCrypter) Encrypt(plaintext []byte) (Data, error) {
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

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.
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
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return plaintext, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < BlockSize {
		return plaintext, errors.New("ciphertext too short")
	}
	iv := ciphertext[:BlockSize]
	ciphertext = ciphertext[BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	plaintext = make([]byte, len(ciphertext))
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(plaintext, ciphertext)

	plaintext = Unpadding(c.padding, plaintext)
	return plaintext, nil
}
