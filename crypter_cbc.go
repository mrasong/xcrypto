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

// CBCCrypter cbc crypter
type CBCCrypter struct {
	key     []byte
	padding string
}

// NewCBCCrypter return *CBCCrypter
func NewCBCCrypter(key []byte, padding string) *CBCCrypter {
	return &CBCCrypter{
		key:     key,
		padding: padding,
	}
}

// Encrypt encrypt plaintext to ciphertext
func (c *CBCCrypter) Encrypt(plaintext []byte) (Data, error) {
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
	mode.CryptBlocks(ciphertext[BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.
	return ciphertext, nil
}

// DecryptFromBase64 encrypt plaintext to ciphertext string
func (c *CBCCrypter) DecryptFromBase64(str string) (Data, error) {
	var ciphertext Data
	ciphertext, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return ciphertext, err
	}

	return c.Decrypt(ciphertext)
}

// Decrypt decrypt ciphertext to plaintext
func (c *CBCCrypter) Decrypt(ciphertext []byte) (Data, error) {
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

	// CBC mode always works in whole blocks.
	if len(ciphertext)%BlockSize != 0 {
		return plaintext, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	plaintext = make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.
	plaintext = Unpadding(c.padding, plaintext)
	return plaintext, nil
}
