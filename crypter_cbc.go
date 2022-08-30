// Copyright © 2022 mrasong <i@mrasong.com>

package xcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// CBCCrypter cbc crypter
type CBCCrypter struct {
	key       []byte
	blockSize int
	padding   string
}

// NewCBCCrypter return *CBCCrypter
func NewCBCCrypter(c *Crypto) *CBCCrypter {
	return &CBCCrypter{
		key:       c.key,
		blockSize: c.blockSize,
		padding:   c.padding,
	}
}

// Encrypt encrypt plaintext to ciphertext
func (c *CBCCrypter) Encrypt(plaintext []byte) (CipherData, error) {
	var ciphertext []byte
	plaintext = Padding(c.padding, c.blockSize, plaintext)
	fmt.Println("c.blockSize", c.blockSize)
	fmt.Println("len(plaintext)", len(plaintext))
	fmt.Println("c.key", len(c.key))

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return ciphertext, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext = make([]byte, c.blockSize+len(plaintext))
	iv := ciphertext[:c.blockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return ciphertext, err
	}

	fmt.Println(len(iv))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[c.blockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.
	return ciphertext, nil
}

// DecryptFromBase64 encrypt plaintext to ciphertext string
func (c *CBCCrypter) DecryptFromBase64(str string) (CipherData, error) {
	var ciphertext CipherData
	plaintext, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return ciphertext, err
	}

	return c.Decrypt(plaintext)
}

// Decrypt decrypt ciphertext to plaintext
func (c *CBCCrypter) Decrypt(ciphertext []byte) (CipherData, error) {
	var plaintext CipherData
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return plaintext, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < c.blockSize {
		return plaintext, errors.New("ciphertext too short")
	}
	iv := ciphertext[:c.blockSize]
	ciphertext = ciphertext[c.blockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%c.blockSize != 0 {
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
	plaintext = Unpadding(c.padding, c.blockSize, plaintext)
	return plaintext, nil
}
