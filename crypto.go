// Copyright © 2022 mrasong <i@mrasong.com>

package xcrypto

import (
	"crypto/aes"
	"crypto/md5"
)

const (
	// CrypterTypeCBC crypter CBC
	CrypterTypeCBC = "CBC"
	// CrypterTypeCFB crypter CFB
	CrypterTypeCFB = "CFB"
	// CrypterTypeECB crypter ECB
	CrypterTypeECB = "ECB"

	// BlockSize of AES
	BlockSize = aes.BlockSize

	// DefaultKey given a default key
	DefaultKey = "0123456789ABCDEF"
)

// Crypto struct
type Crypto struct {
	key         []byte
	padding     string
	crypterType string
	crypter     Crypter
}

// New return *Crypto
func New(opts ...Option) *Crypto {
	c := &Crypto{
		key:         []byte(DefaultKey),
		padding:     PaddingTypePKCS7,
		crypterType: CrypterTypeCBC,
	}

	for _, opt := range opts {
		opt(c)
	}

	if len(opts) == 0 {
		c.setCrypter(c.crypterType)
	}
	return c
}

// Key set key for *Crypto
func (c *Crypto) Key(key []byte) *Crypto {
	hash := md5.Sum(key)
	c.key = hash[:]
	c.setCrypter(c.crypterType)
	return c
}

// Padding set padding for *Crypto
func (c *Crypto) Padding(padding string) *Crypto {
	c.padding = padding
	c.setCrypter(c.crypterType)
	return c
}

// ZeroPadding set padding for *Crypto
func (c *Crypto) ZeroPadding() *Crypto {
	return c.Padding(PaddingTypeZero)
}

// PKCS7Padding set padding for *Crypto
func (c *Crypto) PKCS7Padding() *Crypto {
	return c.Padding(PaddingTypePKCS7)
}

// CBC return *CBCCrypter
func (c *Crypto) CBC() *Crypto {
	return c.setCrypter(CrypterTypeCBC)
}

// CFB return *CFBCrypter
func (c *Crypto) CFB() *Crypto {
	return c.setCrypter(CrypterTypeCFB)
}

// ECB return *ECBCrypter
func (c *Crypto) ECB() *Crypto {
	return c.setCrypter(CrypterTypeECB)
}

// setCrypter set crypter for *Crypto
func (c *Crypto) setCrypter(crypterType string) *Crypto {
	switch crypterType {
	case CrypterTypeCBC:
		c.crypterType = CrypterTypeCBC
		c.crypter = NewCBCCrypter(c.key, c.padding)
	case CrypterTypeCFB:
		c.crypterType = CrypterTypeCFB
		c.crypter = NewCFBCrypter(c.key, c.padding)
	case CrypterTypeECB:
		c.crypterType = CrypterTypeECB
		c.crypter = NewECBCrypter(c.key, c.padding)
	}
	return c
}

// Encrypt data
func (c *Crypto) Encrypt(data []byte) (Data, error) {
	return c.crypter.Encrypt(data)
}

// Decrypt data
func (c *Crypto) Decrypt(data []byte) (Data, error) {
	return c.crypter.Encrypt(data)
}

// DecryptFromBase64 decrypt data from base64
func (c *Crypto) DecryptFromBase64(str string) (Data, error) {
	return c.crypter.DecryptFromBase64(str)
}
