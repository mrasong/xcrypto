// Copyright © 2022 mrasong <i@mrasong.com>

package xcrypto

const (
	// CrypterTypeCBC crypter CBC
	CrypterTypeCBC = "CBC"
	// CrypterTypeCFB crypter CFB
	CrypterTypeCFB = "CFB"
	// CrypterTypeECB crypter ECB
	CrypterTypeECB = "ECB"

	// blocksize
	blocksize = 16
)

// Crypto struct
type Crypto struct {
	key       []byte
	blockSize int
	padding   string
	crypter   Crypter
}

// New return *Crypto
func New(opts ...Option) *Crypto {
	c := &Crypto{
		key:       []byte("0123456789ABCDEF"),
		blockSize: blocksize,
		padding:   PaddingTypePKCS7,
	}
	c.crypter = c.CBC()

	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Key set key for *Crypto
func (c *Crypto) Key(key []byte) *Crypto {
	c.key = ZeroPadding(c.blockSize, key)
	return c
}

// BlockSize set blockSize for *Crypto
func (c *Crypto) BlockSize(blockSize int) *Crypto {
	c.blockSize = blockSize
	return c
}

// Padding set padding for *Crypto
func (c *Crypto) Padding(padding string) *Crypto {
	c.padding = padding
	return c
}

// ZeroPadding set padding for *Crypto
func (c *Crypto) ZeroPadding() *Crypto {
	c.padding = PaddingTypeZero
	return c
}

// PKCS7Padding set padding for *Crypto
func (c *Crypto) PKCS7Padding() *Crypto {
	c.padding = PaddingTypePKCS7
	return c
}

// Crypter set crypter for *Crypto
func (c *Crypto) Crypter(crypterType string) *Crypto {
	switch crypterType {
	case CrypterTypeCBC:
		c.crypter = c.CBC()
	case CrypterTypeCFB:
		c.crypter = c.CFB()
	case CrypterTypeECB:
		c.crypter = c.ECB()
	}
	return c
}
