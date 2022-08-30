// Copyright © 2022 mrasong <i@mrasong.com>

package xcrypto

// Option of crypto
type Option func(*Crypto)

// WithKey set key to crypto
func WithKey(key []byte) Option {
	return func(c *Crypto) {
		c.Key(key)
	}
}

// WithBlockSize set BlockSize to crypto
func WithBlockSize(blockSize int) Option {
	return func(c *Crypto) {
		c.BlockSize(blockSize)
	}
}

// WithCrypter set Crypter to crypto
func WithCrypter(crypter string) Option {
	return func(c *Crypto) {
		c.Crypter(crypter)
	}
}

// WithZeroPadding set Padding to zeropadding
func WithZeroPadding() Option {
	return func(c *Crypto) {
		c.Padding(PaddingTypeZero)
	}
}

// WithPKCS7Padding set Padding to pkcs7padding
func WithPKCS7Padding() Option {
	return func(c *Crypto) {
		c.Padding(PaddingTypePKCS7)
	}
}
