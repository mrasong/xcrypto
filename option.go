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

// WithCBCCrypter set Crypter to CBCCrypter
func WithCBCCrypter() Option {
	return func(c *Crypto) {
		c.CBC()
	}
}

// WithCFBCrypter set Crypter to CFBCrypter
func WithCFBCrypter() Option {
	return func(c *Crypto) {
		c.CFB()
	}
}

// WithECBCrypter set Crypter to ECBCrypter
func WithECBCrypter() Option {
	return func(c *Crypto) {
		c.ECB()
	}
}
