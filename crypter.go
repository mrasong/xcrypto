// Copyright © 2022 mrasong <i@mrasong.com>

package xcrypto

// Crypter struct
type Crypter interface {
	Encrypt(data []byte) (Data, error)
	Decrypt(data []byte) (Data, error)
	DecryptFromBase64(str string) (Data, error)
}

// Crypter return Crypter
func (c *Crypto) Crypter() Crypter {
	return c.crypter
}

// CBCCrypter return *CBCCrypter
func (c *Crypto) CBCCrypter() Crypter {
	return c.CBC().crypter
}

// CFBCrypter return *CFBCrypter
func (c *Crypto) CFBCrypter() Crypter {
	return c.CFB().crypter
}

// ECBCrypter return *ECBCrypter
func (c *Crypto) ECBCrypter() Crypter {
	return c.ECB().crypter
}
