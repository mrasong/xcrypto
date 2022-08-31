// Copyright © 2022 mrasong <i@mrasong.com>

package xcrypto

// Crypter struct
type Crypter interface {
	Encrypt(data []byte) (Data, error)
	Decrypt(data []byte) (Data, error)
	DecryptFromBase64(str string) (Data, error)
}

// CBC return *CBCCrypter
func (c *Crypto) CBC() Crypter {
	c.crypter = NewCBCCrypter(c)
	return c.crypter
}

// CFB return *CFBCrypter
func (c *Crypto) CFB() Crypter {
	c.crypter = NewCFBCrypter(c)
	return c.crypter
}

// ECB return *ECBCrypter
func (c *Crypto) ECB() Crypter {
	c.crypter = NewECBCrypter(c)
	return c.crypter
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
