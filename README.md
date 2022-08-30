# xcrypto
AES encryption and decryption




```go
key := []byte("abcdefghijklmnopqrstuvwxyz")
c := New(
    WithKey(key),
    WithPKCS7Padding(),
)

crypter := c.CBC()

cipherData, err := crypter.Encrypt([]byte(`asdf`))

fmt.Println(cipherData.Base64(), err)
fmt.Println(cipherData.String(), err)
fmt.Println(cipherData.Bytes(), err)

plaintext, err := crypter.DecryptFromBase64(cipherData.Base64())

fmt.Println(plaintext.Base64(), err)
fmt.Println(plaintext.String(), err)
fmt.Println(plaintext.Bytes(), err)

```