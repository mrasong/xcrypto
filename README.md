# xcrypto
AES encryption and decryption


```go

key := []byte("mrasong")
alarm := struct {
    Foo    string `json:"foo"`
    Hello  string `json:"hello"`
    Number int    `json:"number"`
    Bool   bool   `json:"bool"`
}{}
data := []byte(`{
    "foo": "bar",
    "hello": "world",
    "number": 123,
    "bool": true
    }`)

c := New(
    WithKey(key),
    WithPKCS7Padding(),
    WithCrypter(CrypterTypeCBC),
).CBC()
// c := New(
// 	WithKey(key),
// 	WithPKCS7Padding(),
// ).CBC()
// c := New(
// 	WithKey(key),
// ).PKCS7Padding().CBC()
// c := New().Key(key).PKCS7Padding().CBC()

// crypter := c.Crypter()
// crypter := c.CBCCrypter()

cipherData, err := c.Encrypt(data)
// cipherData, err := crypter.Encrypt(data)
fmt.Println("Encrypt.err:         ", err)
fmt.Println("Encrypt.Base64():    ", cipherData.Base64())
fmt.Println("Encrypt.String():    ", cipherData.String())
fmt.Println("Encrypt.HexString(): ", cipherData.HexString())
fmt.Println("Encrypt.Bytes():     ", cipherData.Bytes())

plaintextFromBase64, err := c.DecryptFromBase64(cipherData.Base64())
// plaintextFromBase64, err := crypter.DecryptFromBase64(cipherData.Base64())
fmt.Println("DecryptFromBase64.err:         ", err)
fmt.Println("DecryptFromBase64.Base64():    ", plaintextFromBase64.Base64())
fmt.Println("DecryptFromBase64.String():    ", plaintextFromBase64.String())
fmt.Println("DecryptFromBase64.HexString(): ", plaintextFromBase64.HexString())
fmt.Println("DecryptFromBase64.Bytes():     ", plaintextFromBase64.Bytes())
plaintextFromBase64.Unmarshal(&alarm)
fmt.Println("DecryptFromBase64.Unmarshal:   ", alarm.Hello)

plaintext, err := c.Decrypt(cipherData.Bytes())
fmt.Println("Decrypt.err:         ", err)
fmt.Println("Decrypt.Base64():    ", plaintext.Base64())
fmt.Println("Decrypt.String():    ", plaintext.String())
fmt.Println("Decrypt.HexString(): ", plaintext.HexString())
fmt.Println("Decrypt.Bytes():     ", plaintext.Bytes())
plaintext.Unmarshal(&alarm)
fmt.Println("Decrypt.Unmarshal:   ", alarm.Hello)

```
