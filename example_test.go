package xcrypto_test

import (
	"fmt"

	"github.com/mrasong/xcrypto"
)

func ExampleNew() {
	key := []byte("key")

	c1 := xcrypto.New(
		xcrypto.WithKey(key),
		xcrypto.WithPKCS7Padding(),
		xcrypto.WithCBCCrypter(),
	)

	c2 := xcrypto.New(
		xcrypto.WithKey(key),
		xcrypto.WithPKCS7Padding(),
	).CBC()

	c3 := xcrypto.New(
		xcrypto.WithKey(key),
	).PKCS7Padding().CBC()

	c4 := xcrypto.New().Key(key).PKCS7Padding().CBC()

	fmt.Println(c1, c2, c3, c4)
}

func ExampleCrypto_Encrypt() {
	key := []byte("key")
	data := []byte(`{
        "foo": "bar",
		"hello": "world",
		"number": 123,
		"bool": true
      }`)

	c := xcrypto.New(
		xcrypto.WithKey(key),
		xcrypto.WithPKCS7Padding(),
		xcrypto.WithCBCCrypter(),
	)

	cipherData, err := c.Encrypt(data)
	fmt.Println("Encrypt.err:         ", err)
	fmt.Println("Encrypt.Base64():    ", cipherData.Base64())
	fmt.Println("Encrypt.String():    ", cipherData.String())
	fmt.Println("Encrypt.HexString(): ", cipherData.HexString())
	fmt.Println("Encrypt.Bytes():     ", cipherData.Bytes())
}

func ExampleCrypto_Decrypt() {
	key := []byte("key")
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

	c := xcrypto.New(
		xcrypto.WithKey(key),
		xcrypto.WithPKCS7Padding(),
		xcrypto.WithCBCCrypter(),
	)

	cipherData, err := c.Encrypt(data)
	plaintext, err := c.Decrypt(cipherData)
	fmt.Println("Decrypt.err:         ", err)
	fmt.Println("Decrypt.Base64():    ", plaintext.Base64())
	fmt.Println("Decrypt.String():    ", plaintext.String())
	fmt.Println("Decrypt.HexString(): ", plaintext.HexString())
	fmt.Println("Decrypt.Bytes():     ", plaintext.Bytes())
	plaintext.Unmarshal(&alarm)
	fmt.Println("Decrypt.Unmarshal:   ", alarm.Hello)
}

func ExampleCrypto_DecryptFromBase64() {
	key := []byte("key")
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

	c := xcrypto.New(
		xcrypto.WithKey(key),
		xcrypto.WithPKCS7Padding(),
	).CBC()

	cipherData, err := c.Encrypt(data)
	plaintext, err := c.DecryptFromBase64(cipherData.Base64())
	fmt.Println("Decrypt.err:         ", err)
	fmt.Println("Decrypt.Base64():    ", plaintext.Base64())
	fmt.Println("Decrypt.String():    ", plaintext.String())
	fmt.Println("Decrypt.HexString(): ", plaintext.HexString())
	fmt.Println("Decrypt.Bytes():     ", plaintext.Bytes())
	plaintext.Unmarshal(&alarm)
	fmt.Println("Decrypt.Unmarshal:   ", alarm.Hello)
}

func ExampleCBCCrypter_Encrypt() {
	key := []byte("key")
	data := []byte(`{
        "foo": "bar",
		"hello": "world",
		"number": 123,
		"bool": true
      }`)

	c := xcrypto.New(
		xcrypto.WithKey(key),
		xcrypto.WithPKCS7Padding(),
	)

	crypter := c.CBCCrypter()
	cipherData, err := crypter.Encrypt(data)
	fmt.Println("Encrypt.err:         ", err)
	fmt.Println("Encrypt.Base64():    ", cipherData.Base64())
	fmt.Println("Encrypt.String():    ", cipherData.String())
	fmt.Println("Encrypt.HexString(): ", cipherData.HexString())
	fmt.Println("Encrypt.Bytes():     ", cipherData.Bytes())
}

func ExampleCBCCrypter_Decrypt() {
	key := []byte("key")
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

	c := xcrypto.New(
		xcrypto.WithKey(key),
		xcrypto.WithPKCS7Padding(),
	)

	crypter := c.CBCCrypter()
	cipherData, err := crypter.Encrypt(data)
	plaintext, err := crypter.Decrypt(cipherData)
	fmt.Println("Decrypt.err:         ", err)
	fmt.Println("Decrypt.Base64():    ", plaintext.Base64())
	fmt.Println("Decrypt.String():    ", plaintext.String())
	fmt.Println("Decrypt.HexString(): ", plaintext.HexString())
	fmt.Println("Decrypt.Bytes():     ", plaintext.Bytes())
	plaintext.Unmarshal(&alarm)
	fmt.Println("Decrypt.Unmarshal:   ", alarm.Hello)
}

func ExampleCBCCrypter_DecryptFromBase64() {
	key := []byte("key")
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

	c := xcrypto.New(
		xcrypto.WithKey(key),
		xcrypto.WithPKCS7Padding(),
	)

	crypter := c.CBCCrypter()
	cipherData, err := crypter.Encrypt(data)

	plaintext, err := crypter.DecryptFromBase64(cipherData.Base64())
	fmt.Println("Decrypt.err:         ", err)
	fmt.Println("Decrypt.Base64():    ", plaintext.Base64())
	fmt.Println("Decrypt.String():    ", plaintext.String())
	fmt.Println("Decrypt.HexString(): ", plaintext.HexString())
	fmt.Println("Decrypt.Bytes():     ", plaintext.Bytes())
	plaintext.Unmarshal(&alarm)
	fmt.Println("Decrypt.Unmarshal:   ", alarm.Hello)
}
