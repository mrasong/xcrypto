// Copyright © 2022 mrasong <i@mrasong.com>

package xcrypto

import (
	"fmt"
	"testing"
)

func TestNew(t *testing.T) {

	key := []byte("abcdefghijklmnopqrstuvwxyz")
	c := New(
		WithKey(key),
		WithPKCS7Padding(),
	)

	crypter := c.CBC()

	alarm := struct {
		Foo    string `json:"foo"`
		Hello  string `json:"hello"`
		Number int    `json:"number"`
		Bool   bool   `json:"bool"`
	}{}

	cipherData, err := crypter.Encrypt([]byte(`{
        "foo": "bar",
		"hello": "world",
		"number": 123,
		"bool": true
      }`))

	fmt.Println(cipherData.Base64(), err)
	fmt.Println(cipherData.String(), err)
	fmt.Println(cipherData.Bytes(), err)

	plaintext, err := crypter.DecryptFromBase64(cipherData.Base64())

	fmt.Println(plaintext.Base64(), err)
	fmt.Println(plaintext.String(), err)
	fmt.Println(plaintext.Bytes(), err)

	fmt.Println(plaintext.Unmarshal(&alarm))

	fmt.Println(alarm.Hello)

}
