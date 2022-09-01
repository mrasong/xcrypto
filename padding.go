// Copyright © 2022 mrasong <i@mrasong.com>

package xcrypto

import (
	"bytes"
)

const (
	// PaddingTypeZero ZeroPadding
	PaddingTypeZero = "ZeroPadding"
	// PaddingTypePKCS7 PKCS7Padding
	PaddingTypePKCS7 = "PKCS7Padding"
)

// Padding data
func Padding(padding string, data []byte) []byte {
	var paddingData []byte
	switch padding {
	case PaddingTypeZero:
		paddingData = ZeroPadding(data)
	case PaddingTypePKCS7:
		paddingData = PKCS7Padding(data)
	}
	return paddingData
}

// Unpadding data
func Unpadding(padding string, data []byte) []byte {
	var unpaddingData []byte
	switch padding {
	case PaddingTypeZero:
		unpaddingData = ZeroUnpadding(data)
	case PaddingTypePKCS7:
		unpaddingData = PKCS7Unpadding(data)
	}
	return unpaddingData
}

// ZeroPadding Zero Padding
func ZeroPadding(data []byte) []byte {
	padding := BlockSize - len(data)%BlockSize
	if padding == BlockSize {
		return data
	}
	paddingData := bytes.Repeat([]byte{byte(0)}, padding)
	return append(data, paddingData...)
}

// ZeroUnpadding Zero unpadding
func ZeroUnpadding(data []byte) []byte {
	return bytes.TrimFunc(data, func(r rune) bool {
		return r == rune(0)
	})
}

// PKCS7Padding pkcs7Padding
func PKCS7Padding(data []byte) []byte {
	padding := BlockSize - len(data)%BlockSize
	paddingData := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, paddingData...)
}

// PKCS7Unpadding unpadding PKCS7
func PKCS7Unpadding(data []byte) []byte {
	length := len(data)
	if length == 0 || len(data)%BlockSize != 0 {
		return data
	}

	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}
