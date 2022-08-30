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
func Padding(padding string, blockSize int, data []byte) []byte {
	var paddingData []byte
	switch padding {
	case PaddingTypeZero:
		paddingData = ZeroPadding(blockSize, data)
	case PaddingTypePKCS7:
		paddingData = PKCS7Padding(blockSize, data)
	}
	return paddingData
}

// Unpadding data
func Unpadding(padding string, blockSize int, data []byte) []byte {
	var unpaddingData []byte
	switch padding {
	case PaddingTypeZero:
		unpaddingData = ZeroUnpadding(data)
	case PaddingTypePKCS7:
		unpaddingData = PKCS7Unpadding(blockSize, data)
	}
	return unpaddingData
}

// ZeroPadding Zero Padding
func ZeroPadding(blockSize int, data []byte) []byte {
	padding := blockSize - len(data)%blockSize
	if padding == blockSize {
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
func PKCS7Padding(blockSize int, data []byte) []byte {
	padding := blockSize - len(data)%blockSize
	paddingData := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, paddingData...)
}

// PKCS7Unpadding unpadding PKCS7
func PKCS7Unpadding(blockSize int, data []byte) []byte {
	length := len(data)
	if length == 0 || len(data)%blockSize != 0 {
		panic("PKCS5Unpadding: data length error")
	}

	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}