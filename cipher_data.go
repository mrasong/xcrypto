// Copyright © 2022 mrasong <i@mrasong.com>

package xcrypto

import (
	"encoding/base64"
)

// CipherData []byte
type CipherData []byte

// Base64 encrypt data to base64 string
func (data CipherData) Base64() string {
	return base64.StdEncoding.EncodeToString(data)
}

// String convert data to string
func (data CipherData) String() string {
	return string(data)
}

// Bytes convert data to Byte
func (data CipherData) Bytes() []byte {
	return []byte(data)
}
