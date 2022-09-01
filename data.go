// Copyright © 2022 mrasong <i@mrasong.com>

package xcrypto

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
)

// Data []byte
type Data []byte

// Base64 encrypt data to base64 string
func (d Data) Base64() string {
	return base64.StdEncoding.EncodeToString(d)
}

// String convert data to string
func (d Data) String() string {
	return string(d)
}

// HexString convert data to Hex string
func (d Data) HexString() string {
	return hex.EncodeToString(d)
}

// Bytes convert data to Byte
func (d Data) Bytes() []byte {
	return []byte(d)
}

// Marshal data to json
func (d Data) Marshal() ([]byte, error) {
	return json.Marshal(d)
}

// Unmarshal Unmarshal data to out
func (d Data) Unmarshal(out any) error {
	return json.Unmarshal(d, out)
}
