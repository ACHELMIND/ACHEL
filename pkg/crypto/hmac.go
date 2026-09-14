package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

func HMACSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func VerifyHMACSHA256(key, data, expected []byte) bool {
	actual := HMACSHA256(key, data)
	return hmac.Equal(actual, expected)
}
