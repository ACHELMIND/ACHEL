package crypto

import (
	"bytes"
	"testing"
)

func TestHMACSHA256(t *testing.T) {
	key := []byte("hmac-secret-key")
	data := []byte("data to authenticate")

	result := HMACSHA256(key, data)
	if len(result) != 32 {
		t.Errorf("HMAC length = %d, want 32", len(result))
	}

	result2 := HMACSHA256(key, data)
	if !bytes.Equal(result, result2) {
		t.Error("same inputs should produce same HMAC")
	}

	result3 := HMACSHA256([]byte("different-key"), data)
	if bytes.Equal(result, result3) {
		t.Error("different key should produce different HMAC")
	}
}

func TestVerifyHMACSHA256(t *testing.T) {
	key := []byte("hmac-secret-key")
	data := []byte("data to authenticate")

	expected := HMACSHA256(key, data)

	if !VerifyHMACSHA256(key, data, expected) {
		t.Error("valid HMAC should verify")
	}

	wrongData := []byte("wrong data")
	if VerifyHMACSHA256(key, wrongData, expected) {
		t.Error("wrong data should not verify")
	}

	wrongKey := []byte("wrong-key")
	if VerifyHMACSHA256(wrongKey, data, expected) {
		t.Error("wrong key should not verify")
	}
}

func TestHMACSHA256_EmptyInputs(t *testing.T) {
	result := HMACSHA256([]byte{}, []byte{})
	if len(result) != 32 {
		t.Errorf("HMAC of empty inputs length = %d, want 32", len(result))
	}
}
