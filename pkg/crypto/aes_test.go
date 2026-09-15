package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	key := DeriveKey("password", []byte("salt"))
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}

	key2 := DeriveKey("password", []byte("salt"))
	if !bytes.Equal(key, key2) {
		t.Error("same inputs should produce same key")
	}

	key3 := DeriveKey("password", []byte("different-salt"))
	if bytes.Equal(key, key3) {
		t.Error("different salt should produce different key")
	}
}

func TestEncryptDecryptAESGCM(t *testing.T) {
	key := GenerateAESKey()
	plaintext := []byte("hello, angel platform encryption test")

	ciphertext, err := EncryptAESGCM(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptAESGCM: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted, err := DecryptAESGCM(key, ciphertext)
	if err != nil {
		t.Fatalf("DecryptAESGCM: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptAESGCM_WrongKey(t *testing.T) {
	key1 := GenerateAESKey()
	key2 := GenerateAESKey()
	plaintext := []byte("secret data")

	ciphertext, err := EncryptAESGCM(key1, plaintext)
	if err != nil {
		t.Fatalf("EncryptAESGCM: %v", err)
	}

	_, err = DecryptAESGCM(key2, ciphertext)
	if err == nil {
		t.Error("expected error when decrypting with wrong key")
	}
}

func TestDecryptAESGCM_TooShort(t *testing.T) {
	key := GenerateAESKey()
	_, err := DecryptAESGCM(key, []byte("short"))
	if err == nil {
		t.Error("expected error for short ciphertext")
	}
}

func TestGenerateAESKey(t *testing.T) {
	key := GenerateAESKey()
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}

	key2 := GenerateAESKey()
	if bytes.Equal(key, key2) {
		t.Error("generated keys should differ")
	}
}

func TestXOR(t *testing.T) {
	data := []byte("hello world")
	key := []byte("key")

	result := XOR(data, key)
	decrypted := XOR(result, key)

	if !bytes.Equal(decrypted, data) {
		t.Errorf("XOR round-trip failed: %q, want %q", decrypted, data)
	}
}

func TestXOR_EmptyKey(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for empty key")
		}
	}()
	XOR([]byte("hello"), []byte{})
}

func TestRC4Encrypt(t *testing.T) {
	key := []byte("secret-key-for-rc4")
	data := []byte("data to encrypt")

	encrypted, err := RC4Encrypt(key, data)
	if err != nil {
		t.Fatalf("RC4Encrypt: %v", err)
	}
	if bytes.Equal(encrypted, data) {
		t.Error("encrypted should differ from plaintext")
	}

	decrypted, err := RC4Encrypt(key, encrypted)
	if err != nil {
		t.Fatalf("RC4Encrypt (decrypt): %v", err)
	}
	if !bytes.Equal(decrypted, data) {
		t.Errorf("decrypted = %q, want %q", decrypted, data)
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	b1 := GenerateRandomBytes(32)
	b2 := GenerateRandomBytes(32)

	if len(b1) != 32 {
		t.Errorf("length = %d, want 32", len(b1))
	}
	if bytes.Equal(b1, b2) {
		t.Error("random bytes should differ")
	}
}

func TestGenerateRandomBytes_ZeroLength(t *testing.T) {
	b := GenerateRandomBytes(0)
	if len(b) != 0 {
		t.Errorf("length = %d, want 0", len(b))
	}
}
