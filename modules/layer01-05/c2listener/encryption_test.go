package c2listener

import (
	"bytes"
	"testing"
)

func TestNewC2Encryption(t *testing.T) {
	enc := NewC2Encryption(EncryptionConfig{
		Alg: "aes",
	})
	if enc == nil {
		t.Fatal("expected non-nil C2Encryption")
	}
	if enc.GetAlg() != "aes" {
		t.Errorf("expected alg aes, got %s", enc.GetAlg())
	}
}

func TestNewC2Encryption_DefaultAlg(t *testing.T) {
	enc := NewC2Encryption(EncryptionConfig{})
	if enc.GetAlg() != "aes-gcm" {
		t.Errorf("expected default alg aes-gcm, got %s", enc.GetAlg())
	}
}

func TestC2Encryption_SetKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	enc := NewC2Encryption(EncryptionConfig{})
	err := enc.SetKey(key)
	if err != nil {
		t.Fatalf("SetKey failed: %v", err)
	}
	if !enc.IsInitialized() {
		t.Error("expected initialized after SetKey")
	}
}

func TestC2Encryption_SetKeyInvalid(t *testing.T) {
	enc := NewC2Encryption(EncryptionConfig{})
	err := enc.SetKey([]byte{0x01})
	if err == nil {
		t.Error("expected error setting invalid key")
	}
}

func TestC2Encryption_EncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	enc := NewC2Encryption(EncryptionConfig{})
	if err := enc.SetKey(key); err != nil {
		t.Fatalf("SetKey failed: %v", err)
	}

	plaintext := []byte("hello world test data")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted does not match plaintext: got %s", decrypted)
	}
}

func TestC2Encryption_EncryptNotInitialized(t *testing.T) {
	enc := NewC2Encryption(EncryptionConfig{})
	_, err := enc.Encrypt([]byte("test"))
	if err == nil {
		t.Error("expected error encrypting without key")
	}
}

func TestC2Encryption_DecryptNotInitialized(t *testing.T) {
	enc := NewC2Encryption(EncryptionConfig{})
	_, err := enc.Decrypt([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c})
	if err == nil {
		t.Error("expected error decrypting without key")
	}
}

func TestC2Encryption_DecryptTooShort(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	enc := NewC2Encryption(EncryptionConfig{})
	if err := enc.SetKey(key); err != nil {
		t.Fatalf("SetKey failed: %v", err)
	}
	_, err := enc.Decrypt([]byte{0x01})
	if err == nil {
		t.Error("expected error decrypting short ciphertext")
	}
}

func TestC2Encryption_EncryptEmpty(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	enc := NewC2Encryption(EncryptionConfig{})
	if err := enc.SetKey(key); err != nil {
		t.Fatalf("SetKey failed: %v", err)
	}

	ciphertext, err := enc.Encrypt([]byte{})
	if err != nil {
		t.Fatalf("Encrypt empty failed: %v", err)
	}
	if len(ciphertext) == 0 {
		t.Error("expected non-empty ciphertext for empty plaintext")
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt empty failed: %v", err)
	}
	if len(decrypted) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(decrypted))
	}
}

func TestC2Encryption_GenerateKey(t *testing.T) {
	enc := NewC2Encryption(EncryptionConfig{})
	key, err := enc.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(key))
	}
}

func TestC2Encryption_DeriveKey(t *testing.T) {
	enc := NewC2Encryption(EncryptionConfig{})
	salt := []byte("testsalt12345678")
	key1 := enc.DeriveKey("password1", salt)
	key2 := enc.DeriveKey("password1", salt)
	if !bytes.Equal(key1, key2) {
		t.Error("same password+salt should produce same key")
	}
	key3 := enc.DeriveKey("password2", salt)
	if bytes.Equal(key1, key3) {
		t.Error("different passwords should produce different keys")
	}
	if len(key1) != 32 {
		t.Errorf("expected 32-byte derived key, got %d", len(key1))
	}
}

func TestC2Encryption_GetKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	enc := NewC2Encryption(EncryptionConfig{})
	if enc.GetKey() != nil {
		t.Error("expected nil key before SetKey")
	}
	_ = enc.SetKey(key)
	if enc.GetKey() == nil {
		t.Error("expected non-nil key after SetKey")
	}
}

func TestC2Encryption_GetIV(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	enc := NewC2Encryption(EncryptionConfig{})
	if enc.GetIV() != nil {
		t.Error("expected nil IV before SetKey")
	}
	_ = enc.SetKey(key)
	if enc.GetIV() == nil {
		t.Error("expected non-nil IV after SetKey")
	}
}

func TestC2Encryption_EncryptDecryptMultiple(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	enc := NewC2Encryption(EncryptionConfig{})
	_ = enc.SetKey(key)

	for i := 0; i < 10; i++ {
		plaintext := []byte("message " + string(rune('0'+i)))
		ct, err := enc.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt iteration %d failed: %v", i, err)
		}
		pt, err := enc.Decrypt(ct)
		if err != nil {
			t.Fatalf("Decrypt iteration %d failed: %v", i, err)
		}
		if !bytes.Equal(pt, plaintext) {
			t.Errorf("iteration %d: decrypted mismatch", i)
		}
	}
}
