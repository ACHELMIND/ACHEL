package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateECDHKeyPair(t *testing.T) {
	kp, err := GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair: %v", err)
	}
	if kp.PrivateKey == nil {
		t.Error("PrivateKey should not be nil")
	}
	if len(kp.PublicKey) == 0 {
		t.Error("PublicKey should not be empty")
	}
}

func TestComputeSharedSecret(t *testing.T) {
	kp1, _ := GenerateECDHKeyPair()
	kp2, _ := GenerateECDHKeyPair()

	shared1, err := ComputeSharedSecret(kp1.PrivateKey, kp2.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSharedSecret 1: %v", err)
	}
	shared2, err := ComputeSharedSecret(kp2.PrivateKey, kp1.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSharedSecret 2: %v", err)
	}

	if !bytes.Equal(shared1, shared2) {
		t.Error("shared secrets should match")
	}
	if len(shared1) != 32 {
		t.Errorf("shared secret length = %d, want 32", len(shared1))
	}
}

func TestComputeSharedSecret_InvalidKey(t *testing.T) {
	kp, _ := GenerateECDHKeyPair()
	_, err := ComputeSharedSecret(kp.PrivateKey, []byte("invalid-key-data"))
	if err == nil {
		t.Error("expected error for invalid public key")
	}
}

func TestSignAndVerifyMessage(t *testing.T) {
	kp, _ := GenerateECDHKeyPair()
	message := []byte("test message to sign")

	sig, err := SignMessage(kp.PrivateKey, message)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	if len(sig) == 0 {
		t.Error("signature should not be empty")
	}

	if !VerifyMessage(&kp.PrivateKey.PublicKey, message, sig) {
		t.Error("valid signature should verify")
	}
}

func TestVerifyMessage_WrongMessage(t *testing.T) {
	kp, _ := GenerateECDHKeyPair()
	message := []byte("test message")

	sig, _ := SignMessage(kp.PrivateKey, message)

	if VerifyMessage(&kp.PrivateKey.PublicKey, []byte("different message"), sig) {
		t.Error("wrong message should not verify")
	}
}

func TestVerifyMessage_WrongKey(t *testing.T) {
	kp1, _ := GenerateECDHKeyPair()
	kp2, _ := GenerateECDHKeyPair()
	message := []byte("test message")

	sig, _ := SignMessage(kp1.PrivateKey, message)

	if VerifyMessage(&kp2.PrivateKey.PublicKey, message, sig) {
		t.Error("wrong key should not verify")
	}
}
