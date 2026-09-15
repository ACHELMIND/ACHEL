package crypto

import "testing"

func TestPaddingOracle(t *testing.T) {
	config := CryptoConfig{
		TargetURL:  "http://target/api/decrypt",
		Cipher:     "AES-CBC",
		BlockSize:  16,
		Ciphertext: make([]byte, 32),
	}
	for i := range config.Ciphertext {
		config.Ciphertext[i] = byte(i + 0x41)
	}
	engine := NewEngine(config)
	result := engine.PaddingOracle()
	if result.Attack != CryptoAttackPaddingOracle {
		t.Errorf("expected PaddingOracle, got %d", result.Attack)
	}
	if result.BlockSize != 16 {
		t.Errorf("expected block size 16, got %d", result.BlockSize)
	}
}

func TestWeakKeyDetect(t *testing.T) {
	config := CryptoConfig{
		KeySize: 8,
	}
	engine := NewEngine(config)
	result := engine.WeakKeyDetect()
	if result.Attack != CryptoAttackWeakKey {
		t.Errorf("expected WeakKey, got %d", result.Attack)
	}
}

func TestHashLengthExt(t *testing.T) {
	config := CryptoConfig{
		Plaintext: []byte("secret_data"),
		IV:         make([]byte, 32),
		BlockSize:  64,
	}
	engine := NewEngine(config)
	result := engine.HashLengthExt()
	if result.Attack != CryptoAttackHashLengthExt {
		t.Errorf("expected HashLengthExt, got %d", result.Attack)
	}
	if !result.Vulnerable {
		t.Error("expected vulnerable result")
	}
}

func TestECBLeak(t *testing.T) {
	config := CryptoConfig{
		Plaintext: []byte("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC"),
		BlockSize: 16,
	}
	engine := NewEngine(config)
	result := engine.ECBLeak()
	if result.Attack != CryptoAttackECBLeak {
		t.Errorf("expected ECBLeak, got %d", result.Attack)
	}
}
