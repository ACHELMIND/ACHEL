package c2listener

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
)

type C2Encryption struct {
	mu       sync.RWMutex
	key      []byte
	iv       []byte
	cipher   cipher.Block
	gcm      cipher.AEAD
	alg      string
}

type EncryptionConfig struct {
	Key []byte
	Alg string
}

func NewC2Encryption(config EncryptionConfig) *C2Encryption {
	e := &C2Encryption{
		alg: config.Alg,
	}

	if config.Alg == "" {
		e.alg = "aes-gcm"
	}

	if len(config.Key) > 0 {
		e.SetKey(config.Key)
	}

	return e
}

func (e *C2Encryption) SetKey(key []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.key = key

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %v", err)
	}
	e.cipher = block

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %v", err)
	}
	e.gcm = gcm

	iv := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return fmt.Errorf("failed to generate IV: %v", err)
	}
	e.iv = iv

	return nil
}

func (e *C2Encryption) Encrypt(plaintext []byte) ([]byte, error) {
	e.mu.RLock()
	gcm := e.gcm
	e.mu.RUnlock()

	if gcm == nil {
		return nil, fmt.Errorf("encryption not initialized")
	}

	iv := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %v", err)
	}

	ciphertext := gcm.Seal(iv, iv, plaintext, nil)
	return ciphertext, nil
}

func (e *C2Encryption) Decrypt(ciphertext []byte) ([]byte, error) {
	e.mu.RLock()
	gcm := e.gcm
	e.mu.RUnlock()

	if gcm == nil {
		return nil, fmt.Errorf("encryption not initialized")
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	return plaintext, nil
}

func (e *C2Encryption) GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}
	return key, nil
}

func (e *C2Encryption) DeriveKey(password string, salt []byte) []byte {
	key := sha256.Sum256([]byte(password + hex.EncodeToString(salt)))
	return key[:]
}

func (e *C2Encryption) GetKey() []byte {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.key
}

func (e *C2Encryption) GetIV() []byte {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.iv
}

func (e *C2Encryption) GetAlg() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.alg
}

func (e *C2Encryption) IsInitialized() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.gcm != nil
}
