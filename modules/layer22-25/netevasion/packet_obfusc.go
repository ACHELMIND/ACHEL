package netevasion

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"sync"
)

type PacketObfuscator struct {
	mu       sync.RWMutex
	key      []byte
	encoding string
}

func NewPacketObfuscator(key []byte) *PacketObfuscator {
	if len(key) == 0 {
		key = make([]byte, 32)
		rand.Read(key)
	}
	return &PacketObfuscator{
		key:      key,
		encoding: "base64",
	}
}

func (po *PacketObfuscator) Encrypt(data []byte) ([]byte, error) {
	po.mu.Lock()
	defer po.mu.Unlock()

	block, err := aes.NewCipher(po.key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func (po *PacketObfuscator) Decrypt(data []byte) ([]byte, error) {
	po.mu.Lock()
	defer po.mu.Unlock()

	block, err := aes.NewCipher(po.key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

func (po *PacketObfuscator) EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func (po *PacketObfuscator) DecodeBase64(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

func (po *PacketObfuscator) ObfuscatePayload(data []byte) ([]byte, error) {
	encrypted, err := po.Encrypt(data)
	if err != nil {
		return nil, err
	}
	encoded := []byte(po.EncodeBase64(encrypted))
	return encoded, nil
}

func (po *PacketObfuscator) DeobfuscatePayload(data []byte) ([]byte, error) {
	decoded, err := po.DecodeBase64(string(data))
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	return po.Decrypt(decoded)
}
