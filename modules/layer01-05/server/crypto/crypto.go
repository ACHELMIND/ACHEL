package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

type ServerCrypto struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	aesKey     []byte
}

func NewServerCrypto() (*ServerCrypto, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	return &ServerCrypto{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		aesKey:     generateAESKey(),
	}, nil
}

func generateAESKey() []byte {
	key := make([]byte, 32)
	rand.Read(key)
	return key
}

func (c *ServerCrypto) GetPublicKey() []byte {
	return elliptic.Marshal(c.publicKey.Curve, c.publicKey.X, c.publicKey.Y)
}

func (c *ServerCrypto) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (c *ServerCrypto) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (c *ServerCrypto) ECDHExchange(theirPublicKey []byte) ([]byte, error) {
	curve := elliptic.P256()
	x, y := elliptic.Unmarshal(curve, theirPublicKey)
	if x == nil {
		return nil, fmt.Errorf("invalid public key")
	}

	sharedX, _ := curve.ScalarMult(x, y, c.privateKey.D.Bytes())
	return sharedX.Bytes(), nil
}

func (c *ServerCrypto) Sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, c.privateKey, hash[:])
}

func (c *ServerCrypto) Verify(data, signature []byte) bool {
	hash := sha256.Sum256(data)
	return ecdsa.VerifyASN1(c.publicKey, hash[:], signature)
}

func (c *ServerCrypto) ExportPrivateKey() ([]byte, error) {
	return x509.MarshalECPrivateKey(c.privateKey)
}

func (c *ServerCrypto) ExportPublicKey() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(c.publicKey)
}

func (c *ServerCrypto) ImportPrivateKey(data []byte) error {
	key, err := x509.ParseECPrivateKey(data)
	if err != nil {
		return err
	}
	c.privateKey = key
	c.publicKey = &key.PublicKey
	return nil
}

func (c *ServerCrypto) ExportPrivateKeyPEM() ([]byte, error) {
	data, err := c.ExportPrivateKey()
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: data,
	}), nil
}

func (c *ServerCrypto) ExportPublicKeyPEM() ([]byte, error) {
	data, err := c.ExportPublicKey()
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: data,
	}), nil
}

func (c *ServerCrypto) HMAC(data []byte) []byte {
	mac := make([]byte, 32)
	h := sha256.New()
	h.Write(data)
	h.Write(c.aesKey)
	copy(mac, h.Sum(nil))
	return mac
}
