package c2server

import (
	"crypto/ecdsa"
	"crypto/rand"

	"github.com/angel-platform/angel/pkg/crypto"
)

type ServerCrypto struct {
	keyPair *crypto.ECDHKeyPair
	encKey  []byte
}

func NewServerCrypto() (*ServerCrypto, error) {
	keyPair, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		return nil, err
	}
	encKey := crypto.GenerateAESKey()
	return &ServerCrypto{
		keyPair: keyPair,
		encKey: encKey,
	}, nil
}

func NewServerCryptoFromKey(privKey *ecdsa.PrivateKey) *ServerCrypto {
	pubBytes := make([]byte, 0)
	pubBytes = append(pubBytes, privKey.PublicKey.X.Bytes()...)
	pubBytes = append(pubBytes, privKey.PublicKey.Y.Bytes()...)
	encKey := crypto.GenerateAESKey()
	return &ServerCrypto{
		keyPair: &crypto.ECDHKeyPair{
			PrivateKey: privKey,
			PublicKey:  pubBytes,
		},
		encKey: encKey,
	}
}

func (s *ServerCrypto) DecryptPayload(data []byte) ([]byte, error) {
	return crypto.DecryptAESGCM(s.encKey, data)
}

func (s *ServerCrypto) EncryptPayload(data []byte) ([]byte, error) {
	return crypto.EncryptAESGCM(s.encKey, data)
}

func (s *ServerCrypto) SignData(data []byte) ([]byte, error) {
	return crypto.SignMessage(s.keyPair.PrivateKey, data)
}

func (s *ServerCrypto) VerifySignature(data, sig []byte) bool {
	return crypto.VerifyMessage(&s.keyPair.PrivateKey.PublicKey, data, sig)
}

func (s *ServerCrypto) PublicKey() []byte {
	return s.keyPair.PublicKey
}

func (s *ServerCrypto) SharedSecret(peerPubKey []byte) ([]byte, error) {
	return crypto.ComputeSharedSecret(s.keyPair.PrivateKey, peerPubKey)
}

func (s *ServerCrypto) EncryptKey() []byte {
	key := make([]byte, len(s.encKey))
	copy(key, s.encKey)
	return key
}

func (s *ServerCrypto) GenerateNonce() []byte {
	nonce := make([]byte, 12)
	rand.Read(nonce)
	return nonce
}
