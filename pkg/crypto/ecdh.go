package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

type ECDHKeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  []byte
}

func GenerateECDHKeyPair() (*ECDHKeyPair, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	pubBytes := elliptic.MarshalCompressed(privKey.PublicKey.Curve, privKey.PublicKey.X, privKey.PublicKey.Y)

	return &ECDHKeyPair{
		PrivateKey: privKey,
		PublicKey:  pubBytes,
	}, nil
}

func ComputeSharedSecret(privKey *ecdsa.PrivateKey, peerPubKey []byte) ([]byte, error) {
	x, y := elliptic.UnmarshalCompressed(privKey.PublicKey.Curve, peerPubKey)
	if x == nil {
		return nil, fmt.Errorf("invalid public key")
	}

	xBytes := x.Bytes()
	yBytes := y.Bytes()

	shared := sha256.Sum256(append(xBytes, yBytes...))
	return shared[:], nil
}

func SignMessage(privKey *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	return ecdsa.SignASN1(rand.Reader, privKey, hash[:])
}

func VerifyMessage(pubKey *ecdsa.PublicKey, message, signature []byte) bool {
	hash := sha256.Sum256(message)
	return ecdsa.VerifyASN1(pubKey, hash[:], signature)
}
