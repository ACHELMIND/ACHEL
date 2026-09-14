package c2implant

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sync"

	angelcrypto "github.com/angel-platform/angel/pkg/crypto"
)

type ImplantCrypto struct {
	mu          sync.RWMutex
	sessionKey  []byte
	localKey    *ecdsa.PrivateKey
	serverPub   []byte
	established bool
}

func NewImplantCrypto(serverPubKey []byte) (*ImplantCrypto, error) {
	if len(serverPubKey) == 0 {
		return nil, fmt.Errorf("server public key is required")
	}

	localKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate local key: %w", err)
	}

	return &ImplantCrypto{
		localKey:  localKey,
		serverPub: serverPubKey,
	}, nil
}

func (ic *ImplantCrypto) KeyExchange(localPrivKey *ecdsa.PrivateKey, serverPubKey []byte) ([]byte, error) {
	if localPrivKey == nil {
		return nil, fmt.Errorf("local private key is required")
	}

	x, y := elliptic.UnmarshalCompressed(localPrivKey.PublicKey.Curve, serverPubKey)
	if x == nil {
		return nil, fmt.Errorf("invalid server public key")
	}

	sharedX, sharedY := elliptic.P256().ScalarMult(x, y, localPrivKey.D.Bytes())

	sharedBytes := append(sharedX.Bytes(), sharedY.Bytes()...)
	hash := sha256.Sum256(sharedBytes)

	ic.mu.Lock()
	ic.sessionKey = hash[:]
	ic.established = true
	ic.mu.Unlock()

	return hash[:], nil
}

func (ic *ImplantCrypto) EstablishSession() error {
	ic.mu.Lock()
	defer ic.mu.Unlock()

	x, y := elliptic.UnmarshalCompressed(ic.localKey.PublicKey.Curve, ic.serverPub)
	if x == nil {
		return fmt.Errorf("invalid server public key")
	}

	sharedX, sharedY := elliptic.P256().ScalarMult(x, y, ic.localKey.D.Bytes())
	sharedBytes := append(sharedX.Bytes(), sharedY.Bytes()...)
	hash := sha256.Sum256(sharedBytes)

	ic.sessionKey = hash[:]
	ic.established = true
	return nil
}

func (ic *ImplantCrypto) Encrypt(data []byte) ([]byte, error) {
	ic.mu.RLock()
	key := ic.sessionKey
	established := ic.established
	ic.mu.RUnlock()

	if !established || len(key) == 0 {
		return nil, fmt.Errorf("session not established")
	}

	return angelcrypto.EncryptAESGCM(key, data)
}

func (ic *ImplantCrypto) Decrypt(data []byte) ([]byte, error) {
	ic.mu.RLock()
	key := ic.sessionKey
	established := ic.established
	ic.mu.RUnlock()

	if !established || len(key) == 0 {
		return nil, fmt.Errorf("session not established")
	}

	return angelcrypto.DecryptAESGCM(key, data)
}

func (ic *ImplantCrypto) GetLocalPublicKey() []byte {
	return angelcrypto.GenerateRandomBytes(0)
}

func (ic *ImplantCrypto) GetLocalPublicKeyRaw() []byte {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	if ic.localKey == nil {
		return nil
	}
	return elliptic.MarshalCompressed(
		ic.localKey.PublicKey.Curve,
		ic.localKey.PublicKey.X,
		ic.localKey.PublicKey.Y,
	)
}

func (ic *ImplantCrypto) IsEstablished() bool {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return ic.established
}

func (ic *ImplantCrypto) Sign(data []byte) ([]byte, error) {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	if ic.localKey == nil {
		return nil, fmt.Errorf("no local key")
	}
	return angelcrypto.SignMessage(ic.localKey, data)
}

func (ic *ImplantCrypto) HMAC(data []byte) []byte {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	return angelcrypto.HMACSHA256(ic.sessionKey, data)
}
