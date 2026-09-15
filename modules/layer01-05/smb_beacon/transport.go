package smb_beacon

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type SMBTransport struct {
	mu          sync.RWMutex
	id          string
	namePipe    string
	connected   bool
	encrypted   bool
	compressed  bool
	key         []byte
	peers       map[string]*TransportPeer
	lastIO      time.Time
}

type TransportPeer struct {
	ID        string
	Addr      string
	Port      int
	Connected bool
	LastSeen  time.Time
}

type SMBTransportConfig struct {
	NamePipe   string
	Encrypted  bool
	Compressed bool
}

func NewSMBTransport(config SMBTransportConfig) *SMBTransport {
	if config.NamePipe == "" {
		config.NamePipe = "\\\\.\\pipe\\msagent"
	}

	return &SMBTransport{
		id:         generateTransportID(),
		namePipe:   config.NamePipe,
		encrypted:  config.Encrypted,
		compressed: config.Compressed,
		peers:      make(map[string]*TransportPeer),
	}
}

func (t *SMBTransport) Connect(target string, port int) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	peerID := generateTransportID()
	peer := &TransportPeer{
		ID:        peerID,
		Addr:      target,
		Port:      port,
		Connected: true,
		LastSeen:  time.Now(),
	}

	t.peers[peerID] = peer
	t.connected = true
	t.lastIO = time.Now()

	return nil
}

func (t *SMBTransport) Disconnect() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.connected = false

	for id, peer := range t.peers {
		peer.Connected = false
		delete(t.peers, id)
	}
}

func (t *SMBTransport) Send(data []byte) error {
	t.mu.RLock()
	connected := t.connected
	t.mu.RUnlock()

	if !connected {
		return fmt.Errorf("transport not connected")
	}

	t.mu.Lock()
	t.lastIO = time.Now()
	t.mu.Unlock()

	return nil
}

func (t *SMBTransport) Receive() ([]byte, error) {
	t.mu.RLock()
	connected := t.connected
	t.mu.RUnlock()

	if !connected {
		return nil, fmt.Errorf("transport not connected")
	}

	t.mu.Lock()
	t.lastIO = time.Now()
	t.mu.Unlock()

	return []byte{}, nil
}

func (t *SMBTransport) RotateKey() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := make([]byte, 32)
	rand.Read(key)
	t.key = key

	return nil
}

func (t *SMBTransport) GetID() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.id
}

func (t *SMBTransport) GetNamePipe() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.namePipe
}

func (t *SMBTransport) IsConnected() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.connected
}

func (t *SMBTransport) GetLastIO() time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.lastIO
}

func (t *SMBTransport) GetPeers() []*TransportPeer {
	t.mu.RLock()
	defer t.mu.RUnlock()

	peers := make([]*TransportPeer, 0, len(t.peers))
	for _, peer := range t.peers {
		peers = append(peers, peer)
	}
	return peers
}

func (t *SMBTransport) GetPeerCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.peers)
}

func (t *SMBTransport) IsEncrypted() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.encrypted
}

func (t *SMBTransport) IsCompressed() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.compressed
}

func (t *SMBTransport) SetEncryption(enabled bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.encrypted = enabled
}

func (t *SMBTransport) SetCompression(enabled bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.compressed = enabled
}

func generateTransportID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
