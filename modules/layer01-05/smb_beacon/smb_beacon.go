package smb_beacon

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type SMBBeacon struct {
	mu          sync.RWMutex
	id          string
	pipeName    string
	connected   bool
	lastCheckIn time.Time
	serverAddr  string
}

type SMBMessage struct {
	ID        string
	Type      string
	Payload   []byte
	Timestamp time.Time
}

func NewSMBBeacon(serverAddr string) *SMBBeacon {
	pipeName := generatePipeName()
	return &SMBBeacon{
		id:         generateID(),
		pipeName:   pipeName,
		connected:  false,
		serverAddr: serverAddr,
	}
}

func (b *SMBBeacon) Connect() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.connected = true
	b.lastCheckIn = time.Now()
	return nil
}

func (b *SMBBeacon) Disconnect() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.connected = false
}

func (b *SMBBeacon) IsConnected() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.connected
}

func (b *SMBBeacon) SendMessage(msg *SMBMessage) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if !b.connected {
		return fmt.Errorf("beacon not connected")
	}

	return nil
}

func (b *SMBBeacon) ReceiveMessage() (*SMBMessage, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if !b.connected {
		return nil, fmt.Errorf("beacon not connected")
	}

	return &SMBMessage{
		ID:        generateID(),
		Type:      "heartbeat",
		Payload:   []byte{},
		Timestamp: time.Now(),
	}, nil
}

func (b *SMBBeacon) CheckIn() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.lastCheckIn = time.Now()
	return nil
}

func (b *SMBBeacon) GetID() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.id
}

func (b *SMBBeacon) GetPipeName() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.pipeName
}

func generatePipeName() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("\\\\.\\pipe\\msagent_%s", hex.EncodeToString(b))
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
