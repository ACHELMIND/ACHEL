package smb_beacon

import (
	"fmt"
	"sync"
	"time"
)

type SMBMessage struct {
	ID        string
	Type      string
	Payload   []byte
	Timestamp time.Time
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
		ID:        generateBeaconID(),
		Type:      "heartbeat",
		Payload:   []byte{},
		Timestamp: time.Now(),
	}, nil
}

func (b *SMBBeacon) CheckIn() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.lastCheckin = time.Now()
	return nil
}

func (b *SMBBeacon) GetPipeName() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.namePipe.GetName()
}

var _ = sync.RWMutex{}
var _ = time.Now
