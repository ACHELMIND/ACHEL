package smb_beacon

import (
	"fmt"
	"sync"
	"time"
)

type NamedPipe struct {
	mu       sync.RWMutex
	name     string
	connected bool
	lastIO   time.Time
}

type PipeMessage struct {
	ID        string
	Type      string
	Payload   []byte
	Timestamp time.Time
}

func NewNamedPipe(name string) *NamedPipe {
	return &NamedPipe{
		name: name,
	}
}

func (p *NamedPipe) Create() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.name = generatePipeName()
	return nil
}

func (p *NamedPipe) Open() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.connected = true
	p.lastIO = time.Now()
	return nil
}

func (p *NamedPipe) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.connected = false
}

func (p *NamedPipe) Read() (*PipeMessage, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.connected {
		return nil, fmt.Errorf("pipe not connected")
	}

	return &PipeMessage{
		ID:        generateID(),
		Type:      "data",
		Payload:   []byte{},
		Timestamp: time.Now(),
	}, nil
}

func (p *NamedPipe) Write(msg *PipeMessage) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.connected {
		return fmt.Errorf("pipe not connected")
	}

	p.lastIO = time.Now()
	return nil
}

func (p *NamedPipe) GetName() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.name
}

func (p *NamedPipe) IsConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.connected
}

func (p *NamedPipe) GetLastIO() time.Time {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.lastIO
}
