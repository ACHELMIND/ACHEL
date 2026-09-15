package c2listener

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type C2Channel struct {
	mu          sync.RWMutex
	id          string
	protocol    string
	addr        string
	port        int
	encrypted   bool
	compressor  bool
	key         []byte
	connected   bool
	lastIO      time.Time
	reconnects  int
	maxRetries  int
}

type ChannelConfig struct {
	Protocol   string
	Addr       string
	Port       int
	Encrypted  bool
	Compressor bool
	MaxRetries int
}

func NewC2Channel(config ChannelConfig) *C2Channel {
	if config.MaxRetries == 0 {
		config.MaxRetries = 5
	}
	return &C2Channel{
		id:         generateChannelID(),
		protocol:   config.Protocol,
		addr:       config.Addr,
		port:       config.Port,
		encrypted:  config.Encrypted,
		compressor: config.Compressor,
		maxRetries: config.MaxRetries,
	}
}

func (c *C2Channel) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.connected = true
	c.lastIO = time.Now()

	return nil
}

func (c *C2Channel) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = false
}

func (c *C2Channel) Send(data []byte) error {
	c.mu.RLock()
	connected := c.connected
	c.mu.RUnlock()

	if !connected {
		return fmt.Errorf("channel not connected")
	}

	c.mu.Lock()
	c.lastIO = time.Now()
	c.mu.Unlock()

	return nil
}

func (c *C2Channel) Receive() ([]byte, error) {
	c.mu.RLock()
	connected := c.connected
	c.mu.RUnlock()

	if !connected {
		return nil, fmt.Errorf("channel not connected")
	}

	c.mu.Lock()
	c.lastIO = time.Now()
	c.mu.Unlock()

	return []byte{}, nil
}

func (c *C2Channel) RotateKey() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := make([]byte, 32)
	rand.Read(key)
	c.key = key

	return nil
}

func (c *C2Channel) Reconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.reconnects++
	c.connected = true
	c.lastIO = time.Now()

	return nil
}

func (c *C2Channel) GetID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.id
}

func (c *C2Channel) GetProtocol() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.protocol
}

func (c *C2Channel) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

func (c *C2Channel) GetLastIO() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastIO
}

func (c *C2Channel) GetReconnects() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.reconnects
}

func (c *C2Channel) GetAddr() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return fmt.Sprintf("%s:%d", c.addr, c.port)
}

func generateChannelID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
