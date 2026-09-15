package c2listener

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type C2Comms struct {
	mu          sync.RWMutex
	channels    map[string]*C2Channel
	currentCh   string
	encryption  bool
	compression bool
}

type Message struct {
	ID        string
	Type      string
	Payload   []byte
	Source    string
	Dest      string
	Timestamp time.Time
	Encrypted bool
}

type CommsConfig struct {
	Encryption  bool
	Compression bool
}

func NewC2Comms(config CommsConfig) *C2Comms {
	return &C2Comms{
		channels:    make(map[string]*C2Channel),
		encryption:  config.Encryption,
		compression: config.Compression,
	}
}

func (c *C2Comms) AddChannel(channel *C2Channel) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.channels[channel.GetID()] = channel

	if c.currentCh == "" {
		c.currentCh = channel.GetID()
	}
}

func (c *C2Comms) RemoveChannel(channelID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.channels, channelID)

	if c.currentCh == channelID {
		c.currentCh = ""
		for id := range c.channels {
			c.currentCh = id
			break
		}
	}
}

func (c *C2Comms) SendMessage(msg *Message) error {
	c.mu.RLock()
	currentCh := c.currentCh
	c.mu.RUnlock()

	if currentCh == "" {
		return fmt.Errorf("no active channel")
	}

	c.mu.RLock()
	channel, exists := c.channels[currentCh]
	c.mu.RUnlock()

	if !exists {
		return fmt.Errorf("channel not found: %s", currentCh)
	}

	if !channel.IsConnected() {
		return fmt.Errorf("channel not connected")
	}

	return channel.Send(msg.Payload)
}

func (c *C2Comms) ReceiveMessage() (*Message, error) {
	c.mu.RLock()
	currentCh := c.currentCh
	c.mu.RUnlock()

	if currentCh == "" {
		return nil, fmt.Errorf("no active channel")
	}

	c.mu.RLock()
	channel, exists := c.channels[currentCh]
	c.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("channel not found")
	}

	data, err := channel.Receive()
	if err != nil {
		return nil, err
	}

	return &Message{
		ID:        generateMsgID(),
		Payload:   data,
		Timestamp: time.Now(),
	}, nil
}

func (c *C2Comms) RotateChannel() *C2Channel {
	c.mu.Lock()
	defer c.mu.Unlock()

	var nextID string
	found := false
	for id := range c.channels {
		if id == c.currentCh {
			found = true
			continue
		}
		if found {
			nextID = id
			break
		}
	}

	if nextID == "" {
		for id := range c.channels {
			nextID = id
			break
		}
	}

	if nextID != "" {
		c.currentCh = nextID
		return c.channels[nextID]
	}

	return nil
}

func (c *C2Comms) GetChannel(channelID string) *C2Channel {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.channels[channelID]
}

func (c *C2Comms) GetCurrentChannel() *C2Channel {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.channels[c.currentCh]
}

func (c *C2Comms) GetChannels() []*C2Channel {
	c.mu.RLock()
	defer c.mu.RUnlock()

	channels := make([]*C2Channel, 0, len(c.channels))
	for _, ch := range c.channels {
		channels = append(channels, ch)
	}
	return channels
}

func (c *C2Comms) GetChannelCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.channels)
}

func (c *C2Comms) IsEncrypted() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.encryption
}

func (c *C2Comms) IsCompressed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.compression
}

func (c *C2Comms) SetEncryption(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.encryption = enabled
}

func (c *C2Comms) SetCompression(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.compression = enabled
}

func generateMsgID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
