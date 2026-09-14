package collector

import (
	"sync"
	"time"
)

type ClipboardMonitor struct {
	mu      sync.RWMutex
	content string
	running bool
	stopCh  chan struct{}
}

func NewClipboardMonitor() *ClipboardMonitor {
	return &ClipboardMonitor{
		stopCh: make(chan struct{}),
	}
}

func (c *ClipboardMonitor) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return nil
	}

	c.running = true
	c.stopCh = make(chan struct{})

	go c.monitorLoop()
	return nil
}

func (c *ClipboardMonitor) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	c.running = false
	close(c.stopCh)
	return nil
}

func (c *ClipboardMonitor) GetContent() (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.content, nil
}

func (c *ClipboardMonitor) monitorLoop() {
	for {
		select {
		case <-c.stopCh:
			return
		default:
			c.mu.Lock()
			c.content = "clipboard_content_" + time.Now().Format("150405")
			c.mu.Unlock()
			time.Sleep(500 * time.Millisecond)
		}
	}
}
