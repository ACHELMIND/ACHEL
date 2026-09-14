package collector

import (
	"sync"
	"time"
)

type Keylogger struct {
	mu      sync.RWMutex
	entries []KeylogEntry
	running bool
	stopCh  chan struct{}
}

func NewKeylogger() *Keylogger {
	return &Keylogger{
		entries: make([]KeylogEntry, 0),
		stopCh:  make(chan struct{}),
	}
}

func (k *Keylogger) Start() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.running {
		return nil
	}

	k.running = true
	k.stopCh = make(chan struct{})

	go k.captureLoop()
	return nil
}

func (k *Keylogger) Stop() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if !k.running {
		return nil
	}

	k.running = false
	close(k.stopCh)
	return nil
}

func (k *Keylogger) GetLog() string {
	k.mu.RLock()
	defer k.mu.RUnlock()

	result := ""
	for _, entry := range k.entries {
		result += entry.Key
	}
	return result
}

func (k *Keylogger) GetEntries() []KeylogEntry {
	k.mu.RLock()
	defer k.mu.RUnlock()

	entries := make([]KeylogEntry, len(k.entries))
	copy(entries, k.entries)
	return entries
}

func (k *Keylogger) captureLoop() {
	for {
		select {
		case <-k.stopCh:
			return
		default:
			k.mu.Lock()
			k.entries = append(k.entries, KeylogEntry{
				Process:  "unknown",
				Key:      "captured_key",
				Timestamp: time.Now(),
			})
			k.mu.Unlock()
			time.Sleep(100 * time.Millisecond)
		}
	}
}
