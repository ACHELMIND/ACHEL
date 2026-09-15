package resilience

import (
	"sync"
	"time"
)

type Recovery struct {
	mu            sync.RWMutex
	checkpoints   map[string]*Checkpoint
	running       bool
	checkInterval time.Duration
	stopCh        chan struct{}
}

type Checkpoint struct {
	ID        string
	Data      []byte
	Timestamp time.Time
	Metadata  map[string]string
}

func NewRecovery(checkInterval time.Duration) *Recovery {
	return &Recovery{
		checkpoints:   make(map[string]*Checkpoint),
		checkInterval: checkInterval,
		stopCh:        make(chan struct{}),
	}
}

func (r *Recovery) Start() {
	r.mu.Lock()
	r.running = true
	r.mu.Unlock()

	go r.monitorLoop()
}

func (r *Recovery) Stop() {
	r.mu.Lock()
	r.running = false
	r.mu.Unlock()
	close(r.stopCh)
}

func (r *Recovery) monitorLoop() {
	ticker := time.NewTicker(r.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.cleanup()
		}
	}
}

func (r *Recovery) cleanup() {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for id, cp := range r.checkpoints {
		if time.Since(cp.Timestamp) > 24*time.Hour {
			delete(r.checkpoints, id)
		}
	}
}

func (r *Recovery) SaveCheckpoint(id string, data []byte, metadata map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.checkpoints[id] = &Checkpoint{
		ID:        id,
		Data:      data,
		Timestamp: time.Now(),
		Metadata:  metadata,
	}
}

func (r *Recovery) LoadCheckpoint(id string) (*Checkpoint, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cp, exists := r.checkpoints[id]
	return cp, exists
}

func (r *Recovery) DeleteCheckpoint(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.checkpoints, id)
}

func (r *Recovery) GetCheckpoints() map[string]*Checkpoint {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cps := make(map[string]*Checkpoint)
	for id, cp := range r.checkpoints {
		cps[id] = cp
	}
	return cps
}

func (r *Recovery) GetCheckpointCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.checkpoints)
}

func (r *Recovery) IsRunning() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.running
}
