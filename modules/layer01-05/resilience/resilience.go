package resilience

import (
	"log"
	"sync"
	"time"
)

type ResilienceManager struct {
	mu              sync.RWMutex
	heartbeatTimeout time.Duration
	lastHeartbeat   time.Time
	running         bool
	stopCh          chan struct{}
}

func NewResilienceManager(heartbeatTimeout time.Duration) *ResilienceManager {
	return &ResilienceManager{
		heartbeatTimeout: heartbeatTimeout,
		lastHeartbeat:    time.Now(),
		stopCh:           make(chan struct{}),
	}
}

func (r *ResilienceManager) Start() {
	r.mu.Lock()
	r.running = true
	r.mu.Unlock()

	go r.monitorLoop()
}

func (r *ResilienceManager) Stop() {
	r.mu.Lock()
	r.running = false
	r.mu.Unlock()
	close(r.stopCh)
}

func (r *ResilienceManager) monitorLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.checkHeartbeat()
		}
	}
}

func (r *ResilienceManager) checkHeartbeat() {
	r.mu.RLock()
	lastBeat := r.lastHeartbeat
	timeout := r.heartbeatTimeout
	r.mu.RUnlock()

	if time.Since(lastBeat) > timeout {
		log.Println("Heartbeat timeout - initiating cleanup")
		r.triggerCleanup()
	}
}

func (r *ResilienceManager) triggerCleanup() {
	log.Println("Cleaning up artifacts...")
}

func (r *ResilienceManager) UpdateHeartbeat() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastHeartbeat = time.Now()
}

func (r *ResilienceManager) IsAlive() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return time.Since(r.lastHeartbeat) < r.heartbeatTimeout
}

func (r *ResilienceManager) SelfDestruct() {
	log.Println("Self-destruct initiated")
	r.Stop()
}
