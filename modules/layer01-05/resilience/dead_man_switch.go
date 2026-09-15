package resilience

import (
	"log"
	"sync"
	"time"
)

type DeadManSwitch struct {
	mu              sync.RWMutex
	timeout         time.Duration
	lastHeartbeat   time.Time
	running         bool
	stopCh          chan struct{}
	triggerFunc     func()
}

func NewDeadManSwitch(timeout time.Duration, triggerFunc func()) *DeadManSwitch {
	return &DeadManSwitch{
		timeout:     timeout,
		lastHeartbeat: time.Now(),
		stopCh:      make(chan struct{}),
		triggerFunc: triggerFunc,
	}
}

func (d *DeadManSwitch) Start() {
	d.mu.Lock()
	d.running = true
	d.mu.Unlock()

	go d.monitorLoop()
}

func (d *DeadManSwitch) Stop() {
	d.mu.Lock()
	d.running = false
	d.mu.Unlock()
	close(d.stopCh)
}

func (d *DeadManSwitch) monitorLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.check()
		}
	}
}

func (d *DeadManSwitch) check() {
	d.mu.RLock()
	lastBeat := d.lastHeartbeat
	timeout := d.timeout
	d.mu.RUnlock()

	if time.Since(lastBeat) > timeout {
		log.Println("Dead man switch triggered!")
		if d.triggerFunc != nil {
			d.triggerFunc()
		}
	}
}

func (d *DeadManSwitch) UpdateHeartbeat() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lastHeartbeat = time.Now()
}

func (d *DeadManSwitch) IsAlive() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return time.Since(d.lastHeartbeat) < d.timeout
}

func (d *DeadManSwitch) GetTimeSinceHeartbeat() time.Duration {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return time.Since(d.lastHeartbeat)
}

func (d *DeadManSwitch) GetTimeout() time.Duration {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.timeout
}
