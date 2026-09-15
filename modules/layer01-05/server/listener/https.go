package listener

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

type HTTPSListener struct {
	mu        sync.RWMutex
	addr      string
	port      int
	certFile  string
	keyFile   string
	running   bool
	agents    map[string]*Agent
	tasks     map[string]*Task
	results   []*Result
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

type Result struct {
	TaskID    string
	AgentID   string
	Success   bool
	Output    string
	Error     string
	Timestamp time.Time
}

func NewHTTPSListener(addr string, port int, certFile, keyFile string) *HTTPSListener {
	return &HTTPSListener{
		addr:     addr,
		port:     port,
		certFile: certFile,
		keyFile:  keyFile,
		agents:   make(map[string]*Agent),
		tasks:    make(map[string]*Task),
	}
}

func (l *HTTPSListener) Start() error {
	l.mu.Lock()
	l.running = true
	l.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/register", l.handleRegister)
	mux.HandleFunc("/api/v1/task", l.handleTask)
	mux.HandleFunc("/api/v1/result", l.handleResult)
	mux.HandleFunc("/api/v1/heartbeat", l.handleHeartbeat)

	cert, err := tls.LoadX509KeyPair(l.certFile, l.keyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	addr := fmt.Sprintf("%s:%d", l.addr, l.port)
	server := &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Printf("Starting HTTPS listener on %s", addr)
	return server.ListenAndServeTLS("", "")
}

func (l *HTTPSListener) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.running = false
}

func (l *HTTPSListener) handleRegister(w http.ResponseWriter, r *http.Request) {
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

func (l *HTTPSListener) handleTask(w http.ResponseWriter, r *http.Request) {
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

func (l *HTTPSListener) handleResult(w http.ResponseWriter, r *http.Request) {
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

func (l *HTTPSListener) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
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

func (l *HTTPSListener) getPendingTask(agentID string) *Task {
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

func (l *HTTPSListener) AddTask(task *Task) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tasks[task.ID] = task
}

func (l *HTTPSListener) GetAgents() []*Agent {
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
