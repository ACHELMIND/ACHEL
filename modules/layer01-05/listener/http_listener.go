package listener

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

type HTTPListener struct {
	mu          sync.RWMutex
	addr        string
	port        int
	running     bool
	agents      map[string]*AgentInfo
	ssl         bool
	certFile    string
	keyFile     string
}

type AgentInfo struct {
	ID        string
	Hostname  string
	IP        string
	OS        string
	Arch      string
	LastSeen  time.Time
	Connected bool
}

type HTTPListenerConfig struct {
	Addr     string
	Port     int
	SSL      bool
	CertFile string
	KeyFile  string
}

func NewHTTPListener(config HTTPListenerConfig) *HTTPListener {
	return &HTTPListener{
		addr:   config.Addr,
		port:   config.Port,
		ssl:    config.SSL,
		certFile: config.CertFile,
		keyFile:  config.KeyFile,
		agents: make(map[string]*AgentInfo),
	}
}

func (l *HTTPListener) Start() error {
	l.mu.Lock()
	l.running = true
	l.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/register", l.handleRegister)
	mux.HandleFunc("/api/v1/task", l.handleTask)
	mux.HandleFunc("/api/v1/result", l.handleResult)
	mux.HandleFunc("/api/v1/heartbeat", l.handleHeartbeat)
	mux.HandleFunc("/api/v1/checkin", l.handleCheckIn)

	addr := fmt.Sprintf("%s:%d", l.addr, l.port)
	log.Printf("Starting HTTP listener on %s", addr)

	if l.ssl {
		return http.ListenAndServeTLS(addr, l.certFile, l.keyFile, mux)
	}
	return http.ListenAndServe(addr, mux)
}

func (l *HTTPListener) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.running = false
}

func (l *HTTPListener) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	agentID := generateHTTPID()
	hostname := r.Header.Get("X-Hostname")
	ip := r.RemoteAddr

	agent := &AgentInfo{
		ID:        agentID,
		Hostname:  hostname,
		IP:        ip,
		OS:        r.Header.Get("X-OS"),
		Arch:      r.Header.Get("X-Arch"),
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

func (l *HTTPListener) handleTask(w http.ResponseWriter, r *http.Request) {
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status": "ok", "message": "no tasks"}`)
}

func (l *HTTPListener) handleResult(w http.ResponseWriter, r *http.Request) {
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

func (l *HTTPListener) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
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

func (l *HTTPListener) handleCheckIn(w http.ResponseWriter, r *http.Request) {
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status": "ok"}`)
}

func (l *HTTPListener) GetAgents() []*AgentInfo {
	l.mu.RLock()
	defer l.mu.RUnlock()

	agents := make([]*AgentInfo, 0, len(l.agents))
	for _, agent := range l.agents {
		agents = append(agents, agent)
	}
	return agents
}

func (l *HTTPListener) GetAgent(agentID string) *AgentInfo {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.agents[agentID]
}

func (l *HTTPListener) IsRunning() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.running
}

func generateHTTPID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
