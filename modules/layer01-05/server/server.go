package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

type Server struct {
	mu       sync.RWMutex
	addr     string
	port     int
	running  bool
	agents   map[string]*Agent
	tasks    map[string]*Task
	results  []*Result
}

type Agent struct {
	ID        string
	Hostname  string
	IP        string
	OS        string
	Arch      string
	LastSeen  time.Time
	FirstSeen time.Time
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

func NewServer(addr string, port int) *Server {
	return &Server{
		addr:   addr,
		port:   port,
		agents: make(map[string]*Agent),
		tasks:  make(map[string]*Task),
	}
}

func (s *Server) Start() error {
	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agents", s.handleAgents)
	mux.HandleFunc("/api/v1/tasks", s.handleTasks)
	mux.HandleFunc("/api/v1/results", s.handleResults)
	mux.HandleFunc("/api/v1/health", s.handleHealth)

	addr := fmt.Sprintf("%s:%d", s.addr, s.port)
	log.Printf("Starting server on %s", addr)

	return http.ListenAndServe(addr, mux)
}

func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = false
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	s.mu.RLock()
	agents := make([]*Agent, 0, len(s.agents))
	for _, agent := range s.agents {
		agents = append(agents, agent)
	}
	s.mu.RUnlock()

	json.NewEncoder(w).Encode(agents)
}

func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	s.mu.RLock()
	tasks := make([]*Task, 0, len(s.tasks))
	for _, task := range s.tasks {
		tasks = append(tasks, task)
	}
	s.mu.RUnlock()

	json.NewEncoder(w).Encode(tasks)
}

func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	s.mu.RLock()
	results := make([]*Result, len(s.results))
	copy(results, s.results)
	s.mu.RUnlock()

	json.NewEncoder(w).Encode(results)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status": "ok"}`)
}

func (s *Server) AddAgent(agent *Agent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[agent.ID] = agent
}

func (s *Server) AddTask(task *Task) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tasks[task.ID] = task
}

func (s *Server) AddResult(result *Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results = append(s.results, result)
}

func (s *Server) GetAgent(agentID string) (*Agent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	agent, exists := s.agents[agentID]
	return agent, exists
}

func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

func (s *Server) GetAgentCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.agents)
}

func (s *Server) GetTaskCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tasks)
}
