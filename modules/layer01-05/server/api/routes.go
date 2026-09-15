package api

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
	mux.HandleFunc("/api/v1/agents/", s.handleAgentByID)
	mux.HandleFunc("/api/v1/tasks", s.handleTasks)
	mux.HandleFunc("/api/v1/tasks/", s.handleTaskByID)
	mux.HandleFunc("/api/v1/results", s.handleResults)
	mux.HandleFunc("/api/v1/health", s.handleHealth)

	addr := fmt.Sprintf("%s:%d", s.addr, s.port)
	log.Printf("Starting API server on %s", addr)

	return http.ListenAndServe(addr, mux)
}

func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = false
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		agents := make([]*Agent, 0, len(s.agents))
		for _, agent := range s.agents {
			agents = append(agents, agent)
		}
		s.mu.RUnlock()
		json.NewEncoder(w).Encode(agents)

	case http.MethodPost:
		var agent Agent
		if err := json.NewDecoder(r.Body).Decode(&agent); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		agent.FirstSeen = time.Now()
		agent.LastSeen = time.Now()

		s.mu.Lock()
		s.agents[agent.ID] = &agent
		s.mu.Unlock()

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(agent)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAgentByID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	agentID := r.URL.Path[len("/api/v1/agents/"):]
	if agentID == "" {
		http.Error(w, "Missing agent ID", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	agent, exists := s.agents[agentID]
	s.mu.RUnlock()

	if !exists {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(agent)
}

func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		tasks := make([]*Task, 0, len(s.tasks))
		for _, task := range s.tasks {
			tasks = append(tasks, task)
		}
		s.mu.RUnlock()
		json.NewEncoder(w).Encode(tasks)

	case http.MethodPost:
		var task Task
		if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		task.CreatedAt = time.Now()
		task.Status = "pending"

		s.mu.Lock()
		s.tasks[task.ID] = &task
		s.mu.Unlock()

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(task)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleTaskByID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	taskID := r.URL.Path[len("/api/v1/tasks/"):]
	if taskID == "" {
		http.Error(w, "Missing task ID", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	task, exists := s.tasks[taskID]
	s.mu.RUnlock()

	if !exists {
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(task)
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
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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
