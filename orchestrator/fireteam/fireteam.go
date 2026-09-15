package fireteam

import (
	"fmt"
	"sync"
	"time"
)

type Fireteam struct {
	agents    []*Agent
	tasks     []*Task
	results   []*Result
	mu        sync.RWMutex
	running   bool
	maxAgents int
}

type Agent struct {
	ID        string
	Name      string
	Type      AgentType
	Status    AgentStatus
	Capabilities []string
	CurrentTask  *Task
	mu        sync.Mutex
}

type AgentType string

const (
	AgentRecon      AgentType = "recon"
	AgentExploit    AgentType = "exploit"
	AgentPostExploit AgentType = "post_exploit"
	AgentLateral    AgentType = "lateral"
	AgentDestruction AgentType = "destruction"
)

type AgentStatus string

const (
	StatusIdle     AgentStatus = "idle"
	StatusBusy     AgentStatus = "busy"
	StatusFailed   AgentStatus = "failed"
	StatusOffline  AgentStatus = "offline"
)

type Task struct {
	ID        string
	Type      string
	Payload   map[string]interface{}
	Priority  int
	Status    TaskStatus
	AgentID   string
	CreatedAt time.Time
	StartedAt *time.Time
	CompletedAt *time.Time
	Error     string
}

type TaskStatus string

const (
	TaskPending  TaskStatus = "pending"
	TaskRunning  TaskStatus = "running"
	TaskDone     TaskStatus = "done"
	TaskFailed   TaskStatus = "failed"
)

type Result struct {
	TaskID    string
	AgentID   string
	Data      map[string]interface{}
	Error     string
	Timestamp time.Time
}

func NewFireteam(maxAgents int) *Fireteam {
	return &Fireteam{
		agents:    make([]*Agent, 0),
		tasks:     make([]*Task, 0),
		results:   make([]*Result, 0),
		maxAgents: maxAgents,
	}
}

func (ft *Fireteam) AddAgent(agent *Agent) error {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	if len(ft.agents) >= ft.maxAgents {
		return fmt.Errorf("fireteam at max capacity (%d)", ft.maxAgents)
	}

	agent.Status = StatusIdle
	ft.agents = append(ft.agents, agent)
	return nil
}

func (ft *Fireteam) RemoveAgent(agentID string) error {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	for i, agent := range ft.agents {
		if agent.ID == agentID {
			ft.agents = append(ft.agents[:i], ft.agents[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("agent %s not found", agentID)
}

func (ft *Fireteam) AddTask(task *Task) error {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	task.Status = TaskPending
	task.CreatedAt = time.Now()
	ft.tasks = append(ft.tasks, task)
	return nil
}

func (ft *Fireteam) ExecuteParallel() error {
	ft.mu.Lock()
	ft.running = true
	ft.mu.Unlock()

	defer func() {
		ft.mu.Lock()
		ft.running = false
		ft.mu.Unlock()
	}()

	var wg sync.WaitGroup
	taskChan := make(chan *Task, len(ft.tasks))

	for _, task := range ft.tasks {
		if task.Status == TaskPending {
			taskChan <- task
		}
	}
	close(taskChan)

	for task := range taskChan {
		agent := ft.findIdleAgent(task)
		if agent == nil {
			task.Status = TaskFailed
			task.Error = "no idle agent available"
			continue
		}

		wg.Add(1)
		go func(t *Task, a *Agent) {
			defer wg.Done()
			ft.executeTask(t, a)
		}(task, agent)
	}

	wg.Wait()
	return nil
}

func (ft *Fireteam) ExecuteSequential() error {
	ft.mu.Lock()
	ft.running = true
	ft.mu.Unlock()

	defer func() {
		ft.mu.Lock()
		ft.running = false
		ft.mu.Unlock()
	}()

	for _, task := range ft.tasks {
		if task.Status != TaskPending {
			continue
		}

		agent := ft.findIdleAgent(task)
		if agent == nil {
			task.Status = TaskFailed
			task.Error = "no idle agent available"
			continue
		}

		ft.executeTask(task, agent)
	}

	return nil
}

func (ft *Fireteam) executeTask(task *Task, agent *Agent) {
	agent.mu.Lock()
	agent.Status = StatusBusy
	agent.CurrentTask = task
	agent.mu.Unlock()

	now := time.Now()
	task.Status = TaskRunning
	task.AgentID = agent.ID
	task.StartedAt = &now

	defer func() {
		agent.mu.Lock()
		agent.Status = StatusIdle
		agent.CurrentTask = nil
		agent.mu.Unlock()
	}()

	result := &Result{
		TaskID:    task.ID,
		AgentID:   agent.ID,
		Data:      make(map[string]interface{}),
		Timestamp: time.Now(),
	}

	completedAt := time.Now()
	task.CompletedAt = &completedAt
	task.Status = TaskDone

	ft.mu.Lock()
	ft.results = append(ft.results, result)
	ft.mu.Unlock()
}

func (ft *Fireteam) findIdleAgent(task *Task) *Agent {
	ft.mu.RLock()
	defer ft.mu.RUnlock()

	for _, agent := range ft.agents {
		agent.mu.Lock()
		if agent.Status == StatusIdle {
			agent.mu.Unlock()
			return agent
		}
		agent.mu.Unlock()
	}
	return nil
}

func (ft *Fireteam) GetResults() []*Result {
	ft.mu.RLock()
	defer ft.mu.RUnlock()
	results := make([]*Result, len(ft.results))
	copy(results, ft.results)
	return results
}

func (ft *Fireteam) GetStatus() map[string]interface{} {
	ft.mu.RLock()
	defer ft.mu.RUnlock()

	idleCount := 0
	busyCount := 0
	for _, agent := range ft.agents {
		agent.mu.Lock()
		switch agent.Status {
		case StatusIdle:
			idleCount++
		case StatusBusy:
			busyCount++
		}
		agent.mu.Unlock()
	}

	return map[string]interface{}{
		"total_agents":   len(ft.agents),
		"idle_agents":    idleCount,
		"busy_agents":    busyCount,
		"total_tasks":    len(ft.tasks),
		"total_results":  len(ft.results),
		"running":        ft.running,
	}
}

func (ft *Fireteam) Reset() {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	ft.tasks = make([]*Task, 0)
	ft.results = make([]*Result, 0)
	ft.running = false
	for _, agent := range ft.agents {
		agent.mu.Lock()
		agent.Status = StatusIdle
		agent.CurrentTask = nil
		agent.mu.Unlock()
	}
}
