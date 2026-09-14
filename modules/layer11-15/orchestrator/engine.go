package orchestrator

import (
	"fmt"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/eventbus"
	"github.com/angel-platform/angel/pkg/logger"
	"github.com/angel-platform/angel/pkg/types"
)

type Orchestrator struct {
	bus        *eventbus.EventBus
	config     *OrchestratorConfig
	classifier *IntentClassifier
	dispatcher *Dispatcher
	state      *StateManager
	log        *logger.Logger
	agents     map[string]*AgentInfo
	mu         sync.RWMutex
	running    bool
}

func NewOrchestrator(bus *eventbus.EventBus) *Orchestrator {
	config := DefaultOrchestratorConfig()

	o := &Orchestrator{
		bus:        bus,
		config:     config,
		state:      NewStateManager(),
		log:        logger.New("orchestrator", logger.LevelInfo),
		agents:     make(map[string]*AgentInfo),
		running:    false,
	}

	o.classifier = NewIntentClassifier()
	o.dispatcher = NewDispatcher(bus)

	return o
}

func (o *Orchestrator) Start() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.running {
		return fmt.Errorf("orchestrator already running")
	}

	o.running = true
	o.log.Info("Orchestrator started")

	if o.bus != nil {
		o.bus.Subscribe("agent.register", func(event eventbus.Event) error {
			if agentID, ok := event.Data["agent_id"].(string); ok {
				agent := &AgentInfo{
					ID:       agentID,
					Hostname: fmt.Sprintf("%v", event.Data["hostname"]),
					IP:       fmt.Sprintf("%v", event.Data["ip"]),
					OS:       fmt.Sprintf("%v", event.Data["os"]),
					Status:   "online",
					LastSeen: time.Now(),
				}
				o.mu.Lock()
				o.agents[agentID] = agent
				o.mu.Unlock()
				o.log.Info("Agent registered: %s", agentID)
			}
			return nil
		})
	}

	return nil
}

func (o *Orchestrator) Stop() {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.running = false
	o.log.Info("Orchestrator stopped")
}

func (o *Orchestrator) HandleIntent(intent *Intent) (*OrchResult, error) {
	if intent == nil {
		return nil, fmt.Errorf("nil intent")
	}

	o.log.Info("Handling intent: %s (module: %s, action: %s)", intent.ID, intent.Module, intent.Action)

	start := time.Now()

	result := &OrchResult{
		ID:        intent.ID,
		Module:    intent.Module,
		Action:    intent.Action,
		Data:      make(map[string]interface{}),
		Timestamp: time.Now(),
	}

	o.state.SaveState(fmt.Sprintf("intent:%s", intent.ID), intent)

	switch intent.RiskLevel {
	case RiskLevelBlock:
		result.Error = "action blocked by risk assessment"
		result.Duration = time.Since(start)
		return result, fmt.Errorf("action blocked: risk level too high")
	case RiskLevelRequestApproval:
		o.log.Info("Intent requires approval: %s", intent.ID)
		result.Data["status"] = "awaiting_approval"
		result.Duration = time.Since(start)
		return result, nil
	}

	orchResult, err := o.RouteToModule(string(intent.Module), intent.Action, intent.Params)
	if err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, err
	}

	orchResult.ID = intent.ID
	orchResult.Duration = time.Since(start)
	return orchResult, nil
}

func (o *Orchestrator) RouteToModule(module string, action string, params map[string]interface{}) (*OrchResult, error) {
	o.log.Info("Routing to module: %s, action: %s", module, action)

	start := time.Now()

	result := &OrchResult{
		Module:    ModuleType(module),
		Action:    action,
		Data:      make(map[string]interface{}),
		Timestamp: time.Now(),
	}

	o.mu.RLock()
	agentCount := len(o.agents)
	o.mu.RUnlock()

	if agentCount == 0 {
		result.Data["status"] = "no_agents"
		result.Data["message"] = "no agents available"
		result.Duration = time.Since(start)
		return result, nil
	}

	task := &types.Task{
		ID:        types.GenerateID(),
		Type:      types.TaskTypeShell,
		Status:    types.TaskStatusPending,
		CreatedAt: time.Now(),
	}

	result.TaskID = task.ID
	result.Success = true
	result.Duration = time.Since(start)

	return result, nil
}

func (o *Orchestrator) ExecuteFireteam(targets []string, technique string) ([]*OrchResult, error) {
	o.log.Info("Executing fireteam: %d targets, technique: %s", len(targets), technique)

	start := time.Now()
	results := make([]*OrchResult, 0, len(targets))

	for _, target := range targets {
		result := &OrchResult{
			ID:        types.GenerateID(),
			Module:    ModuleDestruction,
			Action:    technique,
			Data:      map[string]interface{}{"target": target},
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}
		results = append(results, result)
	}

	return results, nil
}

func (o *Orchestrator) GetAgent(agentID string) (*AgentInfo, bool) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	agent, ok := o.agents[agentID]
	return agent, ok
}

func (o *Orchestrator) ListAgents() []*AgentInfo {
	o.mu.RLock()
	defer o.mu.RUnlock()

	agents := make([]*AgentInfo, 0, len(o.agents))
	for _, a := range o.agents {
		agents = append(agents, a)
	}
	return agents
}

func (o *Orchestrator) GetConfig() *OrchestratorConfig {
	return o.config
}

func (o *Orchestrator) IsRunning() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.running
}
