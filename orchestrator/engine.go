package orchestrator

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/angel-platform/angel/orchestrator/fireteam"
	"github.com/angel-platform/angel/orchestrator/intent"
	"github.com/angel-platform/angel/orchestrator/langgraph"
	"github.com/angel-platform/angel/orchestrator/mcp"
)

type Orchestrator struct {
	graph       *langgraph.Graph
	classifier  *intent.IntentClassifier
	fireteam    *fireteam.Fireteam
	mcpServer   *mcp.MCPServer
	state       *State
	config      *Config
	mu          sync.RWMutex
	running     bool
	startTime   time.Time
}

type Config struct {
	MaxAgents      int           `json:"max_agents"`
	MaxMCPsessions int           `json:"max_mcp_sessions"`
	TaskTimeout    time.Duration `json:"task_timeout"`
	EnableFireteam bool          `json:"enable_fireteam"`
	EnableMCP      bool          `json:"enable_mcp"`
	EnableBrain    bool          `json:"enable_brain"`
}

type State struct {
CurrentTask string
LastDecision string
RiskScore    int
	Actions     []string
	mu          sync.RWMutex
}

func New(cfg *Config) *Orchestrator {
	if cfg == nil {
		cfg = &Config{
			MaxAgents:      10,
			MaxMCPsessions: 5,
			TaskTimeout:    5 * time.Minute,
			EnableFireteam: true,
			EnableMCP:      true,
			EnableBrain:    true,
		}
	}

	orch := &Orchestrator{
		graph:      langgraph.NewGraph(),
		classifier: intent.NewIntentClassifier(),
		fireteam:   fireteam.NewFireteam(cfg.MaxAgents),
		mcpServer:  mcp.NewMCPServer(cfg.MaxMCPsessions),
		state: &State{
			Actions: make([]string, 0),
		},
		config:    cfg,
		startTime: time.Now(),
	}

	orch.setupGraph()
	return orch
}

func (o *Orchestrator) setupGraph() {
	o.graph.AddNode("start", "Start", langgraph.NodeTypeStart, nil)
	o.graph.AddNode("classify", "Intent Classification", langgraph.NodeTypeAction, o.classifyIntent)
	o.graph.AddNode("assess_risk", "Risk Assessment", langgraph.NodeTypeAction, o.assessRisk)
	o.graph.AddNode("route", "Route Decision", langgraph.NodeTypeRouter, o.routeDecision)
	o.graph.AddNode("execute_recon", "Execute Recon", langgraph.NodeTypeAction, o.executeRecon)
	o.graph.AddNode("execute_exploit", "Execute Exploit", langgraph.NodeTypeAction, o.executeExploit)
	o.graph.AddNode("execute_post", "Execute Post-Exploit", langgraph.NodeTypeAction, o.executePostExploit)
	o.graph.AddNode("execute_lateral", "Execute Lateral", langgraph.NodeTypeAction, o.executeLateral)
	o.graph.AddNode("execute_destruct", "Execute Destruction", langgraph.NodeTypeAction, o.executeDestruction)
	o.graph.AddNode("collect_results", "Collect Results", langgraph.NodeTypeAction, o.collectResults)
	o.graph.AddNode("end", "End", langgraph.NodeTypeEnd, nil)

	o.graph.AddEdge("start", "classify")
	o.graph.AddEdge("classify", "assess_risk")
	o.graph.AddEdge("assess_risk", "route")
	o.graph.AddEdge("route", "execute_recon")
	o.graph.AddEdge("route", "execute_exploit")
	o.graph.AddEdge("route", "execute_post")
	o.graph.AddEdge("route", "execute_lateral")
	o.graph.AddEdge("route", "execute_destruct")
	o.graph.AddEdge("execute_recon", "collect_results")
	o.graph.AddEdge("execute_exploit", "collect_results")
	o.graph.AddEdge("execute_post", "collect_results")
	o.graph.AddEdge("execute_lateral", "collect_results")
	o.graph.AddEdge("execute_destruct", "collect_results")
	o.graph.AddEdge("collect_results", "end")
}

func (o *Orchestrator) classifyIntent(state map[string]interface{}) (map[string]interface{}, error) {
	input, _ := state["input"].(string)
	result := o.classifier.Classify(input)
	return map[string]interface{}{
		"intent":     string(result.Intent),
		"confidence": result.Confidence,
		"risk_score": result.RiskScore,
		"modules":    result.Modules,
	}, nil
}

func (o *Orchestrator) assessRisk(state map[string]interface{}) (map[string]interface{}, error) {
	riskScore, _ := state["risk_score"].(int)
	intent, _ := state["intent"].(string)

	action := "auto_execute"
	if riskScore > 70 {
		action = "block_alert"
	} else if riskScore > 30 {
		action = "request_approval"
	}

	if intent == "destruction" {
		action = "request_approval"
	}

	return map[string]interface{}{
		"risk_action": action,
	}, nil
}

func (o *Orchestrator) routeDecision(state map[string]interface{}) (map[string]interface{}, error) {
	intent, _ := state["intent"].(string)
	return map[string]interface{}{
		"route": intent,
	}, nil
}

func (o *Orchestrator) executeRecon(state map[string]interface{}) (map[string]interface{}, error) {
	log.Println("Executing recon module")
	return map[string]interface{}{"recon_result": "recon_completed"}, nil
}

func (o *Orchestrator) executeExploit(state map[string]interface{}) (map[string]interface{}, error) {
	log.Println("Executing exploit module")
	return map[string]interface{}{"exploit_result": "exploit_completed"}, nil
}

func (o *Orchestrator) executePostExploit(state map[string]interface{}) (map[string]interface{}, error) {
	log.Println("Executing post-exploit module")
	return map[string]interface{}{"post_result": "post_completed"}, nil
}

func (o *Orchestrator) executeLateral(state map[string]interface{}) (map[string]interface{}, error) {
	log.Println("Executing lateral movement module")
	return map[string]interface{}{"lateral_result": "lateral_completed"}, nil
}

func (o *Orchestrator) executeDestruction(state map[string]interface{}) (map[string]interface{}, error) {
	log.Println("Executing destruction module")
	return map[string]interface{}{"destruct_result": "destruct_completed"}, nil
}

func (o *Orchestrator) collectResults(state map[string]interface{}) (map[string]interface{}, error) {
	return map[string]interface{}{
		"collected": true,
		"timestamp": time.Now().Unix(),
	}, nil
}

func (o *Orchestrator) Execute(input string) error {
	o.mu.Lock()
	o.running = true
	o.mu.Unlock()

	defer func() {
		o.mu.Lock()
		o.running = false
		o.mu.Unlock()
	}()

	o.graph.SetState("input", input)
	o.graph.SetState("start_time", time.Now())

	err := o.graph.Run("start")
	if err != nil {
		return fmt.Errorf("orchestrator execution failed: %w", err)
	}

	return nil
}

func (o *Orchestrator) GetStatus() map[string]interface{} {
	o.mu.RLock()
	defer o.mu.RUnlock()

	return map[string]interface{}{
		"running":        o.running,
		"uptime":         time.Since(o.startTime).String(),
		"fireteam":       o.fireteam.GetStatus(),
		"mcp":            o.mcpServer.GetStatus(),
		"graph_state":    o.graph.GetStateSnapshot(),
	}
}

func (o *Orchestrator) Stop() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.running = false
}

func (o *Orchestrator) Reset() {
	o.graph.Reset()
	o.fireteam.Reset()
	o.state.mu.Lock()
	o.state.Actions = make([]string, 0)
	o.state.CurrentTask = ""
	o.state.LastDecision = ""
	o.state.RiskScore = 0
	o.state.mu.Unlock()
}
