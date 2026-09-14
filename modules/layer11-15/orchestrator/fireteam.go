package orchestrator

import (
	"fmt"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
)

type Fireteam struct {
	agents  []string
	results []*OrchResult
	log     *logger.Logger
	mu      sync.Mutex
}

func CreateFireteam(agents []string) *Fireteam {
	return &Fireteam{
		agents:  agents,
		results: make([]*OrchResult, 0),
		log:     logger.New("fireteam", logger.LevelInfo),
	}
}

func (ft *Fireteam) Execute(technique string, targets []string) ([]*OrchResult, error) {
	ft.log.Info("Fireteam executing: %d agents, %d targets, technique: %s", len(ft.agents), len(targets), technique)

	start := time.Now()
	results := make([]*OrchResult, 0, len(targets))

	for _, target := range targets {
		result := &OrchResult{
			ID:        fmt.Sprintf("fireteam_%d", time.Now().UnixNano()),
			Module:    ModuleDestruction,
			Action:    technique,
			Data:      map[string]interface{}{"target": target, "agents": ft.agents},
			Success:   true,
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}
		results = append(results, result)
	}

	ft.mu.Lock()
	ft.results = append(ft.results, results...)
	ft.mu.Unlock()

	ft.log.Info("Fireteam execution completed: %d results", len(results))
	return results, nil
}

func (ft *Fireteam) Wait() []*OrchResult {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	results := make([]*OrchResult, len(ft.results))
	copy(results, ft.results)
	return results
}

func (ft *Fireteam) AgentCount() int {
	return len(ft.agents)
}

func (ft *Fireteam) GetAgents() []string {
	agents := make([]string, len(ft.agents))
	copy(agents, ft.agents)
	return agents
}
