package orchestrator

import (
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

type RiskLevel int

const (
	RiskLevelAuto RiskLevel = iota
	RiskLevelRequestApproval
	RiskLevelBlock
)

type ModuleType string

const (
	ModuleDestruction  ModuleType = "destruction"
	ModuleCredential   ModuleType = "credential"
	ModuleCollector    ModuleType = "collector"
	ModulePersistence  ModuleType = "persistence"
	ModuleLateral      ModuleType = "lateral"
	ModuleEvasion      ModuleType = "evasion"
	ModuleRootkit      ModuleType = "rootkit"
	ModuleKerberos     ModuleType = "kerberos"
	ModuleBrain        ModuleType = "brain"
)

type Intent struct {
	ID          string            `json:"id"`
	Request     string            `json:"request"`
	Category    string            `json:"category"`
	Module      ModuleType        `json:"module"`
	Action      string            `json:"action"`
	RiskLevel   RiskLevel         `json:"risk_level"`
	Confidence  float64           `json:"confidence"`
	Params      map[string]interface{} `json:"params"`
	Targets     []string          `json:"targets"`
	Timestamp   time.Time         `json:"timestamp"`
}

type Action struct {
	ID          string            `json:"id"`
	Intent      *Intent           `json:"intent"`
	Module      ModuleType        `json:"module"`
	Method      string            `json:"method"`
	Target      string            `json:"target"`
	Params      map[string]interface{} `json:"params"`
	RiskScore   float64           `json:"risk_score"`
	RequiresApproval bool         `json:"requires_approval"`
}

type OrchResult struct {
	ID          string                 `json:"id"`
	Success     bool                   `json:"success"`
	Module      ModuleType             `json:"module"`
	Action      string                 `json:"action"`
	Data        map[string]interface{} `json:"data"`
	Error       string                 `json:"error"`
	Duration    time.Duration          `json:"duration"`
	Timestamp   time.Time              `json:"timestamp"`
	TaskID      string                 `json:"task_id"`
}

type TaskStatus struct {
	TaskID    string            `json:"task_id"`
	AgentID   string            `json:"agent_id"`
	Status    types.TaskStatus  `json:"status"`
	Result    *types.TaskResult `json:"result,omitempty"`
	StartedAt time.Time         `json:"started_at"`
	EndedAt   time.Time         `json:"ended_at"`
	Error     string            `json:"error"`
}

type FireteamResult struct {
	AgentID   string       `json:"agent_id"`
	Result    *OrchResult  `json:"result"`
	Error     string       `json:"error"`
}

type StateEntry struct {
	Key       string      `json:"key"`
	Value     interface{} `json:"value"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
}

type OrchestratorConfig struct {
	MaxConcurrentTasks int           `json:"max_concurrent_tasks"`
	TaskTimeout        time.Duration `json:"task_timeout"`
	HeartbeatInterval  time.Duration `json:"heartbeat_interval"`
	MaxRetries         int           `json:"max_retries"`
	AutoApprove        bool          `json:"auto_approve"`
}

func DefaultOrchestratorConfig() *OrchestratorConfig {
	return &OrchestratorConfig{
		MaxConcurrentTasks: 10,
		TaskTimeout:        5 * time.Minute,
		HeartbeatInterval:  30 * time.Second,
		MaxRetries:         3,
		AutoApprove:        false,
	}
}

type AgentInfo struct {
	ID        string         `json:"id"`
	Hostname  string         `json:"hostname"`
	IP        string         `json:"ip"`
	OS        string         `json:"os"`
	Status    string         `json:"status"`
	Modules   []ModuleType   `json:"modules"`
	LastSeen  time.Time      `json:"last_seen"`
}
