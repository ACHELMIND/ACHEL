package destructionchain

import (
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

type ChainStatus string

const (
	ChainStatusPending   ChainStatus = "pending"
	ChainStatusRunning   ChainStatus = "running"
	ChainStatusPaused    ChainStatus = "paused"
	ChainStatusCompleted ChainStatus = "completed"
	ChainStatusFailed    ChainStatus = "failed"
	ChainStatusAborted   ChainStatus = "aborted"
)

type StepStatus string

const (
	StepStatusPending   StepStatus = "pending"
	StepStatusRunning   StepStatus = "running"
	StepStatusCompleted StepStatus = "completed"
	StepStatusFailed    StepStatus = "failed"
	StepStatusSkipped   StepStatus = "skipped"
)

type StepType string

const (
	StepTypeRecon     StepType = "recon"
	StepTypeScan      StepType = "scan"
	StepTypeExploit   StepType = "exploit"
	StepTypePivot     StepType = "pivot"
	StepTypeEscalate  StepType = "escalate"
	StepTypeExfil     StepType = "exfil"
	StepTypeDestroy   StepType = "destroy"
	StepTypeCleanup   StepType = "cleanup"
	StepTypeReport    StepType = "report"
)

type DestructionChain struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Status      ChainStatus       `json:"status"`
	Steps       []ChainStep       `json:"steps"`
	Target      *FullScopeTarget  `json:"target"`
	CreatedAt   time.Time         `json:"created_at"`
	StartedAt   *time.Time        `json:"started_at,omitempty"`
	CompletedAt *time.Time        `json:"completed_at,omitempty"`
	Error       string            `json:"error,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type ChainStep struct {
	ID          string                 `json:"id"`
	Type        StepType               `json:"type"`
	Name        string                 `json:"name"`
	Status      StepStatus             `json:"status"`
	Config      map[string]interface{} `json:"config"`
	DependsOn   []string               `json:"depends_on,omitempty"`
	Timeout     time.Duration          `json:"timeout"`
	Retries     int                    `json:"retries"`
	Result      *StepResult            `json:"result,omitempty"`
	StartedAt   *time.Time             `json:"started_at,omitempty"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Error       string                 `json:"error,omitempty"`
}

type StepResult struct {
	Success   bool                   `json:"success"`
	Data      map[string]interface{} `json:"data"`
	Error     string                 `json:"error,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

type ChainResult struct {
	ChainID    string                 `json:"chain_id"`
	Success    bool                   `json:"success"`
	Results    map[string]*StepResult `json:"results"`
	StartedAt  time.Time              `json:"started_at"`
	CompletedAt time.Time             `json:"completed_at"`
	Duration   time.Duration          `json:"duration"`
	Error      string                 `json:"error,omitempty"`
}

type FullScopeTarget struct {
	Host       string                 `json:"host"`
	IP         string                 `json:"ip"`
	OS         types.Platform         `json:"os"`
	Arch       string                 `json:"arch"`
	Ports      []int                  `json:"ports,omitempty"`
	Services   []ServiceInfo          `json:"services,omitempty"`
	Vulns      []types.Vulnerability  `json:"vulns,omitempty"`
	Creds      []types.Credential     `json:"creds,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type ServiceInfo struct {
	Port    int    `json:"port"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Banner  string `json:"banner,omitempty"`
}

type FullScopeResult struct {
	ChainID     string                 `json:"chain_id"`
	Target      *FullScopeTarget       `json:"target"`
	Recon       *ReconResult           `json:"recon"`
	Attack      *AttackResult          `json:"attack"`
	Destroy     *DestroyResult         `json:"destroy"`
	Report      *types.ModuleResult    `json:"report"`
	OverallSuccess bool                `json:"overall_success"`
	Duration    time.Duration          `json:"duration"`
	Timestamp   time.Time              `json:"timestamp"`
}

type ReconResult struct {
	Host       string                 `json:"host"`
	Ports      []ServiceInfo          `json:"ports"`
	Vulns      []types.Vulnerability  `json:"vulns"`
	Secrets    []string               `json:"secrets"`
	NetworkMap map[string]interface{} `json:"network_map"`
}

type AttackResult struct {
	Exploited  bool                   `json:"exploited"`
	Access     string                 `json:"access"`
	Creds      []types.Credential     `json:"creds"`
	Shells     []ShellInfo            `json:"shells"`
	Data       map[string]interface{} `json:"data"`
}

type ShellInfo struct {
	Type string `json:"type"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

type DestroyResult struct {
	Target      string   `json:"target"`
	Method      string   `json:"method"`
	Artifacts   []string `json:"artifacts"`
	Verified    bool     `json:"verified"`
}

type ImpactReport struct {
	Target        string        `json:"target"`
	Scope         string        `json:"scope"`
	Criticality   types.Severity `json:"criticality"`
	AffectedHosts int           `json:"affected_hosts"`
	EstimatedTime time.Duration `json:"estimated_time"`
	RiskScore     float64      `json:"risk_score"`
	Recommendations []string    `json:"recommendations"`
}

type DestructionChainConfig struct {
	MaxConcurrentSteps int
	DefaultTimeout     time.Duration
	MaxRetries         int
	PauseOnError       bool
	StealthMode        bool
	Metadata           map[string]string
}

type ChainProgress struct {
	ChainID       string        `json:"chain_id"`
	Status        ChainStatus   `json:"status"`
	TotalSteps    int           `json:"total_steps"`
	CompletedSteps int          `json:"completed_steps"`
	FailedSteps   int           `json:"failed_steps"`
	CurrentStep   string        `json:"current_step,omitempty"`
	Elapsed       time.Duration `json:"elapsed"`
	ETA           time.Duration `json:"eta,omitempty"`
	Percentage    float64      `json:"percentage"`
}

type TimingConfig struct {
	MinDelay     time.Duration
	MaxDelay     time.Duration
	Jitter       float64
	SyncEnabled  bool
}

type TimingCoordinator struct {
	mu       sync.Mutex
	config   *TimingConfig
	schedule map[string]*ScheduledStep
	chain    map[string]*ChainProgress
}

type ScheduledStep struct {
	Step      *ChainStep
	ScheduleAt time.Time
	Delay     time.Duration
	Cancelled bool
}

func NewDefaultChainConfig() *DestructionChainConfig {
	return &DestructionChainConfig{
		MaxConcurrentSteps: 1,
		DefaultTimeout:     30 * time.Minute,
		MaxRetries:         3,
		PauseOnError:       false,
		StealthMode:        false,
	}
}

func NewDefaultTimingConfig() *TimingConfig {
	return &TimingConfig{
		MinDelay:    100 * time.Millisecond,
		MaxDelay:    5 * time.Second,
		Jitter:      0.1,
		SyncEnabled: true,
	}
}
