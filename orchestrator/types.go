package orchestrator

import (
	"time"
)

type TaskType string

const (
	TaskTypeRecon       TaskType = "recon"
	TaskTypeExploit     TaskType = "exploit"
	TaskTypePostExploit TaskType = "post_exploit"
	TaskTypeLateral     TaskType = "lateral_movement"
	TaskTypeDestruct    TaskType = "destruction"
)

type Task struct {
	ID        string                 `json:"id"`
	Type      TaskType               `json:"type"`
	Input     string                 `json:"input"`
	Params    map[string]interface{} `json:"params"`
	Status    string                 `json:"status"`
	Result    map[string]interface{} `json:"result"`
	Error     string                 `json:"error"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

type Decision struct {
	Intent     string  `json:"intent"`
	Confidence float64 `json:"confidence"`
	RiskScore  int     `json:"risk_score"`
	Action     string  `json:"action"`
	Modules    []string `json:"modules"`
}

type ExecutionResult struct {
	TaskID    string                 `json:"task_id"`
	Success   bool                   `json:"success"`
	Data      map[string]interface{} `json:"data"`
	Error     string                 `json:"error"`
	Duration  time.Duration          `json:"duration"`
	Timestamp time.Time              `json:"timestamp"`
}
