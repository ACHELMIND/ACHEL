package types

import (
	"crypto/rand"
	"fmt"
	"time"
)

type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

type Platform string

const (
	PlatformWindows Platform = "windows"
	PlatformLinux   Platform = "linux"
	PlatformDarwin  Platform = "darwin"
	PlatformAndroid Platform = "android"
)

type EventType string

const (
	EventCommand  EventType = "command"
	EventResult   EventType = "result"
	EventSync     EventType = "sync"
	EventAlert    EventType = "alert"
)

type TaskStatus string

const (
	TaskStatusPending    TaskStatus = "pending"
	TaskStatusRunning    TaskStatus = "running"
	TaskStatusCompleted  TaskStatus = "completed"
	TaskStatusFailed     TaskStatus = "failed"
)

type TaskType string

const (
	TaskTypeShell       TaskType = "shell"
	TaskTypeDownload    TaskType = "download"
	TaskTypeUpload      TaskType = "upload"
	TaskTypeScreenshot  TaskType = "screenshot"
	TaskTypeKeylog      TaskType = "keylog"
	TaskTypePersistence TaskType = "persistence"
	TaskTypeExecute     TaskType = "execute"
	TaskTypeMigrate     TaskType = "migrate"
)

type Agent struct {
	ID         string
	Hostname   string
	IP         string
	OS         Platform
	Arch       string
	User       string
	PID        int
	Process    string
	LastCheck  time.Time
	FirstSeen  time.Time
	Metadata   map[string]string
}

type Task struct {
	ID        string
	AgentID   string
	Type      TaskType
	Payload   []byte
	Status    TaskStatus
	Result    []byte
	CreatedAt time.Time
	StartedAt time.Time
	EndedAt   time.Time
	Error     string
}

type Listener struct {
	ID       string
	Type     string
	BindAddr string
	BindPort int
	Status   string
	Config   map[string]string
}

type Evidence struct {
	ID          string
	TaskID      string
	AgentID     string
	Type        string
	Data        []byte
	Hash        string
	Timestamp   time.Time
	ChainHash   string
	Signature   []byte
}

type ModuleResult struct {
	Module    string
	Success   bool
	Data      map[string]interface{}
	Error     string
	Timestamp time.Time
}

type TaskResult struct {
	Module    string
	Success   bool
	Data      map[string]interface{}
	Error     string
	Timestamp time.Time
}

type ScanResult struct {
	Target    string
	Port      int
	Service   string
	Version   string
	OS        string
	Vulns     []Vulnerability
	Timestamp time.Time
}

type Vulnerability struct {
	CVE       string
	Severity  Severity
	Title     string
	Desc      string
	Exploit   bool
	CVSS      float64
}

type Credential struct {
	Type      string
	Username  string
	Password  string
	Hash      string
	Domain    string
	Source    string
	Hostname  string
	Timestamp time.Time
}

type NetworkInterface struct {
	Name      string
	IP        string
	MAC       string
	Gateway   string
	DNS       []string
	IsUp      bool
}

type ShellResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

func GenerateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func GenerateShortID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
