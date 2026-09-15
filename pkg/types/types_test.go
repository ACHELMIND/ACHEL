package types

import (
	"testing"
)

func TestSeverity_String(t *testing.T) {
	tests := []struct {
		s    Severity
		want string
	}{
		{SeverityLow, "LOW"},
		{SeverityMedium, "MEDIUM"},
		{SeverityHigh, "HIGH"},
		{SeverityCritical, "CRITICAL"},
		{Severity(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", int(tt.s), got, tt.want)
		}
	}
}

func TestGenerateID(t *testing.T) {
	id1 := GenerateID()
	id2 := GenerateID()

	if id1 == "" {
		t.Error("ID should not be empty")
	}
	if len(id1) != 32 {
		t.Errorf("ID length = %d, want 32", len(id1))
	}
	if id1 == id2 {
		t.Error("IDs should be unique")
	}
}

func TestGenerateShortID(t *testing.T) {
	id1 := GenerateShortID()
	id2 := GenerateShortID()

	if id1 == "" {
		t.Error("ShortID should not be empty")
	}
	if len(id1) != 16 {
		t.Errorf("ShortID length = %d, want 16", len(id1))
	}
	if id1 == id2 {
		t.Error("ShortIDs should be unique")
	}
}

func TestAgent(t *testing.T) {
	a := Agent{
		ID:       "agent-1",
		Hostname: "desktop-01",
		IP:       "192.168.1.100",
		OS:       PlatformWindows,
		Arch:     "amd64",
		User:     "admin",
		PID:      1234,
		Process:  "explorer.exe",
	}

	if a.ID != "agent-1" {
		t.Errorf("ID = %q, want %q", a.ID, "agent-1")
	}
	if a.OS != PlatformWindows {
		t.Errorf("OS = %q, want %q", a.OS, PlatformWindows)
	}
}

func TestTask(t *testing.T) {
	task := Task{
		ID:      "task-1",
		AgentID: "agent-1",
		Type:    TaskTypeShell,
		Status:  TaskStatusPending,
	}

	if task.Type != TaskTypeShell {
		t.Errorf("Type = %q, want %q", task.Type, TaskTypeShell)
	}
	if task.Status != TaskStatusPending {
		t.Errorf("Status = %q, want %q", task.Status, TaskStatusPending)
	}
}

func TestTaskStatusValues(t *testing.T) {
	statuses := []TaskStatus{
		TaskStatusPending,
		TaskStatusRunning,
		TaskStatusCompleted,
		TaskStatusFailed,
	}

	seen := make(map[TaskStatus]bool)
	for _, s := range statuses {
		if seen[s] {
			t.Errorf("duplicate TaskStatus: %q", s)
		}
		seen[s] = true
	}
}

func TestTaskTypeValues(t *testing.T) {
	types := []TaskType{
		TaskTypeShell,
		TaskTypeDownload,
		TaskTypeUpload,
		TaskTypeScreenshot,
		TaskTypeKeylog,
		TaskTypePersistence,
		TaskTypeExecute,
		TaskTypeMigrate,
	}

	seen := make(map[TaskType]bool)
	for _, tt := range types {
		if seen[tt] {
			t.Errorf("duplicate TaskType: %q", tt)
		}
		seen[tt] = true
	}
}

func TestEventTypeValues(t *testing.T) {
	events := []EventType{
		EventCommand,
		EventResult,
		EventSync,
		EventAlert,
	}

	seen := make(map[EventType]bool)
	for _, e := range events {
		if seen[e] {
			t.Errorf("duplicate EventType: %q", e)
		}
		seen[e] = true
	}
}

func TestPlatformValues(t *testing.T) {
	platforms := []Platform{
		PlatformWindows,
		PlatformLinux,
		PlatformDarwin,
		PlatformAndroid,
	}

	seen := make(map[Platform]bool)
	for _, p := range platforms {
		if seen[p] {
			t.Errorf("duplicate Platform: %q", p)
		}
		seen[p] = true
	}
}

func TestModuleResult(t *testing.T) {
	mr := ModuleResult{
		Module:  "test-module",
		Success: true,
	}

	if mr.Module != "test-module" {
		t.Errorf("Module = %q, want %q", mr.Module, "test-module")
	}
	if !mr.Success {
		t.Error("Success should be true")
	}
}

func TestEvidence(t *testing.T) {
	e := Evidence{
		ID:     "ev-1",
		TaskID: "task-1",
		Type:   "screenshot",
		Hash:   "abc123",
	}

	if e.ID != "ev-1" {
		t.Errorf("ID = %q, want %q", e.ID, "ev-1")
	}
	if e.Type != "screenshot" {
		t.Errorf("Type = %q, want %q", e.Type, "screenshot")
	}
}

func TestCredential(t *testing.T) {
	c := Credential{
		Type:     "password",
		Username: "admin",
		Password: "secret123",
		Domain:   "corp.local",
		Source:   "lsass",
	}

	if c.Type != "password" {
		t.Errorf("Type = %q, want %q", c.Type, "password")
	}
	if c.Username != "admin" {
		t.Errorf("Username = %q, want %q", c.Username, "admin")
	}
}

func TestVulnerability(t *testing.T) {
	v := Vulnerability{
		CVE:      "CVE-2024-1234",
		Severity: SeverityCritical,
		Title:    "Test Vuln",
		Exploit:  true,
		CVSS:     9.8,
	}

	if v.Severity != SeverityCritical {
		t.Errorf("Severity = %v, want %v", v.Severity, SeverityCritical)
	}
	if v.CVSS != 9.8 {
		t.Errorf("CVSS = %f, want 9.8", v.CVSS)
	}
}

func TestShellResult(t *testing.T) {
	sr := ShellResult{
		Stdout:   "output",
		Stderr:   "error",
		ExitCode: 0,
	}

	if sr.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", sr.ExitCode)
	}
}

func TestNetworkInterface(t *testing.T) {
	ni := NetworkInterface{
		Name:    "eth0",
		IP:      "10.0.0.1",
		MAC:     "aa:bb:cc:dd:ee:ff",
		Gateway: "10.0.0.1",
		DNS:     []string{"8.8.8.8"},
		IsUp:    true,
	}

	if !ni.IsUp {
		t.Error("IsUp should be true")
	}
	if len(ni.DNS) != 1 {
		t.Errorf("DNS length = %d, want 1", len(ni.DNS))
	}
}
