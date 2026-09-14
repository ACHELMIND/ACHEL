package c2server

import (
	"encoding/json"
	"testing"

	"github.com/angel-platform/angel/pkg/types"
)

func TestNewTeamserver(t *testing.T) {
	config := DefaultConfig()
	ts, err := NewTeamserver(config)
	if err != nil {
		t.Fatalf("Failed to create teamserver: %v", err)
	}
	if ts == nil {
		t.Fatal("Expected non-nil teamserver")
	}
	if ts.IsRunning() {
		t.Error("Expected teamserver to not be running")
	}
}

func TestTeamserverInvalidConfig(t *testing.T) {
	config := &TeamserverConfig{}
	_, err := NewTeamserver(config)
	if err == nil {
		t.Error("Expected error for invalid config")
	}
}

func TestTeamserverStartStop(t *testing.T) {
	config := DefaultConfig()
	config.BindPort = 18443
	ts, err := NewTeamserver(config)
	if err != nil {
		t.Fatalf("Failed to create teamserver: %v", err)
	}
	if err := ts.Start(); err != nil {
		t.Fatalf("Failed to start teamserver: %v", err)
	}
	if !ts.IsRunning() {
		t.Error("Expected teamserver to be running")
	}
	ts.Stop()
	if ts.IsRunning() {
		t.Error("Expected teamserver to be stopped")
	}
}

func TestHandleRegistration(t *testing.T) {
	config := DefaultConfig()
	ts, err := NewTeamserver(config)
	if err != nil {
		t.Fatalf("Failed to create teamserver: %v", err)
	}
	agentInfo := map[string]string{
		"hostname": "test-host",
		"ip":       "192.168.1.100",
		"os":       "linux",
		"arch":     "amd64",
		"user":     "root",
		"process":  "bash",
	}
	data, _ := json.Marshal(agentInfo)
	agent, err := ts.HandleRegistration(data)
	if err != nil {
		t.Fatalf("Failed to handle registration: %v", err)
	}
	if agent.Hostname != "test-host" {
		t.Errorf("Expected hostname test-host, got %s", agent.Hostname)
	}
	if agent.IP != "192.168.1.100" {
		t.Errorf("Expected IP 192.168.1.100, got %s", agent.IP)
	}
	if agent.OS != types.PlatformLinux {
		t.Errorf("Expected OS linux, got %s", agent.OS)
	}
}

func TestHandleCheckIn(t *testing.T) {
	config := DefaultConfig()
	ts, err := NewTeamserver(config)
	if err != nil {
		t.Fatalf("Failed to create teamserver: %v", err)
	}
	agentInfo := map[string]string{
		"hostname": "test-host",
		"ip":       "192.168.1.100",
		"os":       "linux",
		"arch":     "amd64",
		"user":     "root",
		"process":  "bash",
	}
	data, _ := json.Marshal(agentInfo)
	agent, err := ts.HandleRegistration(data)
	if err != nil {
		t.Fatalf("Failed to handle registration: %v", err)
	}
	task, err := ts.HandleCheckIn(agent.ID)
	if err != nil {
		t.Fatalf("Failed to handle checkin: %v", err)
	}
	if task != nil {
		t.Errorf("Expected nil task, got %v", task)
	}
}

func TestHandleCheckInUnknownAgent(t *testing.T) {
	config := DefaultConfig()
	ts, err := NewTeamserver(config)
	if err != nil {
		t.Fatalf("Failed to create teamserver: %v", err)
	}
	_, err = ts.HandleCheckIn("unknown-agent")
	if err == nil {
		t.Error("Expected error for unknown agent")
	}
}

func TestSendTask(t *testing.T) {
	config := DefaultConfig()
	ts, err := NewTeamserver(config)
	if err != nil {
		t.Fatalf("Failed to create teamserver: %v", err)
	}
	agentInfo := map[string]string{
		"hostname": "test-host",
		"ip":       "192.168.1.100",
		"os":       "linux",
		"arch":     "amd64",
		"user":     "root",
		"process":  "bash",
	}
	data, _ := json.Marshal(agentInfo)
	agent, err := ts.HandleRegistration(data)
	if err != nil {
		t.Fatalf("Failed to handle registration: %v", err)
	}
	task := &types.Task{
		ID:      "task-1",
		Type:    types.TaskTypeShell,
		Payload: []byte("ls -la"),
	}
	if err := ts.SendTask(agent.ID, task); err != nil {
		t.Fatalf("Failed to send task: %v", err)
	}
	received, err := ts.HandleCheckIn(agent.ID)
	if err != nil {
		t.Fatalf("Failed to handle checkin: %v", err)
	}
	if received == nil {
		t.Fatal("Expected task, got nil")
	}
	if received.ID != "task-1" {
		t.Errorf("Expected task-1, got %s", received.ID)
	}
}

func TestSendTaskUnknownAgent(t *testing.T) {
	config := DefaultConfig()
	ts, err := NewTeamserver(config)
	if err != nil {
		t.Fatalf("Failed to create teamserver: %v", err)
	}
	task := &types.Task{
		ID:   "task-1",
		Type: types.TaskTypeShell,
	}
	if err := ts.SendTask("unknown-agent", task); err == nil {
		t.Error("Expected error for unknown agent")
	}
}

func TestHandleResult(t *testing.T) {
	config := DefaultConfig()
	ts, err := NewTeamserver(config)
	if err != nil {
		t.Fatalf("Failed to create teamserver: %v", err)
	}
	agentInfo := map[string]string{
		"hostname": "test-host",
		"ip":       "192.168.1.100",
		"os":       "linux",
		"arch":     "amd64",
		"user":     "root",
		"process":  "bash",
	}
	data, _ := json.Marshal(agentInfo)
	agent, err := ts.HandleRegistration(data)
	if err != nil {
		t.Fatalf("Failed to handle registration: %v", err)
	}
	task := &types.Task{
		ID:      "task-1",
		Type:    types.TaskTypeShell,
		Payload: []byte("ls -la"),
	}
	if err := ts.SendTask(agent.ID, task); err != nil {
		t.Fatalf("Failed to send task: %v", err)
	}
	if err := ts.HandleResult(agent.ID, "task-1", []byte("result data")); err != nil {
		t.Fatalf("Failed to handle result: %v", err)
	}
}

func TestHandleResultUnknownAgent(t *testing.T) {
	config := DefaultConfig()
	ts, err := NewTeamserver(config)
	if err != nil {
		t.Fatalf("Failed to create teamserver: %v", err)
	}
	if err := ts.HandleResult("unknown-agent", "task-1", []byte("result")); err == nil {
		t.Error("Expected error for unknown agent")
	}
}

func TestGetAgent(t *testing.T) {
	config := DefaultConfig()
	ts, err := NewTeamserver(config)
	if err != nil {
		t.Fatalf("Failed to create teamserver: %v", err)
	}
	agentInfo := map[string]string{
		"hostname": "test-host",
		"ip":       "192.168.1.100",
		"os":       "linux",
		"arch":     "amd64",
		"user":     "root",
		"process":  "bash",
	}
	data, _ := json.Marshal(agentInfo)
	agent, err := ts.HandleRegistration(data)
	if err != nil {
		t.Fatalf("Failed to handle registration: %v", err)
	}
	got, exists := ts.GetAgent(agent.ID)
	if !exists {
		t.Error("Expected agent to exist")
	}
	if got.Hostname != "test-host" {
		t.Errorf("Expected hostname test-host, got %s", got.Hostname)
	}
	_, exists = ts.GetAgent("nonexistent")
	if exists {
		t.Error("Expected agent to not exist")
	}
}

func TestGetAllAgents(t *testing.T) {
	config := DefaultConfig()
	ts, err := NewTeamserver(config)
	if err != nil {
		t.Fatalf("Failed to create teamserver: %v", err)
	}
	agents := ts.GetAllAgents()
	if len(agents) != 0 {
		t.Errorf("Expected 0 agents, got %d", len(agents))
	}
	agentInfo := map[string]string{
		"hostname": "test-host",
		"ip":       "192.168.1.100",
		"os":       "linux",
		"arch":     "amd64",
		"user":     "root",
		"process":  "bash",
	}
	data, _ := json.Marshal(agentInfo)
	_, err = ts.HandleRegistration(data)
	if err != nil {
		t.Fatalf("Failed to handle registration: %v", err)
	}
	agents = ts.GetAllAgents()
	if len(agents) != 1 {
		t.Errorf("Expected 1 agent, got %d", len(agents))
	}
}

func TestTeamserverAccessors(t *testing.T) {
	config := DefaultConfig()
	ts, err := NewTeamserver(config)
	if err != nil {
		t.Fatalf("Failed to create teamserver: %v", err)
	}
	if ts.GetTaskQueue() == nil {
		t.Error("Expected non-nil task queue")
	}
	if ts.GetListenerManager() == nil {
		t.Error("Expected non-nil listener manager")
	}
	if ts.GetEventBus() == nil {
		t.Error("Expected non-nil event bus")
	}
	if ts.GetCrypto() == nil {
		t.Error("Expected non-nil crypto")
	}
}

func TestMaxAgentsLimit(t *testing.T) {
	config := DefaultConfig()
	config.MaxAgents = 1
	ts, err := NewTeamserver(config)
	if err != nil {
		t.Fatalf("Failed to create teamserver: %v", err)
	}
	agentInfo1 := map[string]string{
		"hostname": "host1",
		"ip":       "192.168.1.1",
		"os":       "linux",
		"arch":     "amd64",
		"user":     "root",
		"process":  "bash",
	}
	data1, _ := json.Marshal(agentInfo1)
	_, err = ts.HandleRegistration(data1)
	if err != nil {
		t.Fatalf("Failed to register first agent: %v", err)
	}
	agentInfo2 := map[string]string{
		"hostname": "host2",
		"ip":       "192.168.1.2",
		"os":       "linux",
		"arch":     "amd64",
		"user":     "root",
		"process":  "bash",
	}
	data2, _ := json.Marshal(agentInfo2)
	_, err = ts.HandleRegistration(data2)
	if err == nil {
		t.Error("Expected error when max agents reached")
	}
}
