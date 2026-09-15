package mcp

import (
	"fmt"
	"testing"
	"time"
)

func TestNewMCPServer(t *testing.T) {
	srv := NewMCPServer(5)
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
	if srv.maxSess != 5 {
		t.Errorf("expected maxSess 5, got %d", srv.maxSess)
	}
}

func TestDefaultToolsRegistered(t *testing.T) {
	srv := NewMCPServer(5)
	tools := srv.ListTools()
	if len(tools) < 10 {
		t.Errorf("expected at least 10 default tools, got %d", len(tools))
	}

	expectedTools := []string{"nmap", "nuclei", "ffuf", "hydra", "metasploit", "playwright", "subfinder", "shodan", "sqlmap", "mimikatz"}
	for _, id := range expectedTools {
		tool, ok := srv.GetTool(id)
		if !ok {
			t.Errorf("expected default tool %s to be registered", id)
			continue
		}
		if tool.ID != id {
			t.Errorf("expected tool ID %s, got %s", id, tool.ID)
		}
		if tool.Timeout <= 0 {
			t.Errorf("expected positive timeout for tool %s", id)
		}
	}
}

func TestRegisterTool(t *testing.T) {
	srv := NewMCPServer(5)
	tool := &Tool{
		ID:          "custom-tool",
		Name:        "Custom Tool",
		Description: "A custom tool",
		Category:    "custom",
		Timeout:     30 * time.Second,
	}

	err := srv.RegisterTool(tool)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, ok := srv.GetTool("custom-tool")
	if !ok {
		t.Fatal("expected custom tool to be registered")
	}
	if got.Name != "Custom Tool" {
		t.Errorf("expected name 'Custom Tool', got %q", got.Name)
	}
}

func TestRegisterTool_Duplicate(t *testing.T) {
	srv := NewMCPServer(5)
	tool := &Tool{ID: "nmap", Name: "Duplicate", Timeout: 10 * time.Second}
	err := srv.RegisterTool(tool)
	if err == nil {
		t.Fatal("expected error for duplicate tool registration")
	}
}

func TestExecuteTool_WithFunc(t *testing.T) {
	srv := NewMCPServer(5)
	called := false
	srv.RegisterTool(&Tool{
		ID:   "test-tool",
		Name: "Test Tool",
		Execute: func(params map[string]interface{}) (*ToolResult, error) {
			called = true
			return &ToolResult{
				Success: true,
				Data:    map[string]interface{}{"result": "ok"},
			}, nil
		},
		Timeout: 10 * time.Second,
	})

	result, err := srv.ExecuteTool("test-tool", map[string]interface{}{"arg1": "val1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("expected Execute function to be called")
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.Data["result"] != "ok" {
		t.Errorf("expected result 'ok', got %v", result.Data["result"])
	}
}

func TestExecuteTool_WithFunc_Error(t *testing.T) {
	srv := NewMCPServer(5)
	srv.RegisterTool(&Tool{
		ID:   "fail-tool",
		Name: "Fail Tool",
		Execute: func(params map[string]interface{}) (*ToolResult, error) {
			return nil, fmt.Errorf("tool failed")
		},
		Timeout: 10 * time.Second,
	})

	result, err := srv.ExecuteTool("fail-tool", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("expected failure")
	}
	if result.Error != "tool failed" {
		t.Errorf("expected error 'tool failed', got %q", result.Error)
	}
}

func TestExecuteTool_NoFunc_Simulated(t *testing.T) {
	srv := NewMCPServer(5)
	// Default tools have no Execute function
	result, err := srv.ExecuteTool("nmap", map[string]interface{}{"target": "10.0.0.1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for simulated tool")
	}
	if result.Data["status"] != "simulated" {
		t.Errorf("expected status 'simulated', got %v", result.Data["status"])
	}
	if result.Data["tool"] != "nmap" {
		t.Errorf("expected tool 'nmap', got %v", result.Data["tool"])
	}
	if result.Duration <= 0 {
		t.Error("expected positive duration")
	}
}

func TestExecuteTool_NotFound(t *testing.T) {
	srv := NewMCPServer(5)
	result, err := srv.ExecuteTool("nonexistent", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent tool")
	}
	if result != nil {
		t.Error("expected nil result for nonexistent tool")
	}
}

func TestCreateSession(t *testing.T) {
	srv := NewMCPServer(5)
	session, err := srv.CreateSession("sess1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session.ID != "sess1" {
		t.Errorf("expected session ID 'sess1', got %q", session.ID)
	}
	if session.Status != "active" {
		t.Errorf("expected status 'active', got %q", session.Status)
	}
	if session.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}
}

func TestCreateSession_MaxReached(t *testing.T) {
	srv := NewMCPServer(1)
	srv.CreateSession("s1")
	_, err := srv.CreateSession("s2")
	if err == nil {
		t.Fatal("expected error when max sessions reached")
	}
}

func TestCloseSession(t *testing.T) {
	srv := NewMCPServer(5)
	srv.CreateSession("sess1")

	err := srv.CloseSession("sess1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Session should be removed
	status := srv.GetStatus()
	if status["active_sessions"] != 0 {
		t.Errorf("expected 0 active sessions after close, got %v", status["active_sessions"])
	}
}

func TestCloseSession_NotFound(t *testing.T) {
	srv := NewMCPServer(5)
	err := srv.CloseSession("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent session")
	}
}

func TestListTools(t *testing.T) {
	srv := NewMCPServer(5)
	tools := srv.ListTools()
	if len(tools) == 0 {
		t.Error("expected non-empty tool list")
	}

	// Verify no nil tools
	for _, tool := range tools {
		if tool == nil {
			t.Error("expected non-nil tool in list")
		}
	}
}

func TestGetStatus(t *testing.T) {
	srv := NewMCPServer(3)
	srv.CreateSession("s1")

	status := srv.GetStatus()
	if status["total_tools"] != 10 {
		t.Errorf("expected 10 total tools, got %v", status["total_tools"])
	}
	if status["active_sessions"] != 1 {
		t.Errorf("expected 1 active session, got %v", status["active_sessions"])
	}
	if status["max_sessions"] != 3 {
		t.Errorf("expected max_sessions 3, got %v", status["max_sessions"])
	}
}

func TestToolResult_Fields(t *testing.T) {
	start := time.Now()
	result := &ToolResult{
		Success:  true,
		Data:     map[string]interface{}{"key": "val"},
		Error:    "",
		Duration: time.Since(start),
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.Data["key"] != "val" {
		t.Error("expected data")
	}
}

func TestSession_Fields(t *testing.T) {
	now := time.Now()
	session := &Session{
		ID:        "test",
		Tools:     []string{"nmap", "nuclei"},
		CreatedAt: now,
		LastUsed:  now,
		Status:    "active",
	}
	if session.ID != "test" {
		t.Error("expected ID")
	}
	if len(session.Tools) != 2 {
		t.Error("expected 2 tools")
	}
}

func TestDefaultTools_Categories(t *testing.T) {
	srv := NewMCPServer(5)
	tools := srv.ListTools()
	categories := make(map[string]bool)
	for _, tool := range tools {
		if tool.Category != "" {
			categories[tool.Category] = true
		}
	}
	expectedCategories := []string{"recon", "exploit", "credential"}
	for _, cat := range expectedCategories {
		if !categories[cat] {
			t.Errorf("expected category %q to exist", cat)
		}
	}
}
