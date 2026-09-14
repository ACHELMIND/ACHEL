package orchestrator

import (
	"testing"
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

func TestNewOrchestrator(t *testing.T) {
	o := NewOrchestrator(nil)
	if o == nil {
		t.Fatal("expected non-nil orchestrator")
	}
	if o.config == nil {
		t.Fatal("expected non-nil config")
	}
	if o.classifier == nil {
		t.Fatal("expected non-nil classifier")
	}
	if o.dispatcher == nil {
		t.Fatal("expected non-nil dispatcher")
	}
	if o.state == nil {
		t.Fatal("expected non-nil state")
	}
}

func TestOrchestratorStartStop(t *testing.T) {
	o := NewOrchestrator(nil)

	if err := o.Start(); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	if !o.IsRunning() {
		t.Error("expected running")
	}

	if err := o.Start(); err == nil {
		t.Error("expected error on double start")
	}

	o.Stop()
	if o.IsRunning() {
		t.Error("expected not running")
	}
}

func TestOrchestratorConfigDefaults(t *testing.T) {
	config := DefaultOrchestratorConfig()
	if config == nil {
		t.Fatal("expected non-nil config")
	}
	if config.MaxConcurrentTasks != 10 {
		t.Errorf("expected 10 max concurrent tasks, got %d", config.MaxConcurrentTasks)
	}
	if config.TaskTimeout != 5*time.Minute {
		t.Errorf("expected 5m timeout, got %v", config.TaskTimeout)
	}
}

func TestHandleNilIntent(t *testing.T) {
	o := NewOrchestrator(nil)
	_, err := o.HandleIntent(nil)
	if err == nil {
		t.Error("expected error for nil intent")
	}
}

func TestHandleIntentBlock(t *testing.T) {
	o := NewOrchestrator(nil)

	intent := &Intent{
		ID:        "test-1",
		Request:   "destroy everything",
		Category:  "destruction",
		Module:    ModuleDestruction,
		Action:    "destroy",
		RiskLevel: RiskLevelBlock,
		Confidence: 1.0,
		Params:    make(map[string]interface{}),
		Targets:   []string{"all"},
	}

	_, err := o.HandleIntent(intent)
	if err == nil {
		t.Error("expected error for blocked intent")
	}
}

func TestHandleIntentApproval(t *testing.T) {
	o := NewOrchestrator(nil)

	intent := &Intent{
		ID:        "test-2",
		Request:   "scan network",
		Category:  "recon",
		Module:    ModuleCollector,
		Action:    "scan",
		RiskLevel: RiskLevelRequestApproval,
		Confidence: 0.5,
		Params:    make(map[string]interface{}),
		Targets:   []string{"192.168.1.0/24"},
	}

	result, err := o.HandleIntent(intent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
}

func TestRouteToModule(t *testing.T) {
	o := NewOrchestrator(nil)

	result, err := o.RouteToModule("destruction", "encrypt", map[string]interface{}{"path": "/tmp"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if result.Module != ModuleDestruction {
		t.Errorf("expected destruction module, got %s", result.Module)
	}
}

func TestExecuteFireteam(t *testing.T) {
	o := NewOrchestrator(nil)

	targets := []string{"target1", "target2", "target3"}
	results, err := o.ExecuteFireteam(targets, "encrypt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}
}

func TestGetAgentNotFound(t *testing.T) {
	o := NewOrchestrator(nil)
	_, ok := o.GetAgent("nonexistent")
	if ok {
		t.Error("expected not found")
	}
}

func TestListAgentsEmpty(t *testing.T) {
	o := NewOrchestrator(nil)
	agents := o.ListAgents()
	if len(agents) != 0 {
		t.Error("expected no agents")
	}
}

func TestIntentClassifierClassify(t *testing.T) {
	ic := NewIntentClassifier()

	tests := []struct {
		request  string
		expected ModuleType
	}{
		{"drop the database", ModuleDestruction},
		{"encrypt files", ModuleDestruction},
		{"scan the network", ModuleCollector},
		{"extract passwords", ModuleCredential},
		{"install persistence", ModulePersistence},
		{"move laterally", ModuleLateral},
		{"random unknown request", ModuleBrain},
	}

	for _, tt := range tests {
		intent, err := ic.Classify(tt.request)
		if err != nil {
			t.Errorf("Classify(%s) error: %v", tt.request, err)
			continue
		}
		if intent.Module != tt.expected {
			t.Errorf("Classify(%s) module = %s, want %s", tt.request, intent.Module, tt.expected)
		}
	}
}

func TestIntentClassifierEmpty(t *testing.T) {
	ic := NewIntentClassifier()
	_, err := ic.Classify("")
	if err == nil {
		t.Error("expected error for empty request")
	}
}

func TestIntentClassifierSelectAction(t *testing.T) {
	ic := NewIntentClassifier()

	intent := &Intent{
		ID:       "test",
		Module:   ModuleDestruction,
		Action:   "encrypt",
		Targets:  []string{"target1"},
		Params:   make(map[string]interface{}),
	}

	action, err := ic.SelectAction(intent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if action.Target != "target1" {
		t.Errorf("expected target1, got %s", action.Target)
	}
}

func TestIntentClassifierSelectActionNil(t *testing.T) {
	ic := NewIntentClassifier()
	_, err := ic.SelectAction(nil)
	if err == nil {
		t.Error("expected error for nil intent")
	}
}

func TestDispatcherDispatch(t *testing.T) {
	d := NewDispatcher(nil)
	task := &types.Task{
		ID:  "task-1",
		Type: types.TaskTypeShell,
	}

	err := d.Dispatch("agent-1", task)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDispatcherNilTask(t *testing.T) {
	d := NewDispatcher(nil)
	err := d.Dispatch("agent-1", nil)
	if err == nil {
		t.Error("expected error for nil task")
	}
}

func TestDispatcherEmptyAgent(t *testing.T) {
	d := NewDispatcher(nil)
	err := d.Dispatch("", nil)
	if err == nil {
		t.Error("expected error for empty agent")
	}
}

func TestStateManagerSaveLoad(t *testing.T) {
	sm := NewStateManager()

	err := sm.SaveState("key1", "value1")
	if err != nil {
		t.Fatalf("SaveState error: %v", err)
	}

	val, err := sm.LoadState("key1")
	if err != nil {
		t.Fatalf("LoadState error: %v", err)
	}
	if val != "value1" {
		t.Errorf("expected value1, got %v", val)
	}
}

func TestStateManagerLoadNotFound(t *testing.T) {
	sm := NewStateManager()
	_, err := sm.LoadState("nonexistent")
	if err == nil {
		t.Error("expected error for not found")
	}
}

func TestStateManagerListKeys(t *testing.T) {
	sm := NewStateManager()
	sm.SaveState("prefix:key1", "v1")
	sm.SaveState("prefix:key2", "v2")
	sm.SaveState("other:key3", "v3")

	keys := sm.ListKeys("prefix:")
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
}

func TestStateManagerDelete(t *testing.T) {
	sm := NewStateManager()
	sm.SaveState("key1", "value1")

	err := sm.DeleteState("key1")
	if err != nil {
		t.Fatalf("DeleteState error: %v", err)
	}

	_, err = sm.LoadState("key1")
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestStateManagerDeleteNotFound(t *testing.T) {
	sm := NewStateManager()
	err := sm.DeleteState("nonexistent")
	if err == nil {
		t.Error("expected error for not found")
	}
}

func TestStateManagerClear(t *testing.T) {
	sm := NewStateManager()
	sm.SaveState("key1", "v1")
	sm.SaveState("key2", "v2")

	sm.Clear()
	if sm.Count() != 0 {
		t.Error("expected 0 after clear")
	}
}

func TestStateManagerUpdate(t *testing.T) {
	sm := NewStateManager()
	sm.SaveState("key1", "value1")
	sm.SaveState("key1", "value2")

	val, _ := sm.LoadState("key1")
	if val != "value2" {
		t.Errorf("expected value2, got %v", val)
	}
	if sm.Count() != 1 {
		t.Error("expected 1 entry after update")
	}
}

func TestStateManagerEmptyKey(t *testing.T) {
	sm := NewStateManager()
	err := sm.SaveState("", "value")
	if err == nil {
		t.Error("expected error for empty key")
	}
}

func TestFireteamCreate(t *testing.T) {
	ft := CreateFireteam([]string{"agent1", "agent2"})
	if ft.AgentCount() != 2 {
		t.Errorf("expected 2 agents, got %d", ft.AgentCount())
	}
}

func TestFireteamExecute(t *testing.T) {
	ft := CreateFireteam([]string{"agent1"})
	results, err := ft.Execute("test_technique", []string{"target1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}

func TestFireteamWait(t *testing.T) {
	ft := CreateFireteam([]string{"agent1"})
	ft.Execute("test", []string{"target1"})
	results := ft.Wait()
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}

func TestFireteamGetAgents(t *testing.T) {
	ft := CreateFireteam([]string{"a1", "a2", "a3"})
	agents := ft.GetAgents()
	if len(agents) != 3 {
		t.Errorf("expected 3 agents, got %d", len(agents))
	}
}
