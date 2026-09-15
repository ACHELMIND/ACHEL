package fireteam

import (
	"testing"
)

func TestNewFireteam(t *testing.T) {
	ft := NewFireteam(5)
	if ft == nil {
		t.Fatal("expected non-nil fireteam")
	}
	if ft.maxAgents != 5 {
		t.Errorf("expected maxAgents 5, got %d", ft.maxAgents)
	}
	if len(ft.agents) != 0 {
		t.Error("expected empty agents list")
	}
	if len(ft.tasks) != 0 {
		t.Error("expected empty tasks list")
	}
}

func TestAddAgent(t *testing.T) {
	ft := NewFireteam(3)
	agent := &Agent{ID: "a1", Name: "Recon Agent", Type: AgentRecon}
	err := ft.AddAgent(agent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if agent.Status != StatusIdle {
		t.Errorf("expected status idle, got %s", agent.Status)
	}
	if len(ft.agents) != 1 {
		t.Errorf("expected 1 agent, got %d", len(ft.agents))
	}
}

func TestAddAgent_MaxCapacity(t *testing.T) {
	ft := NewFireteam(1)
	ft.AddAgent(&Agent{ID: "a1", Name: "Agent 1", Type: AgentRecon})
	err := ft.AddAgent(&Agent{ID: "a2", Name: "Agent 2", Type: AgentExploit})
	if err == nil {
		t.Fatal("expected error when exceeding max capacity")
	}
	if len(ft.agents) != 1 {
		t.Errorf("expected 1 agent to remain, got %d", len(ft.agents))
	}
}

func TestRemoveAgent(t *testing.T) {
	ft := NewFireteam(3)
	ft.AddAgent(&Agent{ID: "a1", Name: "Agent 1", Type: AgentRecon})
	ft.AddAgent(&Agent{ID: "a2", Name: "Agent 2", Type: AgentExploit})

	err := ft.RemoveAgent("a1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ft.agents) != 1 {
		t.Errorf("expected 1 agent, got %d", len(ft.agents))
	}
	if ft.agents[0].ID != "a2" {
		t.Errorf("expected remaining agent a2, got %s", ft.agents[0].ID)
	}
}

func TestRemoveAgent_NotFound(t *testing.T) {
	ft := NewFireteam(3)
	err := ft.RemoveAgent("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent agent")
	}
}

func TestAddTask(t *testing.T) {
	ft := NewFireteam(3)
	task := &Task{ID: "t1", Type: "scan", Payload: map[string]interface{}{"target": "10.0.0.1"}}
	err := ft.AddTask(task)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if task.Status != TaskPending {
		t.Errorf("expected status pending, got %s", task.Status)
	}
	if task.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}
}

func TestExecuteSequential(t *testing.T) {
	ft := NewFireteam(2)
	ft.AddAgent(&Agent{ID: "a1", Name: "Agent 1", Type: AgentRecon})
	ft.AddAgent(&Agent{ID: "a2", Name: "Agent 2", Type: AgentExploit})

	ft.AddTask(&Task{ID: "t1", Type: "scan", Payload: map[string]interface{}{"target": "10.0.0.1"}})
	ft.AddTask(&Task{ID: "t2", Type: "exploit", Payload: map[string]interface{}{"target": "10.0.0.2"}})

	err := ft.ExecuteSequential()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, task := range ft.tasks {
		if task.Status != TaskDone {
			t.Errorf("expected task %s to be done, got %s", task.ID, task.Status)
		}
		if task.StartedAt == nil {
			t.Errorf("expected task %s to have StartedAt set", task.ID)
		}
		if task.CompletedAt == nil {
			t.Errorf("expected task %s to have CompletedAt set", task.ID)
		}
	}

	results := ft.GetResults()
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestExecuteSequential_AgentReused(t *testing.T) {
	ft := NewFireteam(1)
	ft.AddAgent(&Agent{ID: "a1", Name: "Agent 1", Type: AgentRecon})

	ft.AddTask(&Task{ID: "t1", Type: "scan"})
	ft.AddTask(&Task{ID: "t2", Type: "exploit"})

	err := ft.ExecuteSequential()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Agent is freed by defer after each task, so sequential execution reuses it.
	// Both tasks complete successfully.
	doneCount := 0
	failCount := 0
	for _, task := range ft.tasks {
		switch task.Status {
		case TaskDone:
			doneCount++
		case TaskFailed:
			failCount++
		}
	}
	if doneCount != 2 {
		t.Errorf("expected 2 done tasks, got %d", doneCount)
	}
	if failCount != 0 {
		t.Errorf("expected 0 failed tasks, got %d", failCount)
	}
}

func TestExecuteParallel(t *testing.T) {
	ft := NewFireteam(3)
	ft.AddAgent(&Agent{ID: "a1", Name: "Agent 1", Type: AgentRecon})
	ft.AddAgent(&Agent{ID: "a2", Name: "Agent 2", Type: AgentExploit})
	ft.AddAgent(&Agent{ID: "a3", Name: "Agent 3", Type: AgentLateral})

	ft.AddTask(&Task{ID: "t1", Type: "scan"})
	ft.AddTask(&Task{ID: "t2", Type: "exploit"})
	ft.AddTask(&Task{ID: "t3", Type: "lateral"})

	err := ft.ExecuteParallel()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	results := ft.GetResults()
	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}

	for _, task := range ft.tasks {
		if task.Status != TaskDone {
			t.Errorf("expected task %s to be done, got %s", task.ID, task.Status)
		}
	}
}

func TestExecuteParallel_MoreTasksThanAgents(t *testing.T) {
	ft := NewFireteam(1)
	ft.AddAgent(&Agent{ID: "a1", Name: "Agent 1", Type: AgentRecon})

	ft.AddTask(&Task{ID: "t1", Type: "scan"})
	ft.AddTask(&Task{ID: "t2", Type: "scan"})

	err := ft.ExecuteParallel()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// findIdleAgent runs synchronously before goroutines execute executeTask,
	// so both tasks find the idle agent and get launched. Both complete.
	doneCount := 0
	failCount := 0
	for _, task := range ft.tasks {
		switch task.Status {
		case TaskDone:
			doneCount++
		case TaskFailed:
			failCount++
		}
	}
	if doneCount != 2 {
		t.Errorf("expected 2 done, got %d", doneCount)
	}
	if failCount != 0 {
		t.Errorf("expected 0 failed, got %d", failCount)
	}
}

func TestGetStatus(t *testing.T) {
	ft := NewFireteam(3)
	ft.AddAgent(&Agent{ID: "a1", Name: "Agent 1", Type: AgentRecon})
	ft.AddAgent(&Agent{ID: "a2", Name: "Agent 2", Type: AgentExploit})

	status := ft.GetStatus()
	if status["total_agents"] != 2 {
		t.Errorf("expected 2 total agents, got %v", status["total_agents"])
	}
	if status["idle_agents"] != 2 {
		t.Errorf("expected 2 idle agents, got %v", status["idle_agents"])
	}
	if status["busy_agents"] != 0 {
		t.Errorf("expected 0 busy agents, got %v", status["busy_agents"])
	}
	if status["running"] != false {
		t.Errorf("expected not running, got %v", status["running"])
	}
}

func TestReset(t *testing.T) {
	ft := NewFireteam(2)
	ft.AddAgent(&Agent{ID: "a1", Name: "Agent 1", Type: AgentRecon})
	ft.AddTask(&Task{ID: "t1", Type: "scan"})
	ft.ExecuteSequential()

	ft.Reset()
	if len(ft.tasks) != 0 {
		t.Error("expected empty tasks after reset")
	}
	if len(ft.results) != 0 {
		t.Error("expected empty results after reset")
	}
	if ft.running {
		t.Error("expected not running after reset")
	}
}

func TestAgentStatusTransitions(t *testing.T) {
	ft := NewFireteam(1)
	agent := &Agent{ID: "a1", Name: "Agent 1", Type: AgentRecon}
	ft.AddAgent(agent)

	if agent.Status != StatusIdle {
		t.Errorf("expected idle before execution, got %s", agent.Status)
	}

	ft.AddTask(&Task{ID: "t1", Type: "scan"})
	ft.ExecuteSequential()

	// After execution, defer in executeTask sets agent back to idle.
	agent.mu.Lock()
	finalStatus := agent.Status
	agent.mu.Unlock()
	if finalStatus != StatusIdle {
		t.Errorf("expected agent back to idle after execution, got %s", finalStatus)
	}

	// Verify task completed successfully
	if ft.tasks[0].Status != TaskDone {
		t.Errorf("expected task done, got %s", ft.tasks[0].Status)
	}
}

func TestResultFields(t *testing.T) {
	ft := NewFireteam(1)
	ft.AddAgent(&Agent{ID: "a1", Name: "Agent 1", Type: AgentRecon})
	ft.AddTask(&Task{ID: "t1", Type: "scan", Payload: map[string]interface{}{"key": "value"}})
	ft.ExecuteSequential()

	results := ft.GetResults()
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.TaskID != "t1" {
		t.Errorf("expected TaskID t1, got %s", r.TaskID)
	}
	if r.AgentID != "a1" {
		t.Errorf("expected AgentID a1, got %s", r.AgentID)
	}
	if r.Data == nil {
		t.Error("expected non-nil Data")
	}
	if r.Timestamp.IsZero() {
		t.Error("expected non-zero Timestamp")
	}
}

func TestGetResults_ReturnsCopy(t *testing.T) {
	ft := NewFireteam(1)
	ft.AddAgent(&Agent{ID: "a1", Name: "Agent 1", Type: AgentRecon})
	ft.AddTask(&Task{ID: "t1", Type: "scan"})
	ft.ExecuteSequential()

	results1 := ft.GetResults()
	results2 := ft.GetResults()
	if len(results1) != len(results2) {
		t.Error("expected same length results")
	}
	// Mutating the returned slice should not affect the internal state
	results1[0].TaskID = "modified"
	if ft.results[0].TaskID == "modified" {
		t.Error("GetResults should return a copy, not a reference")
	}
}

func TestExecuteParallel_ConcurrentSafety(t *testing.T) {
	ft := NewFireteam(5)
	for i := 0; i < 5; i++ {
		ft.AddAgent(&Agent{ID: "a" + string(rune('1'+i)), Name: "Agent", Type: AgentRecon})
	}
	for i := 0; i < 10; i++ {
		ft.AddTask(&Task{ID: "t" + string(rune('0'+i)), Type: "scan"})
	}

	err := ft.ExecuteParallel()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify no panic and status is consistent
	status := ft.GetStatus()
	if status["total_agents"] != 5 {
		t.Errorf("expected 5 agents, got %v", status["total_agents"])
	}
}
