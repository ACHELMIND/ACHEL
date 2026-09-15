package destructionchain

import (
	"testing"
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

func TestNewDestructionChainEngine(t *testing.T) {
	engine := NewDestructionChainEngine(nil)
	if engine == nil {
		t.Fatal("engine is nil")
	}
	if engine.config == nil {
		t.Fatal("config is nil")
	}
	if engine.orchestrator == nil {
		t.Fatal("orchestrator is nil")
	}
	if engine.timing == nil {
		t.Fatal("timing is nil")
	}
}

func TestDestructionChainEngine_FullScopeAttack(t *testing.T) {
	engine := NewDestructionChainEngine(nil)

	target := &FullScopeTarget{
		Host: "192.168.1.100",
		IP:   "192.168.1.100",
		OS:   types.PlatformWindows,
		Arch: "x64",
		Vulns: []types.Vulnerability{
			{
				CVE:      "CVE-2024-0001",
				Severity: types.SeverityHigh,
				Title:    "Test Vuln",
			},
		},
	}

	result, err := engine.FullScopeAttack(target)
	if err != nil {
		t.Fatalf("FullScopeAttack failed: %v", err)
	}

	if result == nil {
		t.Fatal("result is nil")
	}
	if result.Target != target {
		t.Error("target mismatch")
	}
	if result.Recon == nil {
		t.Error("recon is nil")
	}
	if result.Attack == nil {
		t.Error("attack is nil")
	}
	if result.Destroy == nil {
		t.Error("destroy is nil")
	}
	if result.Report == nil {
		t.Error("report is nil")
	}
}

func TestDestructionChainEngine_FullScopeAttack_NilTarget(t *testing.T) {
	engine := NewDestructionChainEngine(nil)
	_, err := engine.FullScopeAttack(nil)
	if err == nil {
		t.Fatal("expected error for nil target")
	}
}

func TestDestructionChainEngine_ExecuteChain(t *testing.T) {
	engine := NewDestructionChainEngine(nil)

	steps := []ChainStep{
		{
			Type: StepTypeRecon,
			Name: "Recon Step",
		},
		{
			Type: StepTypeScan,
			Name: "Scan Step",
		},
		{
			Type: StepTypeExploit,
			Name: "Exploit Step",
		},
	}

	chain := engine.orchestrator.BuildChain(steps)

	result, err := engine.ExecuteChain(chain)
	if err != nil {
		t.Fatalf("ExecuteChain failed: %v", err)
	}

	if result == nil {
		t.Fatal("result is nil")
	}
	if !result.Success {
		t.Error("expected success")
	}
	if len(result.Results) != 3 {
		t.Errorf("expected 3 results, got %d", len(result.Results))
	}
}

func TestDestructionChainEngine_CalculateImpact(t *testing.T) {
	engine := NewDestructionChainEngine(nil)

	report, err := engine.CalculateImpact("192.168.1.100")
	if err != nil {
		t.Fatalf("CalculateImpact failed: %v", err)
	}

	if report == nil {
		t.Fatal("report is nil")
	}
	if report.Target != "192.168.1.100" {
		t.Error("target mismatch")
	}
	if report.AffectedHosts != 1 {
		t.Error("expected 1 affected host")
	}
}

func TestDestructionChainEngine_CalculateImpact_EmptyTarget(t *testing.T) {
	engine := NewDestructionChainEngine(nil)
	_, err := engine.CalculateImpact("")
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

func TestDestructionChainEngine_EstimateCompletionTime(t *testing.T) {
	engine := NewDestructionChainEngine(nil)

	chain := &DestructionChain{
		Steps: []ChainStep{
			{Type: StepTypeRecon, Name: "Recon"},
			{Type: StepTypeExploit, Name: "Exploit"},
		},
	}

	est := engine.EstimateCompletionTime(chain)
	if est == 0 {
		t.Error("expected non-zero estimate")
	}
}

func TestDestructionChainEngine_EstimateCompletionTime_NilChain(t *testing.T) {
	engine := NewDestructionChainEngine(nil)
	est := engine.EstimateCompletionTime(nil)
	if est != 0 {
		t.Error("expected zero for nil chain")
	}
}

func TestNewChainOrchestrator(t *testing.T) {
	orch := NewChainOrchestrator(nil, nil, nil)
	if orch == nil {
		t.Fatal("orchestrator is nil")
	}
	if orch.config == nil {
		t.Fatal("config is nil")
	}
	if orch.timing == nil {
		t.Fatal("timing is nil")
	}
}

func TestChainOrchestrator_BuildChain(t *testing.T) {
	orch := NewChainOrchestrator(nil, nil, nil)

	steps := []ChainStep{
		{Type: StepTypeRecon, Name: "Recon"},
		{Type: StepTypeExploit, Name: "Exploit"},
	}

	chain := orch.BuildChain(steps)
	if chain == nil {
		t.Fatal("chain is nil")
	}
	if chain.ID == "" {
		t.Error("chain ID is empty")
	}
	if len(chain.Steps) != 2 {
		t.Errorf("expected 2 steps, got %d", len(chain.Steps))
	}
	if chain.Status != ChainStatusPending {
		t.Errorf("expected pending status, got %s", chain.Status)
	}
}

func TestChainOrchestrator_ExecuteStep(t *testing.T) {
	orch := NewChainOrchestrator(nil, nil, nil)

	step := &ChainStep{
		ID:   "test-step",
		Type: StepTypeRecon,
		Name: "Test Recon",
	}

	result, err := orch.ExecuteStep(step)
	if err != nil {
		t.Fatalf("ExecuteStep failed: %v", err)
	}

	if result == nil {
		t.Fatal("result is nil")
	}
	if !result.Success {
		t.Error("expected success")
	}
	if step.Status != StepStatusCompleted {
		t.Errorf("expected completed status, got %s", step.Status)
	}
}

func TestChainOrchestrator_ExecuteStep_NilStep(t *testing.T) {
	orch := NewChainOrchestrator(nil, nil, nil)
	_, err := orch.ExecuteStep(nil)
	if err == nil {
		t.Fatal("expected error for nil step")
	}
}

func TestChainOrchestrator_ExecuteStep_UnknownType(t *testing.T) {
	orch := NewChainOrchestrator(nil, nil, nil)

	step := &ChainStep{
		ID:   "test-step",
		Type: StepType("unknown"),
		Name: "Unknown Step",
	}

	_, err := orch.ExecuteStep(step)
	if err == nil {
		t.Fatal("expected error for unknown step type")
	}
}

func TestChainOrchestrator_PauseResumeAbortChain(t *testing.T) {
	orch := NewChainOrchestrator(nil, nil, nil)

	steps := []ChainStep{
		{Type: StepTypeRecon, Name: "Recon"},
	}
	chain := orch.BuildChain(steps)
	chain.Status = ChainStatusRunning

	err := orch.PauseChain(chain.ID)
	if err != nil {
		t.Fatalf("PauseChain failed: %v", err)
	}
	if chain.Status != ChainStatusPaused {
		t.Errorf("expected paused, got %s", chain.Status)
	}

	err = orch.ResumeChain(chain.ID)
	if err != nil {
		t.Fatalf("ResumeChain failed: %v", err)
	}
	if chain.Status != ChainStatusRunning {
		t.Errorf("expected running, got %s", chain.Status)
	}

	err = orch.AbortChain(chain.ID)
	if err != nil {
		t.Fatalf("AbortChain failed: %v", err)
	}
	if chain.Status != ChainStatusAborted {
		t.Errorf("expected aborted, got %s", chain.Status)
	}
}

func TestChainOrchestrator_PauseChain_NotRunning(t *testing.T) {
	orch := NewChainOrchestrator(nil, nil, nil)

	steps := []ChainStep{
		{Type: StepTypeRecon, Name: "Recon"},
	}
	chain := orch.BuildChain(steps)

	err := orch.PauseChain(chain.ID)
	if err == nil {
		t.Fatal("expected error pausing non-running chain")
	}
}

func TestChainOrchestrator_PauseChain_NotFound(t *testing.T) {
	orch := NewChainOrchestrator(nil, nil, nil)
	err := orch.PauseChain("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent chain")
	}
}

func TestChainOrchestrator_ResumeChain_NotPaused(t *testing.T) {
	orch := NewChainOrchestrator(nil, nil, nil)

	steps := []ChainStep{
		{Type: StepTypeRecon, Name: "Recon"},
	}
	chain := orch.BuildChain(steps)
	chain.Status = ChainStatusRunning

	err := orch.ResumeChain(chain.ID)
	if err == nil {
		t.Fatal("expected error resuming non-paused chain")
	}
}

func TestChainOrchestrator_AbortChain_NotFound(t *testing.T) {
	orch := NewChainOrchestrator(nil, nil, nil)
	err := orch.AbortChain("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent chain")
	}
}

func TestNewTimingCoordinator(t *testing.T) {
	tc := NewTimingCoordinator(nil)
	if tc == nil {
		t.Fatal("coordinator is nil")
	}
	if tc.config == nil {
		t.Fatal("config is nil")
	}
}

func TestTimingCoordinator_ScheduleStep(t *testing.T) {
	tc := NewTimingCoordinator(nil)

	step := &ChainStep{
		ID:   "test-step",
		Type: StepTypeRecon,
		Name: "Test",
	}

	err := tc.ScheduleStep(step, 1*time.Second)
	if err != nil {
		t.Fatalf("ScheduleStep failed: %v", err)
	}

	scheduled, ok := tc.schedule[step.ID]
	if !ok {
		t.Fatal("step not scheduled")
	}
	if scheduled.Delay < tc.config.MinDelay {
		t.Error("delay too small")
	}
}

func TestTimingCoordinator_ScheduleStep_NilStep(t *testing.T) {
	tc := NewTimingCoordinator(nil)
	err := tc.ScheduleStep(nil, 1*time.Second)
	if err == nil {
		t.Fatal("expected error for nil step")
	}
}

func TestTimingCoordinator_SyncSteps(t *testing.T) {
	tc := NewTimingCoordinator(nil)

	steps := []ChainStep{
		{ID: "step1", Type: StepTypeRecon, Name: "Step 1"},
		{ID: "step2", Type: StepTypeExploit, Name: "Step 2"},
	}

	err := tc.SyncSteps(steps)
	if err != nil {
		t.Fatalf("SyncSteps failed: %v", err)
	}

	if len(tc.schedule) != 2 {
		t.Errorf("expected 2 scheduled steps, got %d", len(tc.schedule))
	}
}

func TestTimingCoordinator_SyncSteps_Empty(t *testing.T) {
	tc := NewTimingCoordinator(nil)
	err := tc.SyncSteps([]ChainStep{})
	if err != nil {
		t.Fatalf("SyncSteps failed: %v", err)
	}
}

func TestTimingCoordinator_GetChainProgress(t *testing.T) {
	tc := NewTimingCoordinator(nil)

	progress := tc.GetChainProgress("nonexistent")
	if progress == nil {
		t.Fatal("progress is nil")
	}
	if progress.Status != ChainStatusPending {
		t.Errorf("expected pending, got %s", progress.Status)
	}
}

func TestTimingCoordinator_UpdateProgress(t *testing.T) {
	tc := NewTimingCoordinator(nil)

	progress := &ChainProgress{
		ChainID:    "test-chain",
		Status:     ChainStatusRunning,
		TotalSteps: 5,
	}
	tc.UpdateProgress("test-chain", progress)

	got := tc.GetChainProgress("test-chain")
	if got.ChainID != "test-chain" {
		t.Error("chain ID mismatch")
	}
	if got.Status != ChainStatusRunning {
		t.Error("status mismatch")
	}
}

func TestTimingCoordinator_CalculateETA(t *testing.T) {
	tc := NewTimingCoordinator(nil)

	eta := tc.CalculateETA(10, 2, 1*time.Minute)
	if eta != 8*time.Minute {
		t.Errorf("expected 8m, got %v", eta)
	}

	eta = tc.CalculateETA(10, 0, 1*time.Minute)
	if eta != 0 {
		t.Error("expected 0 for zero completed")
	}

	eta = tc.CalculateETA(0, 0, 1*time.Minute)
	if eta != 0 {
		t.Error("expected 0 for zero total")
	}
}

func TestTimingCoordinator_ShouldSync(t *testing.T) {
	tc := NewTimingCoordinator(nil)
	if !tc.ShouldSync() {
		t.Error("expected sync enabled by default")
	}
}

func TestTimingCoordinator_GetDelayForStep(t *testing.T) {
	tc := NewTimingCoordinator(nil)

	delay1 := tc.GetDelayForStep(0, 5)
	delay2 := tc.GetDelayForStep(1, 5)

	if delay1 < tc.config.MinDelay {
		t.Error("delay1 too small")
	}
	if delay2 < tc.config.MinDelay {
		t.Error("delay2 too small")
	}
}

func TestStepTypes(t *testing.T) {
	types := []StepType{
		StepTypeRecon, StepTypeScan, StepTypeExploit,
		StepTypePivot, StepTypeEscalate, StepTypeExfil,
		StepTypeDestroy, StepTypeCleanup, StepTypeReport,
	}
	if len(types) != 9 {
		t.Errorf("expected 9 step types, got %d", len(types))
	}
}

func TestChainStatuses(t *testing.T) {
	statuses := []ChainStatus{
		ChainStatusPending, ChainStatusRunning, ChainStatusPaused,
		ChainStatusCompleted, ChainStatusFailed, ChainStatusAborted,
	}
	if len(statuses) != 6 {
		t.Errorf("expected 6 chain statuses, got %d", len(statuses))
	}
}

func TestStepStatuses(t *testing.T) {
	statuses := []StepStatus{
		StepStatusPending, StepStatusRunning, StepStatusCompleted,
		StepStatusFailed, StepStatusSkipped,
	}
	if len(statuses) != 5 {
		t.Errorf("expected 5 step statuses, got %d", len(statuses))
	}
}

func TestNewDefaultChainConfig(t *testing.T) {
	config := NewDefaultChainConfig()
	if config == nil {
		t.Fatal("config is nil")
	}
	if config.MaxConcurrentSteps != 1 {
		t.Error("expected 1 max concurrent steps")
	}
	if config.DefaultTimeout != 30*time.Minute {
		t.Error("expected 30m default timeout")
	}
	if config.MaxRetries != 3 {
		t.Error("expected 3 max retries")
	}
}

func TestNewDefaultTimingConfig(t *testing.T) {
	config := NewDefaultTimingConfig()
	if config == nil {
		t.Fatal("config is nil")
	}
	if config.MinDelay != 100*time.Millisecond {
		t.Error("expected 100ms min delay")
	}
	if config.MaxDelay != 5*time.Second {
		t.Error("expected 5s max delay")
	}
}
