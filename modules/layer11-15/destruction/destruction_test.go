package destruction

import (
	"testing"
	"time"
)

func TestNewDestructionEngine(t *testing.T) {
	config := DefaultDestructionConfig()
	engine := NewDestructionEngine(config)
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	if engine.config != config {
		t.Error("expected config to match")
	}
}

func TestNewDestructionEngineNilConfig(t *testing.T) {
	engine := NewDestructionEngine(nil)
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	if engine.config == nil {
		t.Fatal("expected non-nil default config")
	}
}

func TestDestructionConfigDefaults(t *testing.T) {
	config := DefaultDestructionConfig()
	if config == nil {
		t.Fatal("expected non-nil config")
	}
	if config.MaxParallel != 1 {
		t.Errorf("expected max parallel 1, got %d", config.MaxParallel)
	}
	if !config.DryRun {
		t.Error("expected dry run to be true")
	}
	if config.Timeout != 60*time.Second {
		t.Errorf("expected timeout 60s, got %v", config.Timeout)
	}
}

func TestExecuteChainEmpty(t *testing.T) {
	engine := NewDestructionEngine(nil)
	chain := &DestructionChain{
		Steps:        []DestructionStep{},
		Sequential:   true,
		BreakOnError: true,
	}

	result, err := engine.ExecuteChain(chain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
}

func TestExecuteChainDryRun(t *testing.T) {
	engine := NewDestructionEngine(nil)
	chain := &DestructionChain{
		Steps: []DestructionStep{
			{Method: MethodZeroOverwrite, Target: "/tmp/test"},
		},
		Sequential: true,
	}

	result, err := engine.ExecuteChain(chain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success in dry run")
	}
}

func TestExecuteChainUnknownMethod(t *testing.T) {
	engine := NewDestructionEngine(nil)
	chain := &DestructionChain{
		Steps: []DestructionStep{
			{Method: "unknown_method", Target: "test"},
		},
		BreakOnError: true,
	}

	result, err := engine.ExecuteChain(chain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("expected failure for unknown method")
	}
}

func TestDamageLevelString(t *testing.T) {
	tests := []struct {
		level    DamageLevel
		expected string
	}{
		{DamageLevelNone, "none"},
		{DamageLevelLow, "low"},
		{DamageLevelMedium, "medium"},
		{DamageLevelHigh, "high"},
		{DamageLevelCritical, "critical"},
		{DamageLevel(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.level.String(); got != tt.expected {
			t.Errorf("DamageLevel(%d).String() = %s, want %s", tt.level, got, tt.expected)
		}
	}
}

func TestBlastRadiusCalculation(t *testing.T) {
	engine := NewDestructionEngine(nil)

	tests := []struct {
		target   string
		expected DamageLevel
	}{
		{"database", DamageLevelCritical},
		{"files", DamageLevelHigh},
		{"disk", DamageLevelCritical},
		{"system", DamageLevelCritical},
		{"unknown", DamageLevelHigh},
	}

	for _, tt := range tests {
		radius, err := engine.CalculateBlastRadius(tt.target)
		if err != nil {
			t.Errorf("CalculateBlastRadius(%s) error: %v", tt.target, err)
			continue
		}
		if radius.PrimaryDamage != tt.expected {
			t.Errorf("CalculateBlastRadius(%s) primary damage = %v, want %v", tt.target, radius.PrimaryDamage, tt.expected)
		}
		if radius.Target != tt.target {
			t.Errorf("CalculateBlastRadius(%s) target = %s", tt.target, radius.Target)
		}
	}
}

func TestEstimateRecoveryTime(t *testing.T) {
	engine := NewDestructionEngine(nil)

	tests := []struct {
		damage   DamageLevel
		expected time.Duration
	}{
		{DamageLevelNone, 0},
		{DamageLevelLow, 1 * time.Hour},
		{DamageLevelMedium, 12 * time.Hour},
		{DamageLevelHigh, 48 * time.Hour},
		{DamageLevelCritical, 168 * time.Hour},
	}

	for _, tt := range tests {
		got := engine.EstimateRecoveryTime(tt.damage)
		if got != tt.expected {
			t.Errorf("EstimateRecoveryTime(%v) = %v, want %v", tt.damage, got, tt.expected)
		}
	}
}

func TestScoreP0P1(t *testing.T) {
	engine := NewDestructionEngine(nil)

	findings := []Finding{
		{ID: "1", Target: "db", Type: "vuln", Severity: 3, Description: "critical"},
		{ID: "2", Target: "fs", Type: "vuln", Severity: 1, Description: "medium"},
		{ID: "3", Target: "net", Type: "vuln", Severity: 0, Description: "low"},
	}

	scored := engine.impact.ScoreP0P1(findings)
	if len(scored) != 3 {
		t.Fatalf("expected 3 scored findings, got %d", len(scored))
	}

	if scored[0].Score <= scored[1].Score {
		t.Error("expected findings sorted by score descending")
	}
}

func TestSetDryRun(t *testing.T) {
	engine := NewDestructionEngine(nil)
	engine.SetDryRun(false)
	if engine.GetConfig().DryRun {
		t.Error("expected dry run to be false")
	}
	engine.SetDryRun(true)
	if !engine.GetConfig().DryRun {
		t.Error("expected dry run to be true")
	}
}

func TestGetResults(t *testing.T) {
	engine := NewDestructionEngine(nil)
	results := engine.GetResults()
	if len(results) != 0 {
		t.Error("expected no results initially")
	}
}

func TestDatabaseDestroyerDryRun(t *testing.T) {
	config := DefaultDestructionConfig()
	db := NewDatabaseDestroyer(config)

	methods := []DestructionMethod{
		MethodDatabaseDrop,
		MethodFKDrop,
		MethodCorruptData,
		MethodDeleteBackup,
		MethodDisableRecovery,
	}

	for _, m := range methods {
		result, err := db.Execute(m, "test", nil)
		if err != nil {
			t.Errorf("Execute(%s) error: %v", m, err)
		}
		if !result.Success {
			t.Errorf("Execute(%s) expected success", m)
		}
	}
}

func TestRansomwareEngineDryRun(t *testing.T) {
	config := DefaultDestructionConfig()
	re := NewRansomwareEngine(config)

	methods := []DestructionMethod{
		MethodEncryptFiles,
		MethodEncryptDB,
		MethodRansomNote,
		MethodKeyDestroy,
	}

	for _, m := range methods {
		result, err := re.Execute(m, "/tmp/test", nil)
		if err != nil {
			t.Errorf("Execute(%s) error: %v", m, err)
		}
		if !result.Success {
			t.Errorf("Execute(%s) expected success", m)
		}
	}
}

func TestWiperEngineDryRun(t *testing.T) {
	config := DefaultDestructionConfig()
	we := NewWiperEngine(config)

	methods := []DestructionMethod{
		MethodZeroOverwrite,
		MethodRandomOverwrite,
		MethodMBRDestroy,
		MethodMFTDestroy,
		MethodVolumeDismount,
		MethodRestorePtDelete,
		MethodUSNJournalClear,
	}

	for _, m := range methods {
		result, err := we.Execute(m, "/tmp/test", nil)
		if err != nil {
			t.Errorf("Execute(%s) error: %v", m, err)
		}
		if !result.Success {
			t.Errorf("Execute(%s) expected success", m)
		}
	}
}

func TestImpactAssessorRecoveryTimes(t *testing.T) {
	ia := NewImpactAssessor()

	if ia.EstimateRecoveryTime(DamageLevelNone) != 0 {
		t.Error("expected 0 for none")
	}
	if ia.EstimateRecoveryTime(DamageLevelLow) != 1*time.Hour {
		t.Error("expected 1h for low")
	}
}

func TestImpactAssessorBlastRadiusPaths(t *testing.T) {
	ia := NewImpactAssessor()

	radius, err := ia.CalculateBlastRadius("disk")
	if err != nil {
		t.Fatal(err)
	}
	if radius.PrimaryDamage != DamageLevelCritical {
		t.Error("expected critical for disk")
	}
	if len(radius.AffectedData) < 2 {
		t.Error("expected affected data")
	}
}
