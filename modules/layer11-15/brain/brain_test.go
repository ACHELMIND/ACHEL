package brain

import (
	"testing"
)

func TestNewBrain(t *testing.T) {
	config := DefaultBrainConfig()
	b := NewBrain(config)
	if b == nil {
		t.Fatal("expected non-nil brain")
	}
	if b.config != config {
		t.Error("expected config to match")
	}
}

func TestNewBrainNilConfig(t *testing.T) {
	b := NewBrain(nil)
	if b == nil {
		t.Fatal("expected non-nil brain")
	}
	if b.config == nil {
		t.Fatal("expected non-nil default config")
	}
}

func TestBrainConfigDefaults(t *testing.T) {
	config := DefaultBrainConfig()
	if config == nil {
		t.Fatal("expected non-nil config")
	}
	if config.LearningRate != 0.1 {
		t.Errorf("expected learning rate 0.1, got %f", config.LearningRate)
	}
	if config.ExplorationRate != 0.2 {
		t.Errorf("expected exploration rate 0.2, got %f", config.ExplorationRate)
	}
	if config.MaxHistory != 1000 {
		t.Errorf("expected max history 1000, got %d", config.MaxHistory)
	}
}

func TestAnalyzeEnvironmentNil(t *testing.T) {
	b := NewBrain(nil)
	_, err := b.AnalyzeEnvironment(nil)
	if err == nil {
		t.Error("expected error for nil environment")
	}
}

func TestAnalyzeEnvironmentHighThreat(t *testing.T) {
	b := NewBrain(nil)

	env := &EnvironmentState{
		HostCount:   10,
		AgentCount:  5,
		ThreatLevel: 0.9,
	}

	decision, err := b.AnalyzeEnvironment(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action.Type != ActionTypeEvade {
		t.Errorf("expected evade action, got %s", decision.Action.Type)
	}
}

func TestAnalyzeEnvironmentManyHosts(t *testing.T) {
	b := NewBrain(nil)

	env := &EnvironmentState{
		HostCount:   20,
		AgentCount:  2,
		ThreatLevel: 0.3,
	}

	decision, err := b.AnalyzeEnvironment(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action.Type != ActionTypePersist {
		t.Errorf("expected persist action, got %s", decision.Action.Type)
	}
}

func TestAnalyzeEnvironmentWithAgents(t *testing.T) {
	b := NewBrain(nil)

	env := &EnvironmentState{
		HostCount:   5,
		AgentCount:  3,
		ThreatLevel: 0.2,
	}

	decision, err := b.AnalyzeEnvironment(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action.Type != ActionTypeScan {
		t.Errorf("expected scan action, got %s", decision.Action.Type)
	}
}

func TestAnalyzeEnvironmentNoAgents(t *testing.T) {
	b := NewBrain(nil)

	env := &EnvironmentState{
		HostCount:   0,
		AgentCount:  0,
		ThreatLevel: 0.1,
	}

	decision, err := b.AnalyzeEnvironment(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Action.Type != ActionTypeWait {
		t.Errorf("expected wait action, got %s", decision.Action.Type)
	}
}

func TestDecideNextActionNil(t *testing.T) {
	b := NewBrain(nil)
	_, err := b.DecideNextAction(nil)
	if err == nil {
		t.Error("expected error for nil context")
	}
}

func TestDecideNextActionEmpty(t *testing.T) {
	b := NewBrain(nil)

	context := &DecisionContext{
		State:             &EnvironmentState{},
		AvailableActions:  []Action{},
	}

	action, err := b.DecideNextAction(context)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if action.Type != ActionTypeWait {
		t.Errorf("expected wait, got %s", action.Type)
	}
}

func TestDecideNextActionSelectsBest(t *testing.T) {
	b := NewBrain(nil)

	context := &DecisionContext{
		State: &EnvironmentState{ThreatLevel: 0.5},
		AvailableActions: []Action{
			{Type: ActionTypeWait, RiskLevel: 0.1},
			{Type: ActionTypeScan, RiskLevel: 0.3},
			{Type: ActionTypeExploit, RiskLevel: 0.8},
		},
	}

	action, err := b.DecideNextAction(context)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if action == nil {
		t.Fatal("expected non-nil action")
	}
}

func TestLearnFromHistory(t *testing.T) {
	b := NewBrain(nil)

	history := []Outcome{
		{ActionID: "a1", ActionType: ActionTypeScan, Success: true, Impact: 0.5},
		{ActionID: "a2", ActionType: ActionTypeExploit, Success: false, Impact: 0.2},
	}

	b.LearnFromHistory(history)

	result := b.GetHistory()
	if len(result) != 2 {
		t.Errorf("expected 2 history entries, got %d", len(result))
	}
}

func TestGetState(t *testing.T) {
	b := NewBrain(nil)
	state := b.GetState()
	if state == nil {
		t.Fatal("expected non-nil state")
	}
}

func TestRiskAssessorAssessRiskNil(t *testing.T) {
	ra := NewRiskAssessor()
	score := ra.AssessRisk(nil)
	if score == nil {
		t.Fatal("expected non-nil score")
	}
	if score.Overall != 1.0 {
		t.Errorf("expected 1.0 overall, got %f", score.Overall)
	}
}

func TestRiskAssessorAssessRisk(t *testing.T) {
	ra := NewRiskAssessor()

	action := &Action{
		Type:      ActionTypeDestroy,
		Target:    "domain_controller",
		RiskLevel: 0.9,
	}

	score := ra.AssessRisk(action)
	if score == nil {
		t.Fatal("expected non-nil score")
	}
	if score.Overall < 0.5 {
		t.Errorf("expected high overall score, got %f", score.Overall)
	}
}

func TestRiskAssessorCalculateImpact(t *testing.T) {
	ra := NewRiskAssessor()

	tests := []struct {
		target   string
		expected float64
	}{
		{"domain_controller", 0.95},
		{"database", 0.9},
		{"fileserver", 0.7},
		{"workstation", 0.5},
		{"network", 0.8},
		{"self", 0.1},
		{"unknown", 0.5},
	}

	for _, tt := range tests {
		got := ra.CalculateImpact(tt.target)
		if got != tt.expected {
			t.Errorf("CalculateImpact(%s) = %f, want %f", tt.target, got, tt.expected)
		}
	}
}

func TestRiskAssessorCalculateLikelihood(t *testing.T) {
	ra := NewRiskAssessor()

	action := &Action{Type: ActionTypeDestroy}
	got := ra.CalculateLikelihood(action)
	if got != 0.95 {
		t.Errorf("expected 0.95, got %f", got)
	}

	got = ra.CalculateLikelihood(nil)
	if got != 1.0 {
		t.Errorf("expected 1.0 for nil, got %f", got)
	}
}

func TestBehaviorLearnerRecordOutcome(t *testing.T) {
	bl := NewBehaviorLearner(DefaultBrainConfig())

	action := &Action{Type: ActionTypeScan}
	outcome := &Outcome{Success: true, Impact: 0.6}

	bl.RecordOutcome(action, outcome)

	pattern, ok := bl.GetPattern(ActionTypeScan)
	if !ok {
		t.Fatal("expected pattern")
	}
	if pattern.Count != 1 {
		t.Errorf("expected count 1, got %d", pattern.Count)
	}
	if pattern.SuccessRate != 1.0 {
		t.Errorf("expected success rate 1.0, got %f", pattern.SuccessRate)
	}
}

func TestBehaviorLearnerPredictSuccess(t *testing.T) {
	bl := NewBehaviorLearner(DefaultBrainConfig())

	action := &Action{Type: ActionTypeScan}
	got := bl.PredictSuccess(action)
	if got != 0.5 {
		t.Errorf("expected 0.5 for unknown, got %f", got)
	}

	bl.RecordOutcome(action, &Outcome{Success: true, Impact: 0.5})
	got = bl.PredictSuccess(action)
	if got != 1.0 {
		t.Errorf("expected 1.0 after success, got %f", got)
	}
}

func TestBehaviorLearnerPredictSuccessNil(t *testing.T) {
	bl := NewBehaviorLearner(DefaultBrainConfig())
	got := bl.PredictSuccess(nil)
	if got != 0.5 {
		t.Errorf("expected 0.5 for nil, got %f", got)
	}
}

func TestBehaviorLearnerGetRecommendedAction(t *testing.T) {
	bl := NewBehaviorLearner(DefaultBrainConfig())

	context := &DecisionContext{
		AvailableActions: []Action{
			{Type: ActionTypeScan},
			{Type: ActionTypeExploit},
		},
	}

	action := bl.GetRecommendedAction(context)
	if action == nil {
		t.Fatal("expected non-nil action")
	}
}

func TestBehaviorLearnerGetRecommendedActionNil(t *testing.T) {
	bl := NewBehaviorLearner(DefaultBrainConfig())
	action := bl.GetRecommendedAction(nil)
	if action != nil {
		t.Error("expected nil for nil context")
	}
}

func TestBehaviorLearnerGetPatterns(t *testing.T) {
	bl := NewBehaviorLearner(DefaultBrainConfig())
	bl.RecordOutcome(&Action{Type: ActionTypeScan}, &Outcome{Success: true, Impact: 0.5})

	patterns := bl.GetPatterns()
	if len(patterns) != 1 {
		t.Errorf("expected 1 pattern, got %d", len(patterns))
	}
}

func TestBehaviorLearnerRecordOutcomeNil(t *testing.T) {
	bl := NewBehaviorLearner(DefaultBrainConfig())
	bl.RecordOutcome(nil, nil)
	if len(bl.GetPatterns()) != 0 {
		t.Error("expected no patterns for nil input")
	}
}

func TestTimingControllerCalculateDelay(t *testing.T) {
	tc := NewTimingController(DefaultBrainConfig())

	delay := tc.CalculateDelay(0.5)
	if delay < tc.config.MinDelay {
		t.Errorf("delay %v below minimum %v", delay, tc.config.MinDelay)
	}
	if delay > tc.config.MaxDelay {
		t.Errorf("delay %v above maximum %v", delay, tc.config.MaxDelay)
	}
}

func TestTimingControllerCalculateDelayHighRisk(t *testing.T) {
	tc := NewTimingController(DefaultBrainConfig())

	delayLow := tc.CalculateDelay(0.1)
	delayHigh := tc.CalculateDelay(0.9)

	if delayHigh <= delayLow {
		t.Error("expected higher delay for higher risk")
	}
}

func TestTimingControllerAdaptTiming(t *testing.T) {
	tc := NewTimingController(DefaultBrainConfig())

	initialDelay := tc.GetCurrentDelay()

	tc.AdaptTiming(0.9)

	newDelay := tc.GetCurrentDelay()
	if newDelay > initialDelay {
		t.Error("expected lower delay for high success rate")
	}
}

func TestTimingControllerAdaptTimingLowSuccess(t *testing.T) {
	tc := NewTimingController(DefaultBrainConfig())

	tc.AdaptTiming(0.1)

	delay := tc.GetCurrentDelay()
	if delay < tc.config.MinDelay {
		t.Error("delay should not go below minimum")
	}
}

func TestTimingControllerShouldSleep(t *testing.T) {
	tc := NewTimingController(DefaultBrainConfig())

	if tc.ShouldSleep() {
		t.Error("should not sleep initially")
	}

	tc.AdaptTiming(0.1)
	if !tc.ShouldSleep() {
		t.Error("should sleep with low success rate")
	}
}

func TestTimingControllerShouldSleepDisabled(t *testing.T) {
	config := DefaultBrainConfig()
	config.AdaptiveTiming = false
	tc := NewTimingController(config)

	tc.AdaptTiming(0.1)
	if tc.ShouldSleep() {
		t.Error("should not sleep when disabled")
	}
}

func TestTimingControllerGetState(t *testing.T) {
	tc := NewTimingController(DefaultBrainConfig())
	state := tc.GetState()
	if state == nil {
		t.Fatal("expected non-nil state")
	}
	if state.CurrentDelay != tc.config.MinDelay {
		t.Errorf("expected initial delay %v, got %v", tc.config.MinDelay, state.CurrentDelay)
	}
}

func TestTimingControllerRecordSleep(t *testing.T) {
	tc := NewTimingController(DefaultBrainConfig())
	tc.RecordSleep()

	state := tc.GetState()
	if state.SleepCount != 1 {
		t.Errorf("expected sleep count 1, got %d", state.SleepCount)
	}
}

func TestBrainGetConfig(t *testing.T) {
	b := NewBrain(nil)
	config := b.GetConfig()
	if config == nil {
		t.Fatal("expected non-nil config")
	}
}

func TestDecisionConfidence(t *testing.T) {
	tests := []struct {
		level    DecisionConfidence
		expected int
	}{
		{ConfidenceLow, 0},
		{ConfidenceMedium, 1},
		{ConfidenceHigh, 2},
		{ConfidenceCertain, 3},
	}

	for _, tt := range tests {
		if int(tt.level) != tt.expected {
			t.Errorf("ConfidenceLevel(%d) = %d, want %d", tt.level, int(tt.level), tt.expected)
		}
	}
}

func TestActionTypeConstants(t *testing.T) {
	types := []ActionType{
		ActionTypeScan,
		ActionTypeExploit,
		ActionTypePivot,
		ActionTypePersist,
		ActionTypeExfiltrate,
		ActionTypeDestroy,
		ActionTypeEvade,
		ActionTypeWait,
		ActionTypeAnalyze,
	}

	for _, at := range types {
		if at == "" {
			t.Error("expected non-empty action type")
		}
	}
}
