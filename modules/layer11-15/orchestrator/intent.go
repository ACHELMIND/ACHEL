package orchestrator

import (
	"fmt"
	"strings"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
)

type IntentClassifier struct {
	log     *logger.Logger
	rules   []ClassificationRule
}

type ClassificationRule struct {
	Pattern  string
	Category string
	Module   ModuleType
	Action   string
	RiskBase float64
}

func NewIntentClassifier() *IntentClassifier {
	ic := &IntentClassifier{
		log:   logger.New("intent-classifier", logger.LevelInfo),
		rules: make([]ClassificationRule, 0),
	}

	ic.loadDefaultRules()
	return ic
}

func (ic *IntentClassifier) loadDefaultRules() {
	ic.rules = []ClassificationRule{
		{Pattern: "drop", Category: "destruction", Module: ModuleDestruction, Action: "drop_schema", RiskBase: 0.9},
		{Pattern: "encrypt", Category: "destruction", Module: ModuleDestruction, Action: "encrypt_files", RiskBase: 0.8},
		{Pattern: "overwrite", Category: "destruction", Module: ModuleDestruction, Action: "zero_overwrite", RiskBase: 0.95},
		{Pattern: "mbr", Category: "destruction", Module: ModuleDestruction, Action: "mbr_destroy", RiskBase: 1.0},
		{Pattern: "mft", Category: "destruction", Module: ModuleDestruction, Action: "mft_destroy", RiskBase: 1.0},
		{Pattern: "credential", Category: "credential", Module: ModuleCredential, Action: "extract", RiskBase: 0.6},
		{Pattern: "password", Category: "credential", Module: ModuleCredential, Action: "extract", RiskBase: 0.6},
		{Pattern: "scan", Category: "recon", Module: ModuleCollector, Action: "scan", RiskBase: 0.3},
		{Pattern: "recon", Category: "recon", Module: ModuleCollector, Action: "recon", RiskBase: 0.2},
		{Pattern: "persist", Category: "persistence", Module: ModulePersistence, Action: "install", RiskBase: 0.7},
		{Pattern: "lateral", Category: "lateral", Module: ModuleLateral, Action: "move", RiskBase: 0.5},
		{Pattern: "escape", Category: "evasion", Module: ModuleEvasion, Action: "evade", RiskBase: 0.4},
		{Pattern: "rootkit", Category: "rootkit", Module: ModuleRootkit, Action: "install", RiskBase: 0.85},
		{Pattern: "kerberos", Category: "kerberos", Module: ModuleKerberos, Action: "attack", RiskBase: 0.6},
	}
}

func (ic *IntentClassifier) Classify(request string) (*Intent, error) {
	if request == "" {
		return nil, fmt.Errorf("empty request")
	}

	lowerRequest := strings.ToLower(request)

	bestMatch := ClassificationRule{}
	bestScore := 0.0

	for _, rule := range ic.rules {
		if strings.Contains(lowerRequest, rule.Pattern) {
			score := 1.0
			if score > bestScore {
				bestScore = score
				bestMatch = rule
			}
		}
	}

	if bestScore == 0 {
		bestMatch = ClassificationRule{
			Category: "unknown",
			Module:   ModuleBrain,
			Action:   "analyze",
			RiskBase: 0.1,
		}
	}

	riskLevel := RiskLevelAuto
	if bestMatch.RiskBase >= 0.7 {
		riskLevel = RiskLevelBlock
	} else if bestMatch.RiskBase >= 0.3 {
		riskLevel = RiskLevelRequestApproval
	}

	intent := &Intent{
		ID:         fmt.Sprintf("intent_%d", time.Now().UnixNano()),
		Request:    request,
		Category:   bestMatch.Category,
		Module:     bestMatch.Module,
		Action:     bestMatch.Action,
		RiskLevel:  riskLevel,
		Confidence: bestScore,
		Params:     make(map[string]interface{}),
		Targets:    []string{},
		Timestamp:  time.Now(),
	}

	ic.log.Info("Classified intent: %s -> %s (risk: %v)", request, bestMatch.Category, riskLevel)
	return intent, nil
}

func (ic *IntentClassifier) SelectAction(intent *Intent) (*Action, error) {
	if intent == nil {
		return nil, fmt.Errorf("nil intent")
	}

	action := &Action{
		ID:          fmt.Sprintf("action_%d", time.Now().UnixNano()),
		Intent:      intent,
		Module:      intent.Module,
		Method:      intent.Action,
		Params:      intent.Params,
		RiskScore:   intent.Confidence,
		RequiresApproval: intent.RiskLevel == RiskLevelRequestApproval,
	}

	if len(intent.Targets) > 0 {
		action.Target = intent.Targets[0]
	}

	return action, nil
}
