package purpleteam

import (
	"fmt"
	"math/rand"

	"github.com/google/uuid"
)

type Engine struct {
	config PurpleTeamConfig
}

func NewEngine(config PurpleTeamConfig) *Engine {
	if config.MITREVersion == "" {
		config.MITREVersion = "14.1"
	}
	return &Engine{config: config}
}

func (e *Engine) AlertValidation(alertID string) []AlertValidation {
	var validations []AlertValidation

	rules := []DetectionRule{
		{Name: "Suspicious PowerShell Execution", ID: "SIGMA-001", MITRETechs: []string{"T1059.001"}, Severity: "high", Enabled: true},
		{Name: "Lateral Movement PsExec", ID: "SIGMA-002", MITRETechs: []string{"T1021.002"}, Severity: "critical", Enabled: true},
		{Name: "Credential Dumping", ID: "SIGMA-003", MITRETechs: []string{"T1003"}, Severity: "critical", Enabled: true},
		{Name: "Data Exfiltration Over DNS", ID: "SIGMA-004", MITRETechs: []string{"T1048.003"}, Severity: "high", Enabled: true},
		{Name: "Persistence via Scheduled Task", ID: "SIGMA-005", MITRETechs: []string{"T1053.005"}, Severity: "high", Enabled: true},
	}

	for _, rule := range rules {
		val := AlertValidation{
			AlertID:   fmt.Sprintf("%s-%s", alertID, rule.ID),
			RuleName:  rule.Name,
			Expected:  rule.Enabled,
			Received:  rule.Enabled && rand.Float64() > 0.1,
			Valid:     true,
			LatencyMs: 50 + int(rand.Float64()*200),
		}
		val.Valid = val.Expected == val.Received
		val.FalsePositive = !val.Expected && val.Received
		validations = append(validations, val)
	}

	return validations
}

func (e *Engine) DetectionRuleTest() []DetectionTest {
	var tests []DetectionTest

	techniques := []struct {
		tactic   string
		techID   string
		techName string
	}{
		{"Initial Access", "T1566", "Phishing"},
		{"Execution", "T1059", "Command and Scripting Interpreter"},
		{"Persistence", "T1547", "Boot or Logon Autostart Execution"},
		{"Privilege Escalation", "T1068", "Exploitation for Privilege Escalation"},
		{"Defense Evasion", "T1027", "Obfuscated Files or Information"},
		{"Credential Access", "T1003", "OS Credential Dumping"},
		{"Discovery", "T1087", "Account Discovery"},
		{"Lateral Movement", "T1021", "Remote Services"},
		{"Collection", "T1560", "Archive Collected Data"},
		{"Exfiltration", "T1041", "Exfiltration Over C2 Channel"},
	}

	for i, tech := range techniques {
		test := DetectionTest{
			ID:            uuid.New().String(),
			Name:          fmt.Sprintf("Test %s - %s", tech.techID, tech.techName),
			Tactic:        tech.tactic,
			Technique:     tech.techName,
			TechniqueID:   tech.techID,
			Category:      "Atomic Test",
			Severity:      getSeverity(i),
			ExpectedAlert: true,
			ActualAlert:   i%3 != 0,
			Detected:      i%3 != 0,
			LatencyMs:     100 + i*50,
		}
		tests = append(tests, test)
	}

	return tests
}

func (e *Engine) LogCoverageTest() []MITREMapping {
	var coverage []MITREMapping

	tactics := []struct {
		id        string
		name      string
		techIDs   []string
		techNames []string
	}{
		{"TA0001", "Initial Access", []string{"T1566", "T1190", "T1133"}, []string{"Phishing", "Exploit Public-Facing App", "External Remote Services"}},
		{"TA0002", "Execution", []string{"T1059", "T1204", "T1047"}, []string{"Command and Scripting Interpreter", "User Execution", "Windows Management Instrumentation"}},
		{"TA0003", "Persistence", []string{"T1547", "T1053", "T1136"}, []string{"Boot or Logon Autostart", "Scheduled Task/Job", "Create Account"}},
		{"TA0005", "Defense Evasion", []string{"T1027", "T1070", "T1562"}, []string{"Obfuscated Files", "Indicator Removal", "Impair Defenses"}},
		{"TA0006", "Credential Access", []string{"T1003", "T1110", "T1555"}, []string{"OS Credential Dumping", "Brute Force", "Credentials from Password Stores"}},
	}

	for _, tactic := range tactics {
		detected := 0
		for i := range tactic.techIDs {
			if i%2 == 0 {
				detected++
			}
		}

		mapping := MITREMapping{
			TacticID:       tactic.id,
			TacticName:     tactic.name,
			TechniqueIDs:   tactic.techIDs,
			TechniqueNames: tactic.techNames,
			DetectedCount:  detected,
			TotalCount:     len(tactic.techIDs),
			CoveragePct:    float64(detected) / float64(len(tactic.techIDs)) * 100,
		}
		coverage = append(coverage, mapping)
	}

	return coverage
}

func (e *Engine) MITREMapping(techniqueIDs []string) []MITREMapping {
	var mappings []MITREMapping

	techniqueToTactic := map[string]struct {
		tactic string
		name   string
	}{
		"T1566": {"TA0001", "Phishing"},
		"T1059": {"TA0002", "Command and Scripting Interpreter"},
		"T1547": {"TA0003", "Boot or Logon Autostart Execution"},
		"T1068": {"TA0004", "Exploitation for Privilege Escalation"},
		"T1027": {"TA0005", "Obfuscated Files or Information"},
		"T1003": {"TA0006", "OS Credential Dumping"},
		"T1087": {"TA0007", "Account Discovery"},
		"T1021": {"TA0008", "Remote Services"},
		"T1560": {"TA0009", "Archive Collected Data"},
		"T1041": {"TA0010", "Exfiltration Over C2 Channel"},
	}

	tacticTechs := make(map[string][]string)
	tacticNames := make(map[string]string)

	for _, techID := range techniqueIDs {
		if info, ok := techniqueToTactic[techID]; ok {
			tacticTechs[info.tactic] = append(tacticTechs[info.tactic], techID)
			tacticNames[info.tactic] = info.name
		}
	}

	for tactic, techs := range tacticTechs {
		mappings = append(mappings, MITREMapping{
			TacticID:       tactic,
			TacticName:     tacticNames[tactic],
			TechniqueIDs:   techs,
			DetectedCount:  len(techs),
			TotalCount:     len(techs),
			CoveragePct:    100,
		})
	}

	return mappings
}

func getSeverity(i int) string {
	switch i % 4 {
	case 0:
		return "critical"
	case 1:
		return "high"
	case 2:
		return "medium"
	default:
		return "low"
	}
}
