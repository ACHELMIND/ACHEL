package ir

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Engine struct {
	config IRConfig
}

func NewEngine(config IRConfig) *Engine {
	return &Engine{config: config}
}

func (e *Engine) BreachSimulate(scope []string) IRResult {
	result := IRResult{
		ID:        uuid.New().String(),
		Phase:     IRPhaseIdentification,
		Playbook:  "breach_simulation",
		Timestamp: time.Now(),
	}

	findings := []Finding{
		{ID: uuid.New().String(), Title: "Initial Compromise via Phishing", Severity: "critical", Category: "Initial Access", Details: "User clicked malicious link in email, credentials harvested", IOCs: []string{"185.220.101.45", "phish.example.com"}, AffectedHosts: []string{"ws-finance-01", "ws-finance-02"}},
		{ID: uuid.New().String(), Title: "Lateral Movement via Pass-the-Hash", Severity: "critical", Category: "Lateral Movement", Details: "Attacker used harvested NTLM hash to move laterally", IOCs: []string{"S-1-5-21-...-1001"}, AffectedHosts: []string{"dc-01", "fileserver-01"}},
		{ID: uuid.New().String(), Title: "Data Exfiltration", Severity: "high", Category: "Exfiltration", Details: "Sensitive data exfiltrated via encrypted HTTPS channel", IOCs: []string{"exfil.example.com"}, AffectedHosts: []string{"fileserver-01"}},
	}

	result.Findings = findings

	result.Timeline = []TimelineEntry{
		{Timestamp: time.Now().Add(-48 * time.Hour), Event: "Phishing email sent", Phase: IRPhaseIdentification, Actor: "attacker"},
		{Timestamp: time.Now().Add(-46 * time.Hour), Event: "Credential harvested", Phase: IRPhaseIdentification, Actor: "attacker"},
		{Timestamp: time.Now().Add(-44 * time.Hour), Event: "Lateral movement initiated", Phase: IRPhaseIdentification, Actor: "attacker"},
		{Timestamp: time.Now().Add(-24 * time.Hour), Event: "SOC alert triggered", Phase: IRPhaseIdentification, Actor: "SOC"},
		{Timestamp: time.Now().Add(-23 * time.Hour), Event: "IR team activated", Phase: IRPhaseContainment, Actor: "IR"},
	}

	result.Metrics = IRMetrics{
		TotalFindings:   3,
		CriticalCount:   2,
		HighCount:       1,
		ContainmentTime: 120,
		EradicationTime: 240,
		RecoveryTime:    480,
		TotalDowntime:   60,
	}

	return result
}

func (e *Engine) Containment(findingIDs []string) IRResult {
	result := IRResult{
		ID:        uuid.New().String(),
		Phase:     IRPhaseContainment,
		Playbook:  "containment",
		Timestamp: time.Now(),
	}

	result.Actions = []IRAction{
		{Phase: IRPhaseContainment, Action: "Isolate affected host from network", Result: "Host ws-finance-01 isolated via NAC", Automated: false, Timestamp: time.Now()},
		{Phase: IRPhaseContainment, Action: "Block IOCs at perimeter firewall", Result: "Blocked 185.220.101.45, phish.example.com", Automated: true, Timestamp: time.Now()},
		{Phase: IRPhaseContainment, Action: "Disable compromised user accounts", Result: "Accounts jdoe, asmith disabled", Automated: false, Timestamp: time.Now()},
		{Phase: IRPhaseContainment, Action: "Reset service account credentials", Result: "svc_backup password rotated", Automated: false, Timestamp: time.Now()},
		{Phase: IRPhaseContainment, Action: "Enable enhanced logging", Result: "PowerShell module logging enabled", Automated: true, Timestamp: time.Now()},
	}

	result.Findings = []Finding{
		{ID: uuid.New().String(), Title: "Containment Complete", Severity: "info", Category: "Containment", Details: "All containment actions executed successfully"},
	}

	result.Timeline = []TimelineEntry{
		{Timestamp: time.Now(), Event: "Network isolation applied", Phase: IRPhaseContainment, Actor: "IR"},
		{Timestamp: time.Now(), Event: "IOC blocking configured", Phase: IRPhaseContainment, Actor: "Automation"},
	}

	return result
}

func (e *Engine) Eradication(findings []Finding) IRResult {
	result := IRResult{
		ID:        uuid.New().String(),
		Phase:     IRPhaseEradication,
		Playbook:  "eradication",
		Timestamp: time.Now(),
	}

	result.Actions = []IRAction{
		{Phase: IRPhaseEradication, Action: "Remove malware artifacts", Result: "Malware binaries quarantined from 3 hosts", Automated: false, Timestamp: time.Now()},
		{Phase: IRPhaseEradication, Action: "Clean persistence mechanisms", Result: "Scheduled tasks and registry keys removed", Automated: false, Timestamp: time.Now()},
		{Phase: IRPhaseEradication, Action: "Patch exploited vulnerabilities", Result: "CVE-2024-XXXXX patched on all affected systems", Automated: true, Timestamp: time.Now()},
		{Phase: IRPhaseEradication, Action: "Verify eradication", Result: "Full system scan clean on all affected hosts", Automated: true, Timestamp: time.Now()},
	}

	result.Evidence = []Evidence{
		{ID: uuid.New().String(), Type: "Malware Sample", Path: "/evidence/malware_sample.exe", Hash: computeHash("malware"), Timestamp: time.Now(), CollectedBy: "IR Team"},
		{ID: uuid.New().String(), Type: "Log Excerpt", Path: "/evidence/powershell_logs.txt", Hash: computeHash("logs"), Timestamp: time.Now(), CollectedBy: "SOC"},
	}

	result.Findings = []Finding{
		{ID: uuid.New().String(), Title: "Eradication Complete", Severity: "info", Category: "Eradication", Details: "All malicious artifacts removed and systems verified clean"},
	}

	return result
}

func (e *Engine) Recovery(findings []Finding) IRResult {
	result := IRResult{
		ID:        uuid.New().String(),
		Phase:     IRPhaseRecovery,
		Playbook:  "recovery",
		Timestamp: time.Now(),
	}

	result.Actions = []IRAction{
		{Phase: IRPhaseRecovery, Action: "Restore from clean backups", Result: "System restored from backup dated 2024-01-15", Automated: false, Timestamp: time.Now()},
		{Phase: IRPhaseRecovery, Action: "Re-enable network access", Result: "NAC rules removed for affected hosts", Automated: true, Timestamp: time.Now()},
		{Phase: IRPhaseRecovery, Action: "Re-enable user accounts", Result: "Accounts jdoe, asmith re-enabled with new passwords", Automated: false, Timestamp: time.Now()},
		{Phase: IRPhaseRecovery, Action: "Implement additional monitoring", Result: "Custom detection rules deployed for identified IOCs", Automated: true, Timestamp: time.Now()},
		{Phase: IRPhaseRecovery, Action: "Verify system integrity", Result: "File integrity monitoring baseline updated", Automated: true, Timestamp: time.Now()},
	}

	result.Findings = []Finding{
		{ID: uuid.New().String(), Title: "Recovery Complete", Severity: "info", Category: "Recovery", Details: "All systems restored and verified. Enhanced monitoring active."},
	}

	result.Metrics = IRMetrics{
		TotalFindings:   1,
		RecoveryTime:    120,
		TotalDowntime:   0,
	}

	return result
}

func computeHash(data string) string {
	h := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", h)
}
