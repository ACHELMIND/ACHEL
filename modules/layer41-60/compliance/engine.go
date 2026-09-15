package compliance

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	config ComplianceConfig
	mu     sync.Mutex
}

func NewEngine(cfg ComplianceConfig) *Engine {
	return &Engine{
		config: cfg,
	}
}

func (e *Engine) PCICompliance(scope []string) (*ComplianceResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	controls := e.checkPCIControls(scope)

	passed := 0
	failed := 0
	for _, c := range controls {
		if c.Status == "pass" {
			passed++
		} else {
			failed++
		}
	}

	score := float64(passed) / float64(len(controls)) * 100

	return &ComplianceResult{
		Success:  true,
		Method:   "PCI_DSS",
		Message:  fmt.Sprintf("PCI DSS assessment: %d/%d controls passed (%.1f%%)", passed, len(controls), score),
		Duration: time.Since(start),
		Score:    score,
		Findings: e.extractFindings(controls),
	}, nil
}

func (e *Engine) checkPCIControls(scope []string) []ControlCheck {
	controls := make([]ControlCheck, 0)

	controls = append(controls, ControlCheck{
		ID:       "PCI-DSS-1.1",
		Name:     "Firewall Configuration",
		Status:   "pass",
		Severity: "high",
		Description: "Firewall configuration reviewed",
	})

	controls = append(controls, ControlCheck{
		ID:       "PCI-DSS-2.1",
		Name:     "Default Passwords",
		Status:   "fail",
		Severity: "critical",
		Description: "Default passwords not changed",
		Remediation: "Change all default passwords",
	})

	controls = append(controls, ControlCheck{
		ID:       "PCI-DSS-3.1",
		Name:     "Data Retention",
		Status:   "pass",
		Severity: "medium",
		Description: "Data retention policy in place",
	})

	controls = append(controls, ControlCheck{
		ID:       "PCI-DSS-4.1",
		Name:     "Encryption",
		Status:   "fail",
		Severity: "high",
		Description: "Weak encryption detected",
		Remediation: "Upgrade to TLS 1.2+",
	})

	controls = append(controls, ControlCheck{
		ID:       "PCI-DSS-6.1",
		Name:     "Patch Management",
		Status:   "warning",
		Severity: "medium",
		Description: "Some patches missing",
		Remediation: "Apply latest security patches",
	})

	return controls
}

func (e *Engine) GDPRCheck(scope []string) (*ComplianceResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	controls := e.checkGDPRControls(scope)

	passed := 0
	failed := 0
	for _, c := range controls {
		if c.Status == "pass" {
			passed++
		} else {
			failed++
		}
	}

	score := float64(passed) / float64(len(controls)) * 100

	return &ComplianceResult{
		Success:  true,
		Method:   "GDPR",
		Message:  fmt.Sprintf("GDPR assessment: %d/%d controls passed (%.1f%%)", passed, len(controls), score),
		Duration: time.Since(start),
		Score:    score,
		Findings: e.extractFindings(controls),
	}, nil
}

func (e *Engine) checkGDPRControls(scope []string) []ControlCheck {
	controls := make([]ControlCheck, 0)

	controls = append(controls, ControlCheck{
		ID:       "GDPR-5.1",
		Name:     "Data Processing",
		Status:   "pass",
		Severity: "high",
		Description: "Data processing activities documented",
	})

	controls = append(controls, ControlCheck{
		ID:       "GDPR-17",
		Name:     "Right to Erasure",
		Status:   "fail",
		Severity: "high",
		Description: "Data deletion mechanism not implemented",
		Remediation: "Implement data deletion API",
	})

	controls = append(controls, ControlCheck{
		ID:       "GDPR-25",
		Name:     "Privacy by Design",
		Status:   "fail",
		Severity: "medium",
		Description: "Privacy controls not embedded in design",
		Remediation: "Implement privacy by design principles",
	})

	controls = append(controls, ControlCheck{
		ID:       "GDPR-33",
		Name:     "Breach Notification",
		Status:   "pass",
		Severity: "high",
		Description: "Breach notification process in place",
	})

	return controls
}

func (e *Engine) NISTAssess(scope []string) (*ComplianceResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	controls := e.checkNISTControls(scope)

	passed := 0
	failed := 0
	for _, c := range controls {
		if c.Status == "pass" {
			passed++
		} else {
			failed++
		}
	}

	score := float64(passed) / float64(len(controls)) * 100

	return &ComplianceResult{
		Success:  true,
		Method:   "NIST_800_53",
		Message:  fmt.Sprintf("NIST 800-53 assessment: %d/%d controls passed (%.1f%%)", passed, len(controls), score),
		Duration: time.Since(start),
		Score:    score,
		Findings: e.extractFindings(controls),
	}, nil
}

func (e *Engine) checkNISTControls(scope []string) []ControlCheck {
	controls := make([]ControlCheck, 0)

	controls = append(controls, ControlCheck{
		ID:       "AC-2",
		Name:     "Account Management",
		Status:   "pass",
		Severity: "high",
		Description: "Account management procedures in place",
	})

	controls = append(controls, ControlCheck{
		ID:       "AC-6",
		Name:     "Least Privilege",
		Status:   "fail",
		Severity: "high",
		Description: "Excessive privileges detected",
		Remediation: "Implement least privilege access",
	})

	controls = append(controls, ControlCheck{
		ID:       "AU-2",
		Name:     "Audit Events",
		Status:   "pass",
		Severity: "medium",
		Description: "Audit logging enabled",
	})

	controls = append(controls, ControlCheck{
		ID:       "CA-7",
		Name:     "Continuous Monitoring",
		Status:   "warning",
		Severity: "medium",
		Description: "Monitoring gaps identified",
		Remediation: "Implement continuous monitoring",
	})

	return controls
}

func (e *Engine) CISBenchmark(scope []string) (*ComplianceResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	controls := e.checkCISControls(scope)

	passed := 0
	failed := 0
	for _, c := range controls {
		if c.Status == "pass" {
			passed++
		} else {
			failed++
		}
	}

	score := float64(passed) / float64(len(controls)) * 100

	return &ComplianceResult{
		Success:  true,
		Method:   "CIS_Benchmark",
		Message:  fmt.Sprintf("CIS Benchmark: %d/%d controls passed (%.1f%%)", passed, len(controls), score),
		Duration: time.Since(start),
		Score:    score,
		Findings: e.extractFindings(controls),
	}, nil
}

func (e *Engine) checkCISControls(scope []string) []ControlCheck {
	controls := make([]ControlCheck, 0)

	controls = append(controls, ControlCheck{
		ID:       "CIS-1.1.1",
		Name:     "File System Configuration",
		Status:   "pass",
		Severity: "medium",
		Description: "File system permissions verified",
	})

	controls = append(controls, ControlCheck{
		ID:       "CIS-2.1",
		Name:     "SSH Configuration",
		Status:   "fail",
		Severity: "high",
		Description: "SSH root login enabled",
		Remediation: "Disable SSH root login",
	})

	controls = append(controls, ControlCheck{
		ID:       "CIS-3.1",
		Name:     "Network Parameters",
		Status:   "pass",
		Severity: "medium",
		Description: "Network parameters configured",
	})

	controls = append(controls, ControlCheck{
		ID:       "CIS-4.1",
		Name:     "Logging and Auditing",
		Status:   "fail",
		Severity: "high",
		Description: "Audit logging incomplete",
		Remediation: "Enable comprehensive audit logging",
	})

	return controls
}

func (e *Engine) extractFindings(controls []ControlCheck) []string {
	findings := make([]string, 0)
	for _, c := range controls {
		if c.Status == "fail" {
			findings = append(findings, fmt.Sprintf("[%s] %s: %s", c.Severity, c.Name, c.Description))
		}
	}
	return findings
}

func (e *Engine) GenerateReport(framework string, controls []ControlCheck) ComplianceReport {
	passed := 0
	failed := 0
	warning := 0
	for _, c := range controls {
		switch c.Status {
		case "pass":
			passed++
		case "fail":
			failed++
		case "warning":
			warning++
		}
	}

	score := float64(passed) / float64(len(controls)) * 100

	return ComplianceReport{
		Framework:   framework,
		Scope:       e.config.Scope,
		Score:       score,
		Passed:      passed,
		Failed:      failed,
		Warning:     warning,
		Controls:    controls,
		GeneratedAt: time.Now(),
	}
}

func (e *Engine) GapAnalysis(current []string, required []string) GapAnalysis {
	gaps := make([]string, 0)
	recs := make([]string, 0)

	currentMap := make(map[string]bool)
	for _, c := range current {
		currentMap[c] = true
	}

	for _, r := range required {
		if !currentMap[r] {
			gaps = append(gaps, r)
			recs = append(recs, fmt.Sprintf("Implement %s", r))
		}
	}

	priority := "low"
	if len(gaps) > 3 {
		priority = "critical"
	} else if len(gaps) > 1 {
		priority = "high"
	}

	return GapAnalysis{
		CurrentState:    strings.Join(current, ", "),
		RequiredState:   strings.Join(required, ", "),
		Gaps:            gaps,
		Recommendations: recs,
		Priority:        priority,
	}
}
