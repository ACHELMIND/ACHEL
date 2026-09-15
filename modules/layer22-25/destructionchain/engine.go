package destructionchain

import (
	"fmt"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
	"github.com/angel-platform/angel/pkg/types"
)

type DestructionChainEngine struct {
	mu          sync.Mutex
	config      *DestructionChainConfig
	orchestrator *ChainOrchestrator
	timing      *TimingCoordinator
	log         *logger.Logger
	chains      map[string]*DestructionChain
}

func NewDestructionChainEngine(config *DestructionChainConfig) *DestructionChainEngine {
	if config == nil {
		config = NewDefaultChainConfig()
	}
	l := logger.New("destructionchain", logger.LevelInfo)
	tc := NewTimingCoordinator(NewDefaultTimingConfig())
	co := NewChainOrchestrator(config, tc, l)

	return &DestructionChainEngine{
		config:       config,
		orchestrator: co,
		timing:       tc,
		log:          l,
		chains:       make(map[string]*DestructionChain),
	}
}

func (e *DestructionChainEngine) FullScopeAttack(target *FullScopeTarget) (*FullScopeResult, error) {
	if target == nil {
		return nil, fmt.Errorf("target is nil")
	}

	start := time.Now()
	chainID := types.GenerateID()

	e.log.Info("Starting full scope attack on %s", target.Host)

	recon, err := e.executeRecon(target)
	if err != nil {
		return nil, fmt.Errorf("recon failed: %w", err)
	}

	attack, err := e.executeAttack(target, recon)
	if err != nil {
		return nil, fmt.Errorf("attack failed: %w", err)
	}

	destroy, err := e.executeDestroy(target, attack)
	if err != nil {
		e.log.Error("Destroy phase failed: %v", err)
	}

	report := e.generateReport(target, recon, attack, destroy)

	duration := time.Since(start)
	result := &FullScopeResult{
		ChainID:        chainID,
		Target:         target,
		Recon:          recon,
		Attack:         attack,
		Destroy:        destroy,
		Report:         report,
		OverallSuccess: attack.Exploited,
		Duration:       duration,
		Timestamp:      time.Now(),
	}

	e.log.Info("Full scope attack completed on %s in %v", target.Host, duration)
	return result, nil
}

func (e *DestructionChainEngine) ExecuteChain(chain *DestructionChain) (*ChainResult, error) {
	if chain == nil {
		return nil, fmt.Errorf("chain is nil")
	}

	e.mu.Lock()
	e.chains[chain.ID] = chain
	e.mu.Unlock()

	start := time.Now()
	chain.Status = ChainStatusRunning
	now := time.Now()
	chain.StartedAt = &now

	e.log.Info("Executing chain %s with %d steps", chain.ID, len(chain.Steps))

	results := make(map[string]*StepResult)
	for i := range chain.Steps {
		step := &chain.Steps[i]

		if e.config.PauseOnError && step.Status == StepStatusFailed {
			chain.Status = ChainStatusPaused
			e.log.Warn("Chain paused at step %s due to error", step.ID)
			break
		}

		result, err := e.orchestrator.ExecuteStep(step)
		if err != nil {
			e.log.Error("Step %s failed: %v", step.ID, err)
			if e.config.PauseOnError {
				chain.Status = ChainStatusPaused
				break
			}
			continue
		}
		results[step.ID] = result
	}

	completedAt := time.Now()
	chain.CompletedAt = &completedAt
	chain.Status = ChainStatusCompleted

	return &ChainResult{
		ChainID:     chain.ID,
		Success:     true,
		Results:     results,
		StartedAt:   start,
		CompletedAt: completedAt,
		Duration:    completedAt.Sub(start),
	}, nil
}

func (e *DestructionChainEngine) CalculateImpact(target string) (*ImpactReport, error) {
	if target == "" {
		return nil, fmt.Errorf("target is empty")
	}

	criticality := types.SeverityHigh
	riskScore := 0.7

	return &ImpactReport{
		Target:          target,
		Scope:           "full",
		Criticality:     criticality,
		AffectedHosts:   1,
		EstimatedTime:   30 * time.Minute,
		RiskScore:       riskScore,
		Recommendations: []string{"Isolate target", "Collect evidence", "Document all actions"},
	}, nil
}

func (e *DestructionChainEngine) EstimateCompletionTime(chain *DestructionChain) time.Duration {
	if chain == nil || len(chain.Steps) == 0 {
		return 0
	}

	var total time.Duration
	for _, step := range chain.Steps {
		if step.Status == StepStatusCompleted {
			if step.StartedAt != nil && step.CompletedAt != nil {
				total += step.CompletedAt.Sub(*step.StartedAt)
			}
			continue
		}
		total += e.config.DefaultTimeout
	}
	return total
}

func (e *DestructionChainEngine) executeRecon(target *FullScopeTarget) (*ReconResult, error) {
	result := &ReconResult{
		Host:       target.Host,
		Ports:      target.Services,
		Vulns:      target.Vulns,
		Secrets:    []string{},
		NetworkMap: make(map[string]interface{}),
	}

	// Build network map from target data
	result.NetworkMap["host"] = target.Host
	result.NetworkMap["ip"] = target.IP
	result.NetworkMap["os"] = string(target.OS)
	result.NetworkMap["arch"] = target.Arch
	result.NetworkMap["service_count"] = len(target.Services)
	result.NetworkMap["vuln_count"] = len(target.Vulns)

	// Map services to ports for quick lookup
	servicePorts := make(map[int]string)
	for _, svc := range target.Services {
		servicePorts[svc.Port] = svc.Name
	}
	result.NetworkMap["service_ports"] = servicePorts

	// Enumerate secrets from service banners and target metadata
	secretSet := make(map[string]bool)
	for _, svc := range target.Services {
		if svc.Banner != "" {
			secret := fmt.Sprintf("banner:%d:%s", svc.Port, svc.Banner)
			if !secretSet[secret] {
				result.Secrets = append(result.Secrets, secret)
				secretSet[secret] = true
			}
		}
		// Flag services with known sensitive names
		switch svc.Name {
		case "ssh", "rdp", "ftp", "telnet":
			remoteSvc := fmt.Sprintf("remote_access:%s:%d", svc.Name, svc.Port)
			if !secretSet[remoteSvc] {
				result.Secrets = append(result.Secrets, remoteSvc)
				secretSet[remoteSvc] = true
			}
		case "mysql", "postgresql", "mssql", "oracle", "mongodb", "redis":
			dbSvc := fmt.Sprintf("database:%s:%d", svc.Name, svc.Port)
			if !secretSet[dbSvc] {
				result.Secrets = append(result.Secrets, dbSvc)
				secretSet[dbSvc] = true
			}
		}
	}

	// Extract secrets from pre-harvested credentials
	for _, cred := range target.Creds {
		entry := fmt.Sprintf("credential:%s@%s", cred.Username, cred.Source)
		if !secretSet[entry] {
			result.Secrets = append(result.Secrets, entry)
			secretSet[entry] = true
		}
	}

	// Classify vulns by severity for downstream attack planning
	vulnSummary := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}
	for _, v := range target.Vulns {
		switch v.Severity {
		case types.SeverityCritical:
			vulnSummary["critical"]++
		case types.SeverityHigh:
			vulnSummary["high"]++
		case types.SeverityMedium:
			vulnSummary["medium"]++
		case types.SeverityLow:
			vulnSummary["low"]++
		}
	}
	result.NetworkMap["vuln_summary"] = vulnSummary

	// Compute overall risk score from vulns and exposed services
	totalVulns := len(target.Vulns)
	totalServices := len(target.Services)
	riskScore := 0.0
	if totalVulns > 0 {
		riskScore += float64(vulnSummary["critical"])*0.4 + float64(vulnSummary["high"])*0.25 +
			float64(vulnSummary["medium"])*0.1 + float64(vulnSummary["low"])*0.05
	}
	if totalServices > 0 {
		riskScore += float64(totalServices) * 0.05
	}
	if riskScore > 1.0 {
		riskScore = 1.0
	}
	result.NetworkMap["risk_score"] = riskScore

	e.log.Info("Recon completed on %s: %d services, %d vulns, %d secrets, risk=%.2f",
		target.Host, totalServices, totalVulns, len(result.Secrets), riskScore)

	return result, nil
}

func (e *DestructionChainEngine) executeAttack(target *FullScopeTarget, recon *ReconResult) (*AttackResult, error) {
	result := &AttackResult{
		Exploited: len(recon.Vulns) > 0,
		Access:    "none",
		Creds:     target.Creds,
		Shells:    []ShellInfo{},
		Data:      make(map[string]interface{}),
	}

	if !result.Exploited {
		e.log.Info("No vulnerabilities found on %s — skipping exploitation", target.Host)
		return result, nil
	}

	// Determine highest access level achievable based on vulnerability severity chain
	highestAccess := "user"
	primaryVuln := ""
	for _, v := range recon.Vulns {
		switch v.Severity {
		case types.SeverityCritical:
			highestAccess = "system"
			primaryVuln = v.CVE
		case types.SeverityHigh:
			if highestAccess != "system" {
				highestAccess = "admin"
				if primaryVuln == "" {
					primaryVuln = v.CVE
				}
			}
		case types.SeverityMedium:
			if highestAccess == "none" {
				highestAccess = "user"
				if primaryVuln == "" {
					primaryVuln = v.CVE
				}
			}
		}
	}
	result.Access = highestAccess

	// Determine exploit method based on target OS and vulnerability
	exploitMethod := "unknown"
	switch target.OS {
	case types.PlatformWindows:
		if highestAccess == "system" {
			exploitMethod = "kernel_exploit"
		} else {
			exploitMethod = "service_exploit"
		}
	case types.PlatformLinux:
		if highestAccess == "system" {
			exploitMethod = "suid_binary"
		} else {
			exploitMethod = "webapp_exploit"
		}
	default:
		exploitMethod = "generic_exploit"
	}

	// Create shells proportional to number of critical/high vulns
	shellCount := 0
	for _, v := range recon.Vulns {
		if v.Severity == types.SeverityCritical || v.Severity == types.SeverityHigh {
			shellCount++
		}
	}
	if shellCount > 5 {
		shellCount = 5
	}
	if shellCount < 1 {
		shellCount = 1
	}

	basePort := 4444
	for i := 0; i < shellCount; i++ {
		shellType := "reverse"
		if i%2 == 1 {
			shellType = "bind"
		}
		result.Shells = append(result.Shells, ShellInfo{
			Type: shellType,
			Host: target.IP,
			Port: basePort + i,
		})
	}

	// Populate attack data with exploitation details
	result.Data["primary_vuln"] = primaryVuln
	result.Data["exploit_method"] = exploitMethod
	result.Data["access_level"] = highestAccess
	result.Data["vulns_exploited"] = len(recon.Vulns)
	result.Data["shells_established"] = len(result.Shells)

	// Build exploitation path from vuln chain
	exploitPath := make([]string, 0, len(recon.Vulns))
	for _, v := range recon.Vulns {
		exploitPath = append(exploitPath, fmt.Sprintf("%s (%s)", v.CVE, v.Severity))
	}
	result.Data["exploitation_path"] = exploitPath

	// Aggregate harvested credentials from all sources
	harvestedCreds := make([]string, 0, len(target.Creds))
	for _, cred := range target.Creds {
		harvestedCreds = append(harvestedCreds, fmt.Sprintf("%s@%s", cred.Username, cred.Source))
	}
	result.Data["harvested_credentials"] = harvestedCreds

	e.log.Info("Attack completed on %s: access=%s, method=%s, shells=%d, vulns=%d",
		target.Host, highestAccess, exploitMethod, len(result.Shells), len(recon.Vulns))

	return result, nil
}

func (e *DestructionChainEngine) executeDestroy(target *FullScopeTarget, attack *AttackResult) (*DestroyResult, error) {
	result := &DestroyResult{
		Target:    target.Host,
		Method:    "none",
		Artifacts: []string{},
		Verified:  false,
	}

	if !attack.Exploited {
		e.log.Info("No exploitation on %s — skipping destroy phase", target.Host)
		return result, nil
	}

	// Select destruction method based on target OS and access level
	method := e.selectDestructionMethod(target.OS, attack.Access, target.Services)
	result.Method = method

	// Build artifact list from shells and attack data
	artifacts := e.collectDestructionArtifacts(target, attack, method)
	result.Artifacts = artifacts

	// Verify destruction readiness: we need at least one shell and system/admin access
	result.Verified = e.verifyDestructionReadiness(attack)

	e.log.Info("Destroy plan on %s: method=%s, artifacts=%d, verified=%v",
		target.Host, method, len(artifacts), result.Verified)

	return result, nil
}

func (e *DestructionChainEngine) selectDestructionMethod(osType types.Platform, access string, services []ServiceInfo) string {
	// Determine available attack surfaces from services
	hasSSH := false
	hasWeb := false
	hasDB := false
	for _, svc := range services {
		switch svc.Name {
		case "ssh", "rdp":
			hasSSH = true
		case "http", "https", "nginx", "apache", "iis":
			hasWeb = true
		case "mysql", "postgresql", "mssql", "oracle", "mongodb", "redis":
			hasDB = true
		}
	}

	// Select method based on OS + access level + available surfaces
	switch access {
	case "system":
		switch osType {
		case types.PlatformWindows:
			if hasDB {
				return "database_encrypt"
			}
			return "mbr_overwrite"
		case types.PlatformLinux:
			if hasDB {
				return "database_drop"
			}
			return "filesystem_wipe"
		case types.PlatformDarwin:
			return "filesystem_wipe"
		default:
			return "logical_shred"
		}
	case "admin":
		switch osType {
		case types.PlatformWindows:
			if hasDB {
				return "database_encrypt"
			}
			if hasWeb {
				return "webshell_deploy"
			}
			return "service_stop"
		case types.PlatformLinux:
			if hasDB {
				return "database_drop"
			}
			if hasWeb {
				return "webroot_replace"
			}
			return "crontab_poison"
		default:
			return "service_stop"
		}
	case "user":
		if hasWeb {
			return "webshell_deploy"
		}
		if hasSSH {
			return "keyplant"
		}
		return "data_exfil"
	default:
		return "none"
	}
}

func (e *DestructionChainEngine) collectDestructionArtifacts(target *FullScopeTarget, attack *AttackResult, method string) []string {
	artifacts := []string{}

	// Record each shell as an artifact
	for i, shell := range attack.Shells {
		artifacts = append(artifacts, fmt.Sprintf("shell:%s:%d:%s", shell.Type, shell.Port, shell.Host))
		if i >= 4 { // cap at 5 artifacts for shells
			break
		}
	}

	// Add method-specific artifacts
	switch method {
	case "database_encrypt", "database_drop":
		artifacts = append(artifacts, "db_payload:deployed")
		for _, svc := range target.Services {
			switch svc.Name {
			case "mysql":
				artifacts = append(artifacts, fmt.Sprintf("db_target:mysql:%d", svc.Port))
			case "postgresql":
				artifacts = append(artifacts, fmt.Sprintf("db_target:postgresql:%d", svc.Port))
			case "mssql":
				artifacts = append(artifacts, fmt.Sprintf("db_target:mssql:%d", svc.Port))
			case "oracle":
				artifacts = append(artifacts, fmt.Sprintf("db_target:oracle:%d", svc.Port))
			case "mongodb":
				artifacts = append(artifacts, fmt.Sprintf("db_target:mongodb:%d", svc.Port))
			case "redis":
				artifacts = append(artifacts, fmt.Sprintf("db_target:redis:%d", svc.Port))
			}
		}
	case "mbr_overwrite":
		artifacts = append(artifacts, "mbr_payload:staged")
		artifacts = append(artifacts, "boot_sector:targeted")
	case "filesystem_wipe":
		artifacts = append(artifacts, "wiper_payload:staged")
		artifacts = append(artifacts, "filesystem:targeted")
	case "webshell_deploy":
		artifacts = append(artifacts, "webshell:deployed")
		for _, svc := range target.Services {
			if svc.Name == "http" || svc.Name == "https" || svc.Name == "nginx" || svc.Name == "apache" || svc.Name == "iis" {
				artifacts = append(artifacts, fmt.Sprintf("web_target:%s:%d", svc.Name, svc.Port))
			}
		}
	case "service_stop":
		artifacts = append(artifacts, "service_control:staged")
	case "crontab_poison":
		artifacts = append(artifacts, "crontab_entry:injected")
	case "keyplant":
		artifacts = append(artifacts, "ssh_key:planted")
	case "data_exfil":
		artifacts = append(artifacts, "exfil_channel:established")
	case "logical_shred":
		artifacts = append(artifacts, "shred_payload:staged")
	case "webroot_replace":
		artifacts = append(artifacts, "webroot_replacement:staged")
	}

	// Add harvested credentials as artifacts
	for _, cred := range attack.Creds {
		artifacts = append(artifacts, fmt.Sprintf("cred:%s@%s", cred.Username, cred.Source))
	}

	return artifacts
}

func (e *DestructionChainEngine) verifyDestructionReadiness(attack *AttackResult) bool {
	// Need at least one active shell
	if len(attack.Shells) == 0 {
		return false
	}

	// Need system or admin access for destructive operations
	if attack.Access != "system" && attack.Access != "admin" {
		return false
	}

	return true
}

func (e *DestructionChainEngine) generateReport(target *FullScopeTarget, recon *ReconResult, attack *AttackResult, destroy *DestroyResult) *types.ModuleResult {
	return &types.ModuleResult{
		Module:    "destructionchain",
		Success:   attack.Exploited,
		Data: map[string]interface{}{
			"target":  target.Host,
			"recon":   recon,
			"attack":  attack,
			"destroy": destroy,
		},
		Timestamp: time.Now(),
	}
}
