package threatintel

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Engine struct {
	config ThreatIntelConfig
}

func NewEngine(config ThreatIntelConfig) *Engine {
	if config.LookbackDays == 0 {
		config.LookbackDays = 30
	}
	return &Engine{config: config}
}

func (e *Engine) IOCGeneration(target string) IntelResult {
	result := IntelResult{
		ID:        uuid.New().String(),
		Target:    target,
		Timestamp: time.Now(),
	}

	ios := e.extractIOCs(target)
	result.IOCs = ios

	if e.config.MITREMapping {
		mapping := e.mapToMITRE(ios)
		result.MITREMapping = mapping
	}

	result.RiskScore = e.calculateRiskScore(ios)
	return result
}

func (e *Engine) MITREATTACKMapping(iocs []IOC) IntelResult {
	result := IntelResult{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
	}

	mapping := e.mapToMITRE(iocs)
	result.MITREMapping = mapping
	result.IOCs = iocs

	return result
}

func (e *Engine) ThreatFeed(feedURL string) IntelResult {
	result := IntelResult{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
	}

	threatActors := []ThreatActor{
		{Name: "APT29", Aliases: []string{"Cozy Bear", "The Dukes"}, Attribution: "Russia/SVR", Motivation: "Espionage", Country: "Russia", Techniques: []string{"T1566", "T1059", "T1003"}, Active: true},
		{Name: "Lazarus Group", Aliases: []string{"HIDDEN COBRA"}, Attribution: "North Korea", Motivation: "Financial", Country: "North Korea", Techniques: []string{"T1566", "T1204", "T1041"}, Active: true},
		{Name: "FIN7", Aliases: []string{"Carbanak", "Navigator Group"}, Attribution: "Unknown", Motivation: "Financial", Country: "Unknown", Techniques: []string{"T1566", "T1059", "T1021"}, Active: false},
	}

	result.ThreatActors = threatActors
	return result
}

func (e *Engine) IntelReport(target string) IntelResult {
	result := IntelResult{
		ID:        uuid.New().String(),
		Target:    target,
		Timestamp: time.Now(),
	}

	iocs := e.extractIOCs(target)
	result.IOCs = iocs

	report := IntelReport{
		Title: fmt.Sprintf("Threat Intelligence Report: %s", target),
		Summary: fmt.Sprintf("Analysis of threat landscape targeting %s. Identified %d indicators of compromise.", target, len(iocs)),
		IOCs:   iocs,
		TTPs:   []string{"T1566", "T1059.001", "T1003", "T1041"},
		Severity: "high",
		PublishedAt: time.Now(),
		Source:  "ANGEL Platform",
	}
	result.Reports = append(result.Reports, report)

	return result
}

func (e *Engine) extractIOCs(target string) []IOC {
	var iocs []IOC

	iocs = append(iocs, IOC{
		Type:       IOCTypeIP,
		Value:      "185.220.101.45",
		Confidence: 0.85,
		Source:     "Reputation DB",
		Tags:       []string{"tor_exit", "scanner"},
		FirstSeen:  time.Now().AddDate(0, 0, -7),
		LastSeen:   time.Now(),
	})

	iocs = append(iocs, IOC{
		Type:       IOCTypeDomain,
		Value:      "malware-c2.example.com",
		Confidence: 0.92,
		Source:     "DNS Analysis",
		Tags:       []string{"c2", "malware"},
		FirstSeen:  time.Now().AddDate(0, 0, -14),
		LastSeen:   time.Now(),
	})

	hash := sha256.Sum256([]byte(target))
	iocs = append(iocs, IOC{
		Type:       IOCTypeFileHash,
		Value:      fmt.Sprintf("%x", hash),
		Confidence: 0.78,
		Source:     "Sandbox Analysis",
		Tags:       []string{"malware", "trojan"},
		FirstSeen:  time.Now().AddDate(0, 0, -3),
		LastSeen:   time.Now(),
	})

	iocs = append(iocs, IOC{
		Type:       IOCTypeURL,
		Value:      "http://phish.example.com/login/verify",
		Confidence: 0.88,
		Source:     "Phishing DB",
		Tags:       []string{"phishing", "credential_harvest"},
		FirstSeen:  time.Now().AddDate(0, 0, -1),
		LastSeen:   time.Now(),
	})

	iocs = append(iocs, IOC{
		Type:       IOCTypeJA3,
		Value:      "e47d2c0a361b6dd7397a7d7b957d3b4c",
		Confidence: 0.95,
		Source:     "TLS Fingerprinting",
		Tags:       []string{"malware", "backdoor"},
		FirstSeen:  time.Now().AddDate(0, 0, -10),
		LastSeen:   time.Now(),
	})

	return iocs
}

func (e *Engine) mapToMITRE(iocs []IOC) []MITRETechnique {
	var techniques []MITRETechnique

	techniqueMap := make(map[string]*MITRETechnique)

	for _, ioc := range iocs {
		for _, tag := range ioc.Tags {
			var tech MITRETechnique
			switch tag {
			case "c2", "malware":
				tech = MITRETechnique{TechniqueID: "T1071", Name: "Application Layer Protocol", Tactic: "Command and Control"}
			case "phishing", "credential_harvest":
				tech = MITRETechnique{TechniqueID: "T1566", Name: "Phishing", Tactic: "Initial Access"}
			case "scanner":
				tech = MITRETechnique{TechniqueID: "T1595", Name: "Active Scanning", Tactic: "Reconnaissance"}
			default:
				tech = MITRETechnique{TechniqueID: "T1001", Name: "Data Obfuscation", Tactic: "Defense Evasion"}
			}

			if existing, ok := techniqueMap[tech.TechniqueID]; ok {
				existing.Count++
			} else {
				tech.Count = 1
				techniqueMap[tech.TechniqueID] = &tech
			}
		}
	}

	for _, tech := range techniqueMap {
		techniques = append(techniques, *tech)
	}

	return techniques
}

func (e *Engine) calculateRiskScore(iocs []IOC) int {
	score := 0
	for _, ioc := range iocs {
		score += int(ioc.Confidence * 100)
	}
	if score > 100 {
		score = 100
	}
	return score
}
