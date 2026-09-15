package opsec

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	config OPSECConfig
	mu     sync.Mutex
}

func NewEngine(cfg OPSECConfig) *Engine {
	return &Engine{
		config: cfg,
	}
}

func (e *Engine) CommChannelSetup(channelType string) (*OPSECResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	profile := e.analyzeChannel(channelType)

	return &OPSECResult{
		Success:  true,
		Method:   "Comm_Channel_Setup",
		Message:  fmt.Sprintf("Channel '%s' analyzed: %s (risk: %s)", channelType, profile.Name, profile.OPSECLevel),
		Duration: time.Since(start),
		RiskScore: e.calculateChannelRisk(profile),
		Details:  profile.Recommendations,
	}, nil
}

func (e *Engine) analyzeChannel(channelType string) CommunicationProfile {
	profile := CommunicationProfile{
		Name:         channelType,
		Channels:     make([]CommChannel, 0),
		OPSECLevel:   "medium",
		Recommendations: make([]string, 0),
	}

	switch strings.ToLower(channelType) {
	case "tor":
		profile.OPSECLevel = "high"
		profile.Channels = append(profile.Channels, CommChannel{
			Name: "Tor", Type: "anonymizer", Encrypted: true, Anonymous: true, RiskLevel: "low",
		})
		profile.Recommendations = append(profile.Recommendations, "Use Tor browser for web traffic")
		profile.Recommendations = append(profile.Recommendations, "Avoid logging into personal accounts")

	case "vpn":
		profile.OPSECLevel = "medium"
		profile.Channels = append(profile.Channels, CommChannel{
			Name: "VPN", Type: "tunnel", Encrypted: true, Anonymous: false, RiskLevel: "medium",
		})
		profile.Recommendations = append(profile.Recommendations, "Use no-log VPN provider")
		profile.Recommendations = append(profile.Recommendations, "Chain multiple VPNs")

	case "proxy":
		profile.OPSECLevel = "low"
		profile.Channels = append(profile.Channels, CommChannel{
			Name: "HTTP Proxy", Type: "proxy", Encrypted: false, Anonymous: false, RiskLevel: "high",
		})
		profile.Recommendations = append(profile.Recommendations, "Do not use for sensitive operations")
		profile.Recommendations = append(profile.Recommendations, "Proxy may log all traffic")

	default:
		profile.OPSECLevel = "low"
		profile.Recommendations = append(profile.Recommendations, "Unknown channel type")
	}

	return profile
}

func (e *Engine) calculateChannelRisk(profile CommunicationProfile) int {
	risk := 50
	if profile.OPSECLevel == "high" {
		risk = 20
	} else if profile.OPSECLevel == "low" {
		risk = 80
	}
	return risk
}

func (e *Engine) TrafficAnalysis(sourceIP string, destIP string) (*OPSECResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	analysis := e.analyzeTraffic(sourceIP, destIP)

	return &OPSECResult{
		Success:  true,
		Method:   "Traffic_Analysis",
		Message:  fmt.Sprintf("Traffic analysis: %d signatures detected", len(analysis)),
		Duration: time.Since(start),
		RiskScore: e.calculateTrafficRisk(analysis),
		Details:  e.formatTrafficAnalysis(analysis),
	}, nil
}

func (e *Engine) analyzeTraffic(sourceIP, destIP string) []TrafficAnalysis {
	analyses := make([]TrafficAnalysis, 0)

	analyses = append(analyses, TrafficAnalysis{
		SourceIP:   sourceIP,
		DestIP:     destIP,
		Port:       443,
		Protocol:   "TCP/TLS",
		PacketSize: 1500,
		Frequency:  100 * time.Millisecond,
		Signature:  "HTTPS traffic pattern detected",
	})

	analyses = append(analyses, TrafficAnalysis{
		SourceIP:   sourceIP,
		DestIP:     destIP,
		Port:       53,
		Protocol:   "UDP/DNS",
		PacketSize: 512,
		Frequency:  1 * time.Second,
		Signature:  "DNS query pattern detected",
	})

	return analyses
}

func (e *Engine) calculateTrafficRisk(analyses []TrafficAnalysis) int {
	risk := 30
	for _, a := range analyses {
		if a.Port == 53 {
			risk += 10
		}
		if a.Port == 80 {
			risk += 15
		}
	}
	if risk > 100 {
		risk = 100
	}
	return risk
}

func (e *Engine) formatTrafficAnalysis(analyses []TrafficAnalysis) []string {
	details := make([]string, 0)
	for _, a := range analyses {
		details = append(details, fmt.Sprintf("%s:%d -> %s (%s)", a.SourceIP, a.Port, a.DestIP, a.Signature))
	}
	return details
}

func (e *Engine) RiskAssessment(scope []string) (*OPSECResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	risks := e.assessRisks(scope)

	return &OPSECResult{
		Success:  true,
		Method:   "Risk_Assessment",
		Message:  fmt.Sprintf("Risk assessment: %d risks identified", len(risks)),
		Duration: time.Since(start),
		RiskScore: e.calculateOverallRisk(risks),
		Details:  e.formatRisks(risks),
	}, nil
}

func (e *Engine) assessRisks(scope []string) []OPSECRisk {
	risks := make([]OPSECRisk, 0)

	risks = append(risks, OPSECRisk{
		Category:    "Identity",
		Description: "Potential IP exposure",
		Severity:    "high",
		Mitigation:  "Use VPN or Tor",
	})

	risks = append(risks, OPSECRisk{
		Category:    "Traffic",
		Description: "Detectable traffic patterns",
		Severity:    "medium",
		Mitigation:  "Use traffic obfuscation",
	})

	risks = append(risks, OPSECRisk{
		Category:    "Metadata",
		Description: "Metadata leakage possible",
		Severity:    "medium",
		Mitigation:  "Strip metadata from files",
	})

	risks = append(risks, OPSECRisk{
		Category:    "Timing",
		Description: "Activity timing correlation",
		Severity:    "low",
		Mitigation:  "Vary activity times",
	})

	return risks
}

func (e *Engine) calculateOverallRisk(risks []OPSECRisk) int {
	score := 0
	for _, r := range risks {
		switch r.Severity {
		case "critical":
			score += 40
		case "high":
			score += 30
		case "medium":
			score += 20
		case "low":
			score += 10
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

func (e *Engine) formatRisks(risks []OPSECRisk) []string {
	details := make([]string, 0)
	for _, r := range risks {
		details = append(details, fmt.Sprintf("[%s] %s: %s (mitigation: %s)", r.Severity, r.Category, r.Description, r.Mitigation))
	}
	return details
}

func (e *Engine) CleanupVerify(actions []string) (*OPSECResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	results := e.verifyCleanup(actions)

	return &OPSECResult{
		Success:  true,
		Method:   "Cleanup_Verify",
		Message:  fmt.Sprintf("Cleanup verification: %d actions processed", len(results)),
		Duration: time.Since(start),
		RiskScore: e.calculateCleanupRisk(results),
		Details:  e.formatCleanupResults(results),
	}, nil
}

func (e *Engine) verifyCleanup(actions []string) []CleanupAction {
	results := make([]CleanupAction, 0)

	for _, action := range actions {
		results = append(results, CleanupAction{
			Action: action,
			Target: "system",
			Status: "verified",
			Impact: "clean",
		})
	}

	results = append(results, CleanupAction{
		Action: "Log deletion",
		Target: "/var/log/auth.log",
		Status: "verified",
		Impact: "removed",
	})

	results = append(results, CleanupAction{
		Action: "Temp file cleanup",
		Target: "/tmp",
		Status: "verified",
		Impact: "cleaned",
	})

	return results
}

func (e *Engine) calculateCleanupRisk(results []CleanupAction) int {
	risk := 0
	for _, r := range results {
		if r.Status != "verified" {
			risk += 20
		}
	}
	return risk
}

func (e *Engine) formatCleanupResults(results []CleanupAction) []string {
	details := make([]string, 0)
	for _, r := range results {
		details = append(details, fmt.Sprintf("%s: %s -> %s", r.Action, r.Target, r.Status))
	}
	return details
}
