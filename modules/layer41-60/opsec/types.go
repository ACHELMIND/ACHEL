package opsec

import "time"

type OPSECConfig struct {
	Project     string        `json:"project"`
	Team        string        `json:"team"`
	Timeout     time.Duration `json:"timeout"`
}

type OPSECResult struct {
	Success  bool          `json:"success"`
	Method   string        `json:"method"`
	Message  string        `json:"message"`
	Duration time.Duration `json:"duration"`
	RiskScore int          `json:"risk_score"`
	Details  []string      `json:"details"`
}

type CommChannel struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Encrypted   bool   `json:"encrypted"`
	Anonymous   bool   `json:"anonymous"`
	RiskLevel   string `json:"risk_level"`
}

type OPSECRisk struct {
	Category    string `json:"category"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Mitigation  string `json:"mitigation"`
}

type TrafficAnalysis struct {
	SourceIP    string        `json:"source_ip"`
	DestIP      string        `json:"dest_ip"`
	Port        int           `json:"port"`
	Protocol    string        `json:"protocol"`
	PacketSize  int           `json:"packet_size"`
	Frequency   time.Duration `json:"frequency"`
	Signature   string        `json:"signature"`
}

type RiskScore struct {
	Overall    int            `json:"overall"`
	Categories map[string]int `json:"categories"`
}

type CleanupAction struct {
	Action   string `json:"action"`
	Target   string `json:"target"`
	Status   string `json:"status"`
	Impact   string `json:"impact"`
}

type CommunicationProfile struct {
	Name         string            `json:"name"`
	Channels     []CommChannel     `json:"channels"`
	OPSECLevel   string            `json:"opsec_level"`
	Recommendations []string       `json:"recommendations"`
}
