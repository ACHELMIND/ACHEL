package threatintel

import "time"

type IOCType int

const (
	IOCTypeIP IOCType = iota
	IOCTypeDomain
	IOCTypeURL
	IOCTypeFileHash
	IOCTypeEmailAddress
	IOCTypeMutex
	IOCTypeRegistryKey
	IOCTypeJA3
)

func (i IOCType) String() string {
	return [...]string{
		"IP", "Domain", "URL", "FileHash",
		"EmailAddress", "Mutex", "RegistryKey", "JA3",
	}[i]
}

type ThreatIntelConfig struct {
	Target        string
	IOCTypes      []IOCType
	FeedURLs      []string
	APIKeys       map[string]string
	MITREMapping  bool
	ReportFormat  string
	LookbackDays  int
	IncludeHash   bool
}

type IntelResult struct {
	ID            string        `json:"id"`
	Target        string        `json:"target"`
	IOCs          []IOC         `json:"iocs"`
	ThreatActors  []ThreatActor `json:"threat_actors"`
	MITREMapping  []MITRETechnique `json:"mitre_mapping"`
	Reports       []IntelReport `json:"reports"`
	RiskScore     int           `json:"risk_score"`
	Timestamp     time.Time     `json:"timestamp"`
}

type IOC struct {
	Type       IOCType  `json:"type"`
	Value      string   `json:"value"`
	Confidence float64  `json:"confidence"`
	Source     string   `json:"source"`
	Tags       []string `json:"tags"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Context    string   `json:"context"`
}

type ThreatActor struct {
	Name        string   `json:"name"`
	Aliases     []string `json:"aliases"`
	Attribution string   `json:"attribution"`
	Motivation  string   `json:"motivation"`
	TP          string   `json:"tp"`
	Country     string   `json:"country"`
	Techniques  []string `json:"techniques"`
	Active      bool     `json:"active"`
}

type MITRETechnique struct {
	TechniqueID string `json:"technique_id"`
	Name        string `json:"name"`
	Tactic      string `json:"tactic"`
	Description string `json:"description"`
	Count       int    `json:"count"`
}

type IntelReport struct {
	Title       string    `json:"title"`
	Summary     string    `json:"summary"`
	IOCs        []IOC     `json:"iocs"`
	TTPs        []string  `json:"ttps"`
	Severity    string    `json:"severity"`
	PublishedAt time.Time `json:"published_at"`
	Source      string    `json:"source"`
}

type ThreatFeed struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Format   string `json:"format"`
	IOCCount int    `json:"ioc_count"`
	LastSync time.Time `json:"last_sync"`
	Health   string `json:"health"`
}
