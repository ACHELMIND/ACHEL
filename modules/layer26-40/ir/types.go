package ir

import "time"

type IRPhase int

const (
	IRPhasePreparation IRPhase = iota
	IRPhaseIdentification
	IRPhaseContainment
	IRPhaseEradication
	IRPhaseRecovery
	IRPhaseLessons
)

func (i IRPhase) String() string {
	return [...]string{
		"Preparation", "Identification", "Containment",
		"Eradication", "Recovery", "LessonsLearned",
	}[i]
}

type IRConfig struct {
	PlaybookPath  string
	EvidenceDir   string
	Scope         []string
	Severity      string
	TimelineStart time.Time
	TimelineEnd   time.Time
	AutoContain   bool
	NotifySOC     bool
	NotifyExec    bool
}

type IRResult struct {
	ID            string        `json:"id"`
	Phase         IRPhase       `json:"phase"`
	Playbook      string        `json:"playbook"`
	Findings      []Finding     `json:"findings"`
	Actions       []IRAction    `json:"actions"`
	Evidence      []Evidence    `json:"evidence"`
	Timeline      []TimelineEntry `json:"timeline"`
	Metrics       IRMetrics     `json:"metrics"`
	Timestamp     time.Time     `json:"timestamp"`
}

type Finding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Details     string `json:"details"`
	IOCs        []string `json:"iocs"`
	AffectedHosts []string `json:"affected_hosts"`
}

type IRAction struct {
	Phase       IRPhase   `json:"phase"`
	Action      string    `json:"action"`
	Result      string    `json:"result"`
	Automated   bool      `json:"automated"`
	Timestamp   time.Time `json:"timestamp"`
}

type Evidence struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Path        string    `json:"path"`
	Hash        string    `json:"hash"`
	Timestamp   time.Time `json:"timestamp"`
	CollectedBy string    `json:"collected_by"`
}

type TimelineEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Event     string    `json:"event"`
	Phase     IRPhase   `json:"phase"`
	Actor     string    `json:"actor"`
}

type IRMetrics struct {
	TotalFindings   int     `json:"total_findings"`
	CriticalCount   int     `json:"critical_count"`
	HighCount       int     `json:"high_count"`
	MediumCount     int     `json:"medium_count"`
	LowCount        int     `json:"low_count"`
	ContainmentTime int     `json:"containment_time_minutes"`
	EradicationTime int     `json:"eradication_time_minutes"`
	RecoveryTime    int     `json:"recovery_time_minutes"`
	TotalDowntime   int     `json:"total_downtime_minutes"`
}

type Playbook struct {
	Name        string       `json:"name"`
	Phase       IRPhase      `json:"phase"`
	Steps       []PlaybookStep `json:"steps"`
	Automated   bool         `json:"automated"`
}

type PlaybookStep struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Command     string `json:"command"`
	AutoRun     bool   `json:"auto_run"`
}
