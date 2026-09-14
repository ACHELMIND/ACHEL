package report

import (
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

type ReportConfig struct {
	Title       string
	Engagement  string
	Author      string
	OutputDir   string
}

type Finding struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Severity    types.Severity    `json:"severity"`
	Category    string            `json:"category"`
	Description string            `json:"description"`
	Impact      string            `json:"impact"`
	Remediation string            `json:"remediation"`
	References  []string          `json:"references"`
	Evidence    []string          `json:"evidence"`
	Metadata    map[string]string `json:"metadata"`
}

type Engagement struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Target    string    `json:"target"`
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
	Findings  []Finding `json:"findings"`
	Evidence  []string  `json:"evidence"`
}

type Report struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Engagement string  `json:"engagement"`
	CreatedAt time.Time `json:"created_at"`
	Author    string    `json:"author"`
	Sections  []Section `json:"sections"`
}

type Section struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

type TechnicalReport struct {
	Report
	Findings  []Finding `json:"findings"`
	Evidence  []string  `json:"evidence"`
}

type ExecutiveSummary struct {
	TotalFindings  int     `json:"total_findings"`
	CriticalCount  int     `json:"critical_count"`
	HighCount      int     `json:"high_count"`
	MediumCount    int     `json:"medium_count"`
	LowCount       int     `json:"low_count"`
	RiskScore      float64 `json:"risk_score"`
	Summary        string  `json:"summary"`
}

type SeverityBreakdown struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type Metrics struct {
	Breakdown    SeverityBreakdown `json:"breakdown"`
	Total        int               `json:"total"`
	RiskScore    float64           `json:"risk_score"`
	Categories   map[string]int    `json:"categories"`
}
