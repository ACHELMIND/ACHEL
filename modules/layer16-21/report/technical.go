package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

type TechnicalReportGen struct {
	config  *ReportConfig
	sections []Section
}

func NewTechnicalReportGen(config *ReportConfig) *TechnicalReportGen {
	return &TechnicalReportGen{config: config}
}

func (tr *TechnicalReportGen) Generate(findings []Finding, evidence []string) (*TechnicalReport, error) {
	report := &TechnicalReport{
		Report: Report{
			ID:        types.GenerateID(),
			Title:     tr.config.Title + " - Technical Report",
			CreatedAt: time.Now().UTC(),
			Author:    tr.config.Author,
			Sections:  make([]Section, 0),
		},
		Findings: findings,
		Evidence: evidence,
	}

	tr.addFindingsSection(findings)
	tr.addEvidenceSection(evidence)

	report.Sections = tr.sections
	return report, nil
}

func (tr *TechnicalReportGen) AddSection(name, content string) {
	tr.sections = append(tr.sections, Section{Name: name, Content: content})
}

func (tr *TechnicalReportGen) RenderMarkdown() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# %s - Technical Report\n\n", tr.config.Title))
	sb.WriteString(fmt.Sprintf("Author: %s\n", tr.config.Author))
	sb.WriteString(fmt.Sprintf("Date: %s\n\n", time.Now().UTC().Format("2006-01-02")))

	for _, s := range tr.sections {
		sb.WriteString(fmt.Sprintf("## %s\n\n%s\n\n", s.Name, s.Content))
	}

	return sb.String()
}

func (tr *TechnicalReportGen) RenderJSON() ([]byte, error) {
	report := &TechnicalReport{
		Report: Report{
			ID:        types.GenerateID(),
			Title:     tr.config.Title + " - Technical Report",
			CreatedAt: time.Now().UTC(),
			Author:    tr.config.Author,
			Sections:  tr.sections,
		},
	}
	return json.Marshal(report)
}

func (tr *TechnicalReportGen) addFindingsSection(findings []Finding) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Total findings: %d\n\n", len(findings)))

	for i, f := range findings {
		sb.WriteString(fmt.Sprintf("### Finding %d: %s\n", i+1, f.Title))
		sb.WriteString(fmt.Sprintf("- Severity: %s\n", f.Severity))
		sb.WriteString(fmt.Sprintf("- Category: %s\n", f.Category))
		sb.WriteString(fmt.Sprintf("- Description: %s\n", f.Description))
		sb.WriteString(fmt.Sprintf("- Impact: %s\n", f.Impact))
		sb.WriteString(fmt.Sprintf("- Remediation: %s\n\n", f.Remediation))
	}

	tr.AddSection("Findings", sb.String())
}

func (tr *TechnicalReportGen) addEvidenceSection(evidence []string) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Evidence items: %d\n\n", len(evidence)))

	for i, e := range evidence {
		sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, e))
	}

	tr.AddSection("Evidence", sb.String())
}
