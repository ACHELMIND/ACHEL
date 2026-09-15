package supplychain

import "time"

type DependencyType int

const (
	DependencyTypeNPM DependencyType = iota
	DependencyTypePyPI
	DependencyTypeGo
	DependencyTypeMaven
	DependencyTypeRubyGems
	DependencyTypeDocker
	DependencyTypeGitHub
)

func (d DependencyType) String() string {
	return [...]string{"NPM", "PyPI", "Go", "Maven", "RubyGems", "Docker", "GitHub"}[d]
}

type CIProvider int

const (
	CIProviderGitHubActions CIProvider = iota
	CIProviderGitLabCI
	CIProviderJenkins
	CIProviderCircleCI
	CIProviderAzurePipelines
	CIProviderTravisCI
)

func (c CIProvider) String() string {
	return [...]string{
		"GitHub Actions", "GitLab CI", "Jenkins",
		"CircleCI", "Azure Pipelines", "Travis CI",
	}[c]
}

type SupplyChainConfig struct {
	TargetRepo    string
	TargetPackage string
	RegistryURL   string
	CIConfig      CIProvider
	Dockerfile    string
	ManifestFile  string
	LockFile      string
	PreCommitConf string
	SearchDepth   int
}

type SupplyChainResult struct {
	ID              string             `json:"id"`
	Type            DependencyType     `json:"type"`
	TyposquatHits   []TyposquatHit     `json:"typosquat_hits"`
	CIInjection     []CIInjectionPath  `json:"ci_injection"`
	DockerIssues    []DockerIssue      `json:"docker_issues"`
	HookIssues      []HookIssue        `json:"hook_issues"`
	RiskScore       int                `json:"risk_score"`
	Timestamp       time.Time          `json:"timestamp"`
}

type TyposquatHit struct {
	PackageName     string  `json:"package_name"`
	SimilarTo       string  `json:"similar_to"`
	Distance        int     `json:"distance"`
	Downloads       int     `json:"downloads"`
	PublishedDate   string  `json:"published_date"`
	Malicious       bool    `json:"malicious"`
	RiskIndicators  []string `json:"risk_indicators"`
}

type CIInjectionPath struct {
	Provider   CIProvider `json:"provider"`
	Workflow   string     `json:"workflow"`
	Injection  string     `json:"injection_point"`
	Payload    string     `json:"payload"`
	Risk       string     `json:"risk"`
}

type DockerIssue struct {
	Line        int    `json:"line"`
	Issue       string `json:"issue"`
	Severity    string `json:"severity"`
	Fix         string `json:"fix"`
}

type HookIssue struct {
	HookType    string `json:"hook_type"`
	Script      string `json:"script"`
	Issue       string `json:"issue"`
	Severity    string `json:"severity"`
}
