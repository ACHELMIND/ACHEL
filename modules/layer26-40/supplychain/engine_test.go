package supplychain

import (
	"testing"
)

func TestNPMTyposquat(t *testing.T) {
	engine := NewEngine(SupplyChainConfig{})

	result := engine.NPMTyposquat("express")

	if result.Type != DependencyTypeNPM {
		t.Errorf("Expected NPM type, got %v", result.Type)
	}
	if len(result.TyposquatHits) == 0 {
		t.Error("Expected at least one typosquat hit")
	}
	for _, hit := range result.TyposquatHits {
		if hit.SimilarTo != "express" {
			t.Errorf("Expected similarTo 'express', got %s", hit.SimilarTo)
		}
	}
}

func TestGitHubActionsInject(t *testing.T) {
	engine := NewEngine(SupplyChainConfig{})

	result := engine.GitHubActionsInject(".github/workflows/ci.yml")

	if len(result.CIInjection) == 0 {
		t.Error("Expected CI injection paths")
	}
	for _, ci := range result.CIInjection {
		if ci.Provider != CIProviderGitHubActions {
			t.Error("Expected GitHub Actions provider")
		}
		if ci.Injection == "" {
			t.Error("Injection point should not be empty")
		}
	}
}

func TestDockerfileInject(t *testing.T) {
	engine := NewEngine(SupplyChainConfig{})

	result := engine.DockerfileInject("Dockerfile")

	if result.Type != DependencyTypeDocker {
		t.Errorf("Expected Docker type, got %v", result.Type)
	}
	if len(result.DockerIssues) == 0 {
		t.Error("Expected Docker issues")
	}
	for _, issue := range result.DockerIssues {
		if issue.Issue == "" {
			t.Error("Issue description should not be empty")
		}
		if issue.Severity == "" {
			t.Error("Severity should not be empty")
		}
	}
}

func TestPreCommitHook(t *testing.T) {
	engine := NewEngine(SupplyChainConfig{})

	result := engine.PreCommitHook(".pre-commit-config.yaml")

	if len(result.HookIssues) == 0 {
		t.Error("Expected hook issues")
	}
	for _, hook := range result.HookIssues {
		if hook.HookType == "" {
			t.Error("Hook type should not be empty")
		}
		if hook.Severity == "" {
			t.Error("Severity should not be empty")
		}
	}
}

func TestEngineCreation(t *testing.T) {
	engine := NewEngine(SupplyChainConfig{})
	if engine == nil {
		t.Fatal("Engine should not be nil")
	}
}

func TestDependencyTypes(t *testing.T) {
	types := []DependencyType{
		DependencyTypeNPM, DependencyTypePyPI, DependencyTypeGo,
		DependencyTypeMaven, DependencyTypeRubyGems, DependencyTypeDocker,
	}
	for _, dt := range types {
		if dt.String() == "" {
			t.Errorf("DependencyType %d should have string", dt)
		}
	}
}

func TestCIProviders(t *testing.T) {
	providers := []CIProvider{
		CIProviderGitHubActions, CIProviderGitLabCI, CIProviderJenkins,
	}
	for _, p := range providers {
		if p.String() == "" {
			t.Errorf("CIProvider %d should have string", p)
		}
	}
}
