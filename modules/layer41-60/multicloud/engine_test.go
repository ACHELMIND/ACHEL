package multicloud

import (
	"strings"
	"testing"
)

func newTestEngine() *Engine {
	return NewEngine(MultiCloudConfig{
		SourceCloud: "aws",
		TargetCloud: "azure",
	})
}

func TestAWSToAzurePivot(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.AWSToAzurePivot("123456789012", "tenant-abc")
	if err != nil {
		t.Fatalf("AWSToAzurePivot failed: %v", err)
	}
	if !result.Success {
		t.Error("AWSToAzurePivot reported failure")
	}
	if result.Method != "AWS_To_Azure_Pivot" {
		t.Errorf("expected method AWS_To_Azure_Pivot, got %s", result.Method)
	}
}

func TestAWSToAzurePivotPaths(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.AWSToAzurePivot("123456789012", "tenant-abc")
	if err != nil {
		t.Fatalf("AWSToAzurePivot failed: %v", err)
	}
	if !strings.Contains(result.Pivot, "Step") {
		t.Error("should contain pivot steps")
	}
}

func TestAzureToGCPPivot(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.AzureToGCPPivot("tenant-abc", "gcp-project-123")
	if err != nil {
		t.Fatalf("AzureToGCPPivot failed: %v", err)
	}
	if !result.Success {
		t.Error("AzureToGCPPivot reported failure")
	}
	if result.Method != "Azure_To_GCP_Pivot" {
		t.Errorf("expected method Azure_To_GCP_Pivot, got %s", result.Method)
	}
}

func TestCrossAccountExploit(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.CrossAccountExploit("111111111111", "222222222222")
	if err != nil {
		t.Fatalf("CrossAccountExploit failed: %v", err)
	}
	if !result.Success {
		t.Error("CrossAccountExploit reported failure")
	}
	if result.Risk != "critical" {
		t.Errorf("expected critical risk, got %s", result.Risk)
	}
}

func TestCloudTrailEvade(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.CloudTrailEvade("us-east-1")
	if err != nil {
		t.Fatalf("CloudTrailEvade failed: %v", err)
	}
	if !result.Success {
		t.Error("CloudTrailEvade reported failure")
	}
	if !strings.Contains(result.Pivot, "CloudTrail") {
		t.Error("should mention CloudTrail")
	}
}

func TestAnalyzeTrustRelationships(t *testing.T) {
	eng := newTestEngine()
	rels := eng.AnalyzeTrustRelationships("aws", "azure")
	if len(rels) == 0 {
		t.Error("should return trust relationships")
	}
}

func TestGetCloudServices(t *testing.T) {
	eng := newTestEngine()
	awsServices := eng.GetCloudServices("aws")
	if len(awsServices) == 0 {
		t.Error("should return AWS services")
	}
	hasIAM := false
	for _, s := range awsServices {
		if s == "IAM" {
			hasIAM = true
		}
	}
	if !hasIAM {
		t.Error("should include IAM")
	}
}

func TestGetCloudServicesUnknown(t *testing.T) {
	eng := newTestEngine()
	services := eng.GetCloudServices("unknown")
	if len(services) != 1 || services[0] != "unknown" {
		t.Error("unknown cloud should return unknown")
	}
}
