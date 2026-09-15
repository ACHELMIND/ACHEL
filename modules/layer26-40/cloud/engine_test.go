package cloud

import (
	"testing"
)

func TestAWSIAMPrivesc(t *testing.T) {
	engine := NewEngine(CloudConfig{
		Provider: CloudProviderAWS,
		Region:   "us-east-1",
	})

	result := engine.AWSIAMPrivesc(IAMConfig{
		RoleEnum:       true,
		UserEnum:       true,
		PolicyAnalysis: true,
		PrivescDetect:  true,
	})

	if result.Provider != CloudProviderAWS {
		t.Errorf("Expected AWS provider, got %v", result.Provider)
	}
	if len(result.IAMPolicies) == 0 {
		t.Error("Expected IAM policies")
	}
	if len(result.PrivPaths) == 0 {
		t.Error("Expected privilege escalation paths")
	}
	if len(result.Buckets) == 0 {
		t.Error("Expected buckets")
	}
}

func TestAzureADAttack(t *testing.T) {
	engine := NewEngine(CloudConfig{Provider: CloudProviderAzure})

	result := engine.AzureADAttack(AzureADConfig{
		TenantID:       "tenant-123",
		SubscriptionID: "sub-456",
	})

	if result.Provider != CloudProviderAzure {
		t.Errorf("Expected Azure provider, got %v", result.Provider)
	}
	if len(result.IAMPolicies) == 0 {
		t.Error("Expected Azure IAM policies")
	}
}

func TestGCPServiceAccountAbuse(t *testing.T) {
	engine := NewEngine(CloudConfig{Provider: CloudProviderGCP})

	result := engine.GCPServiceAccountAbuse(GCPConfig{
		ProjectID: "my-project-123",
	})

	if result.Provider != CloudProviderGCP {
		t.Errorf("Expected GCP provider, got %v", result.Provider)
	}
	if len(result.PrivPaths) == 0 {
		t.Error("Expected privilege paths")
	}
}

func TestCloudEnum(t *testing.T) {
	engine := NewEngine(CloudConfig{})

	providers := []CloudProvider{CloudProviderAWS, CloudProviderAzure, CloudProviderGCP}
	for _, provider := range providers {
		result := engine.CloudEnum(provider)
		if result.Provider != provider {
			t.Errorf("Expected provider %v, got %v", provider, result.Provider)
		}
		if result.AccountID == "" {
			t.Error("Expected account ID")
		}
	}
}

func TestEngineCreation(t *testing.T) {
	engine := NewEngine(CloudConfig{})
	if engine == nil {
		t.Fatal("Engine should not be nil")
	}
}
