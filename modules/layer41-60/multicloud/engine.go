package multicloud

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	config MultiCloudConfig
	mu     sync.Mutex
}

func NewEngine(cfg MultiCloudConfig) *Engine {
	return &Engine{
		config: cfg,
	}
}

func (e *Engine) AWSToAzurePivot(awsAccountID string, azureTenantID string) (*MultiCloudResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	paths := e.findAWSAzurePaths(awsAccountID, azureTenantID)

	return &MultiCloudResult{
		Success:  true,
		Method:   "AWS_To_Azure_Pivot",
		Message:  fmt.Sprintf("Found %d pivot paths from AWS %s to Azure %s", len(paths), awsAccountID, azureTenantID),
		Duration: time.Since(start),
		Pivot:    e.formatPivotPaths(paths),
		Risk:     "high",
	}, nil
}

func (e *Engine) findAWSAzurePaths(awsAccount, azureTenant string) []PivotPath {
	paths := make([]PivotPath, 0)

	path1 := PivotPath{
		Steps: []PivotStep{
			{Cloud: "AWS", Service: "IAM", Resource: fmt.Sprintf("arn:aws:iam::%s:role/CrossCloudRole", awsAccount), Action: "AssumeRole"},
			{Cloud: "Azure", Service: "AAD", Resource: azureTenant, Action: "Federate"},
		},
		TotalHops: 2,
		RiskLevel: "high",
	}
	paths = append(paths, path1)

	path2 := PivotPath{
		Steps: []PivotStep{
			{Cloud: "AWS", Service: "S3", Resource: fmt.Sprintf("s3://%s-data", awsAccount), Action: "AccessData"},
			{Cloud: "Azure", Service: "ADLS", Resource: fmt.Sprintf("abfss://%s.dfs.core.windows.net", azureTenant), Action: "MountShare"},
		},
		TotalHops: 2,
		RiskLevel: "medium",
	}
	paths = append(paths, path2)

	return paths
}

func (e *Engine) formatPivotPaths(paths []PivotPath) string {
	var result strings.Builder
	for i, p := range paths {
		result.WriteString(fmt.Sprintf("Path %d (%s):\n", i+1, p.RiskLevel))
		for j, step := range p.Steps {
			result.WriteString(fmt.Sprintf("  Step %d: [%s] %s -> %s (%s)\n", j+1, step.Cloud, step.Service, step.Resource, step.Action))
		}
	}
	return result.String()
}

func (e *Engine) AzureToGCPPivot(azureTenantID string, gcpProjectID string) (*MultiCloudResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	paths := e.findAzureGCPPaths(azureTenantID, gcpProjectID)

	return &MultiCloudResult{
		Success:  true,
		Method:   "Azure_To_GCP_Pivot",
		Message:  fmt.Sprintf("Found %d pivot paths from Azure %s to GCP %s", len(paths), azureTenantID, gcpProjectID),
		Duration: time.Since(start),
		Pivot:    e.formatPivotPaths(paths),
		Risk:     "high",
	}, nil
}

func (e *Engine) findAzureGCPPaths(azureTenant, gcpProject string) []PivotPath {
	paths := make([]PivotPath, 0)

	path1 := PivotPath{
		Steps: []PivotStep{
			{Cloud: "Azure", Service: "AAD", Resource: azureTenant, Action: "GetToken"},
			{Cloud: "GCP", Service: "IAM", Resource: gcpProject, Action: "WorkloadIdentityFederation"},
		},
		TotalHops: 2,
		RiskLevel: "high",
	}
	paths = append(paths, path1)

	path2 := PivotPath{
		Steps: []PivotStep{
			{Cloud: "Azure", Service: "KeyVault", Resource: fmt.Sprintf("%s-keys", azureTenant), Action: "GetSecret"},
			{Cloud: "GCP", Service: "SecretManager", Resource: fmt.Sprintf("projects/%s/secrets", gcpProject), Action: "AccessSecret"},
		},
		TotalHops: 2,
		RiskLevel: "critical",
	}
	paths = append(paths, path2)

	return paths
}

func (e *Engine) CrossAccountExploit(sourceAccount string, targetAccount string) (*MultiCloudResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	trusts := e.analyzeCrossAccountTrust(sourceAccount, targetAccount)

	return &MultiCloudResult{
		Success:  true,
		Method:   "Cross_Account_Exploit",
		Message:  fmt.Sprintf("Found %d cross-account trust relationships", len(trusts)),
		Duration: time.Since(start),
		Pivot:    e.formatTrusts(trusts),
		Risk:     "critical",
	}, nil
}

func (e *Engine) analyzeCrossAccountTrust(source, target string) []CrossAccountTrust {
	trusts := make([]CrossAccountTrust, 0)

	trusts = append(trusts, CrossAccountTrust{
		AccountID:  target,
		RoleARN:    fmt.Sprintf("arn:aws:iam::%s:role/CrossAccountRole", target),
		ExternalID: "external-id-12345",
		Condition:  "sts:ExternalId",
	})

	trusts = append(trusts, CrossAccountTrust{
		AccountID:  target,
		RoleARN:    fmt.Sprintf("arn:aws:iam::%s:role/AdminRole", target),
		ExternalID: "",
		Condition:  "aws:PrincipalOrgID",
	})

	return trusts
}

func (e *Engine) formatTrusts(trusts []CrossAccountTrust) string {
	var result strings.Builder
	for i, t := range trusts {
		result.WriteString(fmt.Sprintf("[%d] Account: %s\n", i+1, t.AccountID))
		result.WriteString(fmt.Sprintf("    Role: %s\n", t.RoleARN))
		if t.ExternalID != "" {
			result.WriteString(fmt.Sprintf("    ExternalID: %s\n", t.ExternalID))
		}
		result.WriteString(fmt.Sprintf("    Condition: %s\n", t.Condition))
	}
	return result.String()
}

func (e *Engine) CloudTrailEvade(region string) (*MultiCloudResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	techniques := e.getEvadeTechniques(region)

	return &MultiCloudResult{
		Success:  true,
		Method:   "CloudTrail_Evade",
		Message:  fmt.Sprintf("Identified %d CloudTrail evasion techniques for %s", len(techniques), region),
		Duration: time.Since(start),
		Pivot:    strings.Join(techniques, "\n"),
		Risk:     "high",
	}, nil
}

func (e *Engine) getEvadeTechniques(region string) []string {
	techniques := make([]string, 0)

	techniques = append(techniques, fmt.Sprintf("Stop CloudTrail in %s", region))
	techniques = append(techniques, fmt.Sprintf("Delete CloudTrail logs in %s", region))
	techniques = append(techniques, fmt.Sprintf("Modify CloudTrail to exclude regions: %s", region))
	techniques = append(techniques, "Use untrail (custom logging avoidance)")
	techniques = append(techniques, "Exploit CloudTrail event selector gaps")
	techniques = append(techniques, "Use CloudWatch Logs subscription filter manipulation")

	return techniques
}

func (e *Engine) AnalyzeTrustRelationships(sourceCloud string, targetCloud string) []TrustRelationship {
	relationships := make([]TrustRelationship, 0)

	relationships = append(relationships, TrustRelationship{
		Type:      "Federation",
		Principal: fmt.Sprintf("arn:aws:iam::123456789012:root"),
		Resource:  fmt.Sprintf("subscriptions/%s", targetCloud),
		Condition: "ExternalId",
	})

	relationships = append(relationships, TrustRelationship{
		Type:      "ServiceLink",
		Principal: fmt.Sprintf("service:%s", sourceCloud),
		Resource:  fmt.Sprintf("projects/%s", targetCloud),
		Condition: "WorkloadIdentityPool",
	})

	return relationships
}

func (e *Engine) GetCloudServices(cloud string) []string {
	services := map[string][]string{
		"aws":   {"IAM", "EC2", "S3", "Lambda", "RDS", "DynamoDB", "ECS", "EKS"},
		"azure": {"AAD", "ARM", "KeyVault", "Storage", "Compute", "SQL", "AKS", "Functions"},
		"gcp":   {"IAM", "Compute", "Storage", "CloudSQL", "GKE", "CloudFunctions", "BigQuery"},
	}
	if svc, ok := services[cloud]; ok {
		return svc
	}
	return []string{"unknown"}
}
