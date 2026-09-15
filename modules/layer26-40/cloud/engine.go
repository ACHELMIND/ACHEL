package cloud

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Engine struct {
	config CloudConfig
}

func NewEngine(config CloudConfig) *Engine {
	return &Engine{config: config}
}

func (e *Engine) AWSIAMPrivesc(iamConfig IAMConfig) CloudResult {
	result := CloudResult{
		ID:          uuid.New().String(),
		Provider:    CloudProviderAWS,
		AccountID:   e.getAccountID(),
		Timestamp:   time.Now(),
	}

	if iamConfig.RoleEnum {
		policies := e.enumerateRoles()
		result.IAMPolicies = policies
	}

	if iamConfig.PrivescDetect {
		paths := e.detectPrivescPaths(result.IAMPolicies)
		result.PrivPaths = paths
	}

	if iamConfig.UserEnum {
		buckets := e.enumerateBuckets()
		result.Buckets = buckets
		instances := e.enumerateInstances()
		result.Instances = instances
	}

	return result
}

func (e *Engine) AzureADAttack(azureConfig AzureADConfig) CloudResult {
	result := CloudResult{
		ID:        uuid.New().String(),
		Provider:  CloudProviderAzure,
		AccountID: azureConfig.TenantID,
		Timestamp: time.Now(),
	}

	result.IAMPolicies = []IAMPolicy{
		{Name: "Global Admin", ARN: fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments", azureConfig.SubscriptionID), Effect: "Allow", Actions: []string{"*"}, Resources: []string{"*"}},
	}

	result.PrivPaths = []PrivescPath{
		{From: "User", To: "Global Admin", Method: "PIM Activation", Risk: "critical", Actions: []string{"microsoft.directory/roleAssignments/write"}},
		{From: "App Registration", To: "Service Principal", Method: "Credential Reset", Risk: "high", Actions: []string{"microsoft.directory/applications/credentials/update"}},
	}

	result.Secrets = append(result.Secrets, SecretEntry{Key: "client_secret", Value: "***REDACTED***", Source: "app_registration", Severity: "high"})

	return result
}

func (e *Engine) GCPServiceAccountAbuse(gcpConfig GCPConfig) CloudResult {
	result := CloudResult{
		ID:        uuid.New().String(),
		Provider:  CloudProviderGCP,
		AccountID: gcpConfig.ProjectID,
		Timestamp: time.Now(),
	}

	result.IAMPolicies = []IAMPolicy{
		{Name: "Service Account User", ARN: fmt.Sprintf("projects/%s/serviceAccounts/*", gcpConfig.ProjectID), Effect: "Allow", Actions: []string{"iam.serviceAccounts.actAs", "iam.serviceAccounts.getAccessToken"}, Resources: []string{"*"}},
	}

	result.PrivPaths = []PrivescPath{
		{From: "Service Account", To: "Project Editor", Method: "Token Impersonation", Risk: "critical", Actions: []string{"iam.serviceAccounts.getAccessToken", "resourcemanager.projects.get"}},
	}

	result.Secrets = append(result.Secrets, SecretEntry{Key: "service_account_key", Value: "***REDACTED***", Source: "metadata", Severity: "critical"})

	return result
}

func (e *Engine) CloudEnum(provider CloudProvider) CloudResult {
	result := CloudResult{
		ID:        uuid.New().String(),
		Provider:  provider,
		AccountID: e.getAccountID(),
		Timestamp: time.Now(),
	}

	switch provider {
	case CloudProviderAWS:
		result.IAMPolicies = e.enumerateRoles()
		result.Buckets = e.enumerateBuckets()
		result.Instances = e.enumerateInstances()
		result.Lambdas = e.enumerateLambdas()
	case CloudProviderAzure:
		result.IAMPolicies = []IAMPolicy{{Name: "Reader", Effect: "Allow", Actions: []string{"read"}, Resources: []string{"*"}}}
	case CloudProviderGCP:
		result.IAMPolicies = []IAMPolicy{{Name: "Viewer", Effect: "Allow", Actions: []string{"get*"}, Resources: []string{"*"}}}
	}

	return result
}

func (e *Engine) enumerateRoles() []IAMPolicy {
	return []IAMPolicy{
		{Name: "AdministratorAccess", ARN: "arn:aws:iam::policy/AdministratorAccess", Effect: "Allow", Actions: []string{"*"}, Resources: []string{"*"}},
		{Name: "PowerUserAccess", ARN: "arn:aws:iam::policy/PowerUserAccess", Effect: "Allow", Actions: []string{"*"}, Resources: []string{"*"}, Condition: "NotAction: iam:*"},
		{Name: "S3ReadOnlyAccess", ARN: "arn:aws:iam::policy/AmazonS3ReadOnlyAccess", Effect: "Allow", Actions: []string{"s3:GetObject", "s3:ListBucket"}, Resources: []string{"*"}},
	}
}

func (e *Engine) detectPrivescPaths(policies []IAMPolicy) []PrivescPath {
	var paths []PrivescPath
	for _, p := range policies {
		for _, action := range p.Actions {
			if action == "*" || strings.Contains(action, "iam:PassRole") || strings.Contains(action, "sts:AssumeRole") {
				paths = append(paths, PrivescPath{
					From:    p.Name,
					To:      "Administrator",
					Method:  action,
					Risk:    "critical",
					Actions: []string{action},
				})
			}
			if strings.Contains(action, "lambda:CreateFunction") || strings.Contains(action, "lambda:InvokeFunction") {
				paths = append(paths, PrivescPath{
					From:    p.Name,
					To:      "Lambda Execution",
					Method:  "Lambda Privesc",
					Risk:    "high",
					Actions: []string{action},
				})
			}
		}
	}
	return paths
}

func (e *Engine) enumerateBuckets() []BucketInfo {
	return []BucketInfo{
		{Name: "backup-data-2024", Region: "us-east-1", Public: false, Encrypted: true},
		{Name: "logs-archive", Region: "us-west-2", Public: true, Encrypted: false},
	}
}

func (e *Engine) enumerateInstances() []InstanceInfo {
	return []InstanceInfo{
		{ID: "i-0abc123def456789", Name: "web-server-1", State: "running", Type: "t3.medium", PublicIP: "52.12.34.56", IAMRole: "WebServerRole"},
	}
}

func (e *Engine) enumerateLambdas() []LambdaInfo {
	return []LambdaInfo{
		{Name: "process-data", ARN: "arn:aws:lambda:us-east-1:123456789:function:process-data", Runtime: "python3.9", Role: "LambdaExecutionRole", EnvVars: map[string]string{"DB_PASSWORD": "***"}, Memory: 256, Timeout: 30},
	}
}

func (e *Engine) getAccountID() string {
	return "123456789012"
}
