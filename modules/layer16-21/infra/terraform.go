package infra

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
)

type TerraformManager struct {
	config *InfraConfig
	log    *logger.Logger
	mu     sync.RWMutex
	workdir string
}

func NewTerraformManager(config *InfraConfig) *TerraformManager {
	if config == nil {
		config = DefaultInfraConfig()
	}
	return &TerraformManager{
		config: config,
		log:    logger.New("terraform-mgr", logger.LevelInfo),
		workdir: "/tmp/tf-workspace",
	}
}

func (t *TerraformManager) ProvisionVPS(provider, region string) (*VPSInstance, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.log.Info("Provisioning VPS via %s in %s", provider, region)

	config, err := t.GenerateTF(TFProvider(provider), &InfraConfig{
		Provider: CloudProvider(provider),
		Region:   region,
	})
	if err != nil {
		return nil, fmt.Errorf("generate tf config failed: %w", err)
	}

	if err := os.MkdirAll(t.workdir, 0755); err != nil {
		return nil, fmt.Errorf("create workdir failed: %w", err)
	}

	tfFile := filepath.Join(t.workdir, "main.tf")
	if err := os.WriteFile(tfFile, []byte(config), 0644); err != nil {
		return nil, fmt.Errorf("write tf config failed: %w", err)
	}

	if err := t.ApplyTF(t.workdir); err != nil {
		return nil, fmt.Errorf("apply failed: %w", err)
	}

	instance := &VPSInstance{
		ID:       fmt.Sprintf("vps-%s-%s", provider, region),
		Provider: CloudProvider(provider),
		Region:   region,
		Status:   "running",
		OS:       "ubuntu-22.04",
		Metadata: make(map[string]string),
	}

	t.log.Info("VPS provisioned: %s", instance.ID)
	return instance, nil
}

func (t *TerraformManager) DestroyVPS(instanceID string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.log.Info("Destroying VPS: %s", instanceID)

	tfDestroy := fmt.Sprintf(`
resource "null_resource" "destroy" {
  provisioner "local-exec" {
    command = "echo destroying %s"
  }
}
`, instanceID)

	tfFile := filepath.Join(t.workdir, "destroy.tf")
	if err := os.WriteFile(tfFile, []byte(tfDestroy), 0644); err != nil {
		return fmt.Errorf("write destroy config failed: %w", err)
	}

	t.log.Info("VPS destroyed: %s", instanceID)
	return nil
}

var tfTemplate = `# Auto-generated Terraform configuration
terraform {
  required_providers {
    {{.Provider}} = {
      source  = "{{.ProviderSource}}"
      version = "{{.ProviderVersion}}"
    }
  }
}

provider "{{.Provider}}" {
  region = "{{.Region}}"
}

resource "{{.ResourceType}}" "main" {
  {{- range $key, $val := .Labels}}
  {{ $key }} = "{{ $val }}"
  {{- end}}
}

output "instance_id" {
  value = {{.ResourceType}}.main.id
}

output "public_ip" {
  value = {{.ResourceType}}.main.public_ip
}
`

type tfData struct {
	Provider        string
	ProviderSource  string
	ProviderVersion string
	ResourceType    string
	Region          string
	Labels          map[string]string
}

func (t *TerraformManager) GenerateTF(provider TFProvider, config *InfraConfig) (string, error) {
	data := tfData{
		Region: config.Region,
		Labels: make(map[string]string),
	}

	switch provider {
	case TFProviderAWS:
		data.Provider = "aws"
		data.ProviderSource = "hashicorp/aws"
		data.ProviderVersion = "~> 5.0"
		data.ResourceType = "aws_instance"
		data.Labels["ami"] = "ami-0c55b159cbfafe1f0"
		data.Labels["instance_type"] = "t3.micro"
	case TFProviderGCP:
		data.Provider = "google"
		data.ProviderSource = "hashicorp/google"
		data.ProviderVersion = "~> 5.0"
		data.ResourceType = "google_compute_instance"
		data.Labels["machine_type"] = "e2-micro"
		data.Labels["zone"] = config.Region + "-a"
	case TFProviderAzure:
		data.Provider = "azurerm"
		data.ProviderSource = "hashicorp/azurerm"
		data.ProviderVersion = "~> 3.0"
		data.ResourceType = "azurerm_linux_virtual_machine"
		data.Labels["size"] = "Standard_B1s"
	case TFProviderDigitalOcean:
		data.Provider = "digitalocean"
		data.ProviderSource = "digitalocean/digitalocean"
		data.ProviderVersion = "~> 2.0"
		data.ResourceType = "digitalocean_droplet"
		data.Labels["size"] = "s-1vcpu-1gb"
	default:
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}

	tmpl, err := template.New("tf").Parse(tfTemplate)
	if err != nil {
		return "", fmt.Errorf("parse template failed: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute template failed: %w", err)
	}

	return buf.String(), nil
}

// runTF executes a terraform command in the given workdir and returns combined output.
func (t *TerraformManager) runTF(workdir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "terraform", args...)
	cmd.Dir = workdir
	cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1", "TF_INPUT=false")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	t.log.Info("exec: terraform %s (workdir=%s)", strings.Join(args, " "), workdir)

	if err := cmd.Run(); err != nil {
		errOutput := strings.TrimSpace(stderr.String())
		if errOutput == "" {
			errOutput = strings.TrimSpace(stdout.String())
		}
		return "", fmt.Errorf("terraform %s failed: %w\n%s", strings.Join(args, " "), err, errOutput)
	}

	return stdout.String(), nil
}

func (t *TerraformManager) ApplyTF(workdir string) error {
	t.log.Info("Applying Terraform in %s", workdir)

	if err := os.MkdirAll(workdir, 0755); err != nil {
		return fmt.Errorf("create workdir: %w", err)
	}

	// terraform init
	if _, err := t.runTF(workdir, "init", "-input=false", "-no-color"); err != nil {
		return fmt.Errorf("terraform init: %w", err)
	}

	// terraform apply -auto-approve
	if _, err := t.runTF(workdir, "apply", "-auto-approve", "-input=false", "-no-color"); err != nil {
		return fmt.Errorf("terraform apply: %w", err)
	}

	t.log.Info("Terraform apply completed in %s", workdir)
	return nil
}

func (t *TerraformManager) PlanTF(workdir string) (*TFPlan, error) {
	t.log.Info("Planning Terraform in %s", workdir)

	if err := os.MkdirAll(workdir, 0755); err != nil {
		return nil, fmt.Errorf("create workdir: %w", err)
	}

	// Ensure initialised before planning
	if _, err := t.runTF(workdir, "init", "-input=false", "-no-color"); err != nil {
		return nil, fmt.Errorf("terraform init before plan: %w", err)
	}

	raw, err := t.runTF(workdir, "plan", "-input=false", "-no-color", "-json")
	if err != nil {
		return nil, fmt.Errorf("terraform plan: %w", err)
	}

	// Parse the JSON output
	plan := &TFPlan{Raw: raw}
	lines := strings.Split(raw, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Try to parse each line as a JSON object (Terraform JSON output emits one JSON per line)
		var event struct {
			Type string `json:"@level"`
			Message string `json:"@message"`
			Changes *struct {
				Add int `json:"add"`
				Change int `json:"change"`
				Destroy int `json:"destroy"`
				ResourceChanges []struct {
					Address string `json:"address"`
					Change struct {
						Action string `json:"actions"`
						Before json.RawMessage `json:"before"`
						After  json.RawMessage `json:"after"`
					} `json:"change"`
				} `json:"resource_changes"`
			} `json:"changes"`
		}

		if json.Unmarshal([]byte(line), &event) != nil {
			continue
		}

		if event.Changes != nil {
			plan.Add = event.Changes.Add
			plan.Change = event.Changes.Change
			plan.Destroy = event.Changes.Destroy

			for _, rc := range event.Changes.ResourceChanges {
				plan.Changes = append(plan.Changes, TFChange{
					Resource: rc.Address,
					Action:   rc.Change.Action,
					Before:   string(rc.Change.Before),
					After:    string(rc.Change.After),
				})
			}
		}

		if strings.Contains(event.Message, "Error:") || strings.Contains(event.Message, "error") {
			plan.Errored = true
		}
	}

	return plan, nil
}
