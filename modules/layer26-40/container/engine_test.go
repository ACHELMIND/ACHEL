package container

import (
	"testing"
	"time"
)

func TestDockerEscape(t *testing.T) {
	engine := NewEngine(ContainerEscapeConfig{
		ContainerType: ContainerTypeDocker,
		DockerSocket:  "/var/run/docker.sock",
		Timeout:       30 * time.Second,
	})

	result := engine.DockerEscape("test-container")

	if result.ID == "" {
		t.Error("Expected non-empty ID")
	}
	if result.ContainerType != ContainerTypeDocker {
		t.Errorf("Expected ContainerType Docker, got %v", result.ContainerType)
	}
	if result.Timestamp.IsZero() {
		t.Error("Expected non-zero timestamp")
	}
}

func TestKubernetesAPIAccess(t *testing.T) {
	engine := NewEngine(ContainerEscapeConfig{})

	config := KubernetesConfig{
		APIServer: "https://kubernetes.default.svc",
		Token:     "eyJhbGciOiJSUzI1NiIs...",
		Namespace: "production",
		RBACEnum:  true,
		NodeEnum:  true,
	}

	result := engine.KubernetesAPIAccess(config)

	if result.APIServer != "https://kubernetes.default.svc" {
		t.Errorf("Expected APIServer 'https://kubernetes.default.svc', got %s", result.APIServer)
	}
	if len(result.Namespaces) == 0 {
		t.Error("Expected at least one namespace")
	}
	if len(result.Roles) == 0 {
		t.Error("Expected at least one role")
	}
	if len(result.EscapePaths) == 0 {
		t.Error("Expected at least one escape path")
	}
}

func TestExtractSecrets(t *testing.T) {
	engine := NewEngine(ContainerEscapeConfig{})

	result := engine.ExtractSecrets("test-container-abc123")

	if result.SecretsFound == nil {
		t.Error("Expected secrets to be found")
	}
	if len(result.SecretsFound) == 0 {
		t.Error("Expected at least one secret")
	}
	for _, s := range result.SecretsFound {
		if s.Key == "" {
			t.Error("Secret key should not be empty")
		}
		if s.Source == "" {
			t.Error("Secret source should not be empty")
		}
	}
}

func TestContainerEnum(t *testing.T) {
	engine := NewEngine(ContainerEscapeConfig{})

	result := engine.ContainerEnum("web-app-001")

	if result.ContainerName != "web-app-001" {
		t.Errorf("Expected ContainerName 'web-app-001', got %s", result.ContainerName)
	}
	if result.ContainerInfo.Image == "" {
		t.Error("Expected image info")
	}
	if result.ContainerInfo.PID == 0 {
		t.Error("Expected PID info")
	}
	if !result.Success {
		t.Error("Expected success")
	}
}

func TestEngineCreation(t *testing.T) {
	engine := NewEngine(ContainerEscapeConfig{})
	if engine == nil {
		t.Fatal("Engine should not be nil")
	}
	if engine.config.DockerSocket != "/var/run/docker.sock" {
		t.Error("Default Docker socket should be set")
	}
}
