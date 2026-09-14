package infra

import (
	"testing"
)

func TestNewTerraformManager(t *testing.T) {
	config := DefaultInfraConfig()
	mgr := NewTerraformManager(config)

	if mgr == nil {
		t.Fatal("manager should not be nil")
	}

	if mgr.config == nil {
		t.Fatal("config should not be nil")
	}

	if mgr.log == nil {
		t.Fatal("logger should not be nil")
	}
}

func TestNewTerraformManagerNilConfig(t *testing.T) {
	mgr := NewTerraformManager(nil)

	if mgr == nil {
		t.Fatal("manager should not be nil")
	}

	if mgr.config == nil {
		t.Fatal("config should not be nil after nil config")
	}
}

func TestGenerateTF(t *testing.T) {
	config := DefaultInfraConfig()
	mgr := NewTerraformManager(config)

	tests := []struct {
		name     string
		provider TFProvider
		wantErr  bool
	}{
		{"AWS provider", TFProviderAWS, false},
		{"GCP provider", TFProviderGCP, false},
		{"Azure provider", TFProviderAzure, false},
		{"DigitalOcean provider", TFProviderDigitalOcean, false},
		{"Unsupported provider", TFProvider("unsupported"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := mgr.GenerateTF(tt.provider, config)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateTF() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result == "" {
				t.Error("GenerateTF() returned empty string")
			}
		})
	}
}

func TestDefaultInfraConfig(t *testing.T) {
	config := DefaultInfraConfig()

	if config == nil {
		t.Fatal("config should not be nil")
	}

	if config.Provider != ProviderAWS {
		t.Errorf("expected provider aws, got %s", config.Provider)
	}

	if config.Region != "us-east-1" {
		t.Errorf("expected region us-east-1, got %s", config.Region)
	}
}

func TestDefaultRedirectorConfig(t *testing.T) {
	config := DefaultRedirectorConfig()

	if config == nil {
		t.Fatal("config should not be nil")
	}

	if config.ListenAddr != "0.0.0.0" {
		t.Errorf("expected listen addr 0.0.0.0, got %s", config.ListenAddr)
	}

	if config.ListenPort != 443 {
		t.Errorf("expected listen port 443, got %d", config.ListenPort)
	}
}

func TestNewAnsibleManager(t *testing.T) {
	config := DefaultInfraConfig()
	mgr := NewAnsibleManager(config)

	if mgr == nil {
		t.Fatal("manager should not be nil")
	}
}

func TestGeneratePlaybook(t *testing.T) {
	config := DefaultInfraConfig()
	mgr := NewAnsibleManager(config)

	roles := []string{"recon", "phishing", "c2", "dns", "wireguard", "nginx", "firewall"}

	for _, role := range roles {
		t.Run(role, func(t *testing.T) {
			result, err := mgr.GeneratePlaybook(role, map[string]interface{}{
				"target": "192.168.1.100",
			})
			if err != nil {
				t.Errorf("GeneratePlaybook(%s) error = %v", role, err)
				return
			}
			if result == "" {
				t.Errorf("GeneratePlaybook(%s) returned empty string", role)
			}
		})
	}
}

func TestGeneratePlaybookUnknownRole(t *testing.T) {
	config := DefaultInfraConfig()
	mgr := NewAnsibleManager(config)

	_, err := mgr.GeneratePlaybook("unknown-role", map[string]interface{}{})
	if err == nil {
		t.Error("expected error for unknown role")
	}
}

func TestNewNginxRedirector(t *testing.T) {
	config := DefaultRedirectorConfig()
	redir := NewNginxRedirector(config)

	if redir == nil {
		t.Fatal("redirector should not be nil")
	}
}

func TestAddRoute(t *testing.T) {
	config := DefaultRedirectorConfig()
	redir := NewNginxRedirector(config)

	err := redir.AddRoute("/api", "http://backend:8080")
	if err != nil {
		t.Fatalf("AddRoute failed: %v", err)
	}

	if _, ok := config.Routes["/api"]; !ok {
		t.Error("route should be added")
	}
}

func TestAddRouteEmpty(t *testing.T) {
	config := DefaultRedirectorConfig()
	redir := NewNginxRedirector(config)

	err := redir.AddRoute("", "http://backend:8080")
	if err == nil {
		t.Error("expected error for empty path")
	}

	err = redir.AddRoute("/api", "")
	if err == nil {
		t.Error("expected error for empty backend")
	}
}

func TestRemoveRoute(t *testing.T) {
	config := DefaultRedirectorConfig()
	redir := NewNginxRedirector(config)

	redir.AddRoute("/api", "http://backend:8080")

	err := redir.RemoveRoute("/api")
	if err != nil {
		t.Fatalf("RemoveRoute failed: %v", err)
	}

	if _, ok := config.Routes["/api"]; ok {
		t.Error("route should be removed")
	}
}

func TestRemoveRouteNotFound(t *testing.T) {
	config := DefaultRedirectorConfig()
	redir := NewNginxRedirector(config)

	err := redir.RemoveRoute("/nonexistent")
	if err == nil {
		t.Error("expected error for non-existent route")
	}
}

func TestGenerateConfig(t *testing.T) {
	config := DefaultRedirectorConfig()
	redir := NewNginxRedirector(config)

	redir.AddRoute("/api", "http://backend:8080")

	result := redir.GenerateConfig()
	if result == "" {
		t.Error("GenerateConfig returned empty string")
	}
}

func TestNewVPNManager(t *testing.T) {
	config := DefaultInfraConfig()
	mgr := NewVPNManager(config)

	if mgr == nil {
		t.Fatal("manager should not be nil")
	}
}

func TestGenerateWireGuardConfig(t *testing.T) {
	config := DefaultInfraConfig()
	mgr := NewVPNManager(config)

	result, err := mgr.GenerateWireGuardConfig("10.0.0.1", "10.0.0.2")
	if err != nil {
		t.Fatalf("GenerateWireGuardConfig failed: %v", err)
	}

	if result == "" {
		t.Error("config should not be empty")
	}
}

func TestGenerateWireGuardConfigEmpty(t *testing.T) {
	config := DefaultInfraConfig()
	mgr := NewVPNManager(config)

	_, err := mgr.GenerateWireGuardConfig("", "10.0.0.2")
	if err == nil {
		t.Error("expected error for empty server IP")
	}

	_, err = mgr.GenerateWireGuardConfig("10.0.0.1", "")
	if err == nil {
		t.Error("expected error for empty peer IP")
	}
}

func TestGenerateOpenVPNConfig(t *testing.T) {
	config := DefaultInfraConfig()
	mgr := NewVPNManager(config)

	vpnConfig := &OpenVPNConfig{
		Remote: "vpn.example.com",
		Port:   1194,
		Proto:  "udp",
		Dev:    "tun",
	}

	result, err := mgr.GenerateOpenVPNConfig(vpnConfig)
	if err != nil {
		t.Fatalf("GenerateOpenVPNConfig failed: %v", err)
	}

	if result == "" {
		t.Error("config should not be empty")
	}
}

func TestGenerateOpenVPNConfigNil(t *testing.T) {
	config := DefaultInfraConfig()
	mgr := NewVPNManager(config)

	_, err := mgr.GenerateOpenVPNConfig(nil)
	if err == nil {
		t.Error("expected error for nil config")
	}
}

func TestGenerateOpenVPNConfigDefaults(t *testing.T) {
	config := DefaultInfraConfig()
	mgr := NewVPNManager(config)

	vpnConfig := &OpenVPNConfig{
		Remote: "vpn.example.com",
	}

	result, err := mgr.GenerateOpenVPNConfig(vpnConfig)
	if err != nil {
		t.Fatalf("GenerateOpenVPNConfig failed: %v", err)
	}

	if result == "" {
		t.Error("config should not be empty")
	}
}

func TestNewIPRotationManager(t *testing.T) {
	config := DefaultInfraConfig()
	mgr := NewIPRotationManager(config)

	if mgr == nil {
		t.Fatal("manager should not be nil")
	}
}

func TestSetProxies(t *testing.T) {
	config := DefaultInfraConfig()
	mgr := NewIPRotationManager(config)

	proxies := []string{"1.2.3.4:8080", "5.6.7.8:3128"}
	mgr.SetProxies(proxies)

	if mgr.GetProxyCount() != 2 {
		t.Errorf("expected 2 proxies, got %d", mgr.GetProxyCount())
	}
}

func TestGetProxyChain(t *testing.T) {
	config := DefaultInfraConfig()
	mgr := NewIPRotationManager(config)

	proxies := []string{"1.2.3.4:8080", "5.6.7.8:3128"}
	mgr.SetProxies(proxies)

	chain := mgr.GetProxyChain()
	if len(chain) != 2 {
		t.Errorf("expected 2 proxies in chain, got %d", len(chain))
	}
}

func TestValidateProxyEmpty(t *testing.T) {
	config := DefaultInfraConfig()
	mgr := NewIPRotationManager(config)

	if mgr.ValidateProxy("") {
		t.Error("expected false for empty proxy")
	}
}

func TestValidateProxyInvalid(t *testing.T) {
	config := DefaultInfraConfig()
	mgr := NewIPRotationManager(config)

	if mgr.ValidateProxy("invalid") {
		t.Error("expected false for invalid proxy")
	}
}

func TestAddProxy(t *testing.T) {
	config := DefaultInfraConfig()
	mgr := NewIPRotationManager(config)

	mgr.AddProxy("1.2.3.4:8080")
	if mgr.GetProxyCount() != 1 {
		t.Errorf("expected 1 proxy, got %d", mgr.GetProxyCount())
	}
}

func TestRemoveProxy(t *testing.T) {
	config := DefaultInfraConfig()
	mgr := NewIPRotationManager(config)

	mgr.AddProxy("1.2.3.4:8080")
	result := mgr.RemoveProxy("1.2.3.4:8080")

	if !result {
		t.Error("expected true for successful remove")
	}

	if mgr.GetProxyCount() != 0 {
		t.Errorf("expected 0 proxies, got %d", mgr.GetProxyCount())
	}
}

func TestRemoveProxyNotFound(t *testing.T) {
	config := DefaultInfraConfig()
	mgr := NewIPRotationManager(config)

	result := mgr.RemoveProxy("1.2.3.4:8080")
	if result {
		t.Error("expected false for non-existent proxy")
	}
}

func TestGetCurrentProxy(t *testing.T) {
	config := DefaultInfraConfig()
	mgr := NewIPRotationManager(config)

	if mgr.GetCurrentProxy() != "" {
		t.Error("expected empty when no proxies")
	}

	mgr.AddProxy("1.2.3.4:8080")
	if mgr.GetCurrentProxy() == "" {
		t.Error("expected non-empty proxy")
	}
}

func TestRotateIPNoProxies(t *testing.T) {
	config := DefaultInfraConfig()
	mgr := NewIPRotationManager(config)

	_, err := mgr.RotateIP()
	if err == nil {
		t.Error("expected error when no proxies configured")
	}
}

func TestWireGuardKeyGeneration(t *testing.T) {
	key := generateWGKey()
	if key == "" {
		t.Error("key should not be empty")
	}
}

func TestDeriveWGPubKey(t *testing.T) {
	privKey := generateWGKey()
	pubKey := deriveWGPublicKey(privKey)
	if pubKey == "" {
		t.Error("public key should not be empty")
	}
}
