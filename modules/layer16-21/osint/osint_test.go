package osint

import (
	"testing"
)

func TestNewOSINTEngine(t *testing.T) {
	config := DefaultOSINTConfig()
	engine := NewOSINTEngine(config)

	if engine == nil {
		t.Fatal("engine should not be nil")
	}

	if engine.config == nil {
		t.Fatal("config should not be nil")
	}

	if engine.log == nil {
		t.Fatal("logger should not be nil")
	}
}

func TestNewOSINTEngineNilConfig(t *testing.T) {
	engine := NewOSINTEngine(nil)

	if engine == nil {
		t.Fatal("engine should not be nil")
	}

	if engine.config == nil {
		t.Fatal("config should not be nil after nil config")
	}
}

func TestDefaultOSINTConfig(t *testing.T) {
	config := DefaultOSINTConfig()

	if config == nil {
		t.Fatal("config should not be nil")
	}

	if config.Timeout == 0 {
		t.Error("timeout should be set")
	}

	if config.MaxConcurrency == 0 {
		t.Error("max concurrency should be set")
	}

	if len(config.Ports) == 0 {
		t.Error("ports should be set")
	}
}

func TestNewDNSRecon(t *testing.T) {
	config := DefaultOSINTConfig()
	recon := NewDNSRecon(config)

	if recon == nil {
		t.Fatal("recon should not be nil")
	}
}

func TestDNSReverseDNS(t *testing.T) {
	config := DefaultOSINTConfig()
	recon := NewDNSRecon(config)

	_, err := recon.ReverseDNS("8.8.8.8")
	if err != nil {
		t.Logf("ReverseDNS failed (may be expected in sandbox): %v", err)
	}
}

func TestDNSResolve(t *testing.T) {
	config := DefaultOSINTConfig()
	recon := NewDNSRecon(config)

	_, err := recon.Resolve("localhost")
	if err != nil {
		t.Logf("Resolve localhost failed: %v", err)
	}
}

func TestDNSCheckWildcards(t *testing.T) {
	config := DefaultOSINTConfig()
	recon := NewDNSRecon(config)

	_, _, err := recon.CheckWildcards("example.com")
	if err != nil {
		t.Logf("CheckWildcards failed: %v", err)
	}
}

func TestNewPortScanner(t *testing.T) {
	config := DefaultOSINTConfig()
	scanner := NewPortScanner(config)

	if scanner == nil {
		t.Fatal("scanner should not be nil")
	}
}

func TestPortScannerIsPortOpen(t *testing.T) {
	config := DefaultOSINTConfig()
	scanner := NewPortScanner(config)

	result := scanner.IsPortOpen("127.0.0.1", 1)
	if result {
		t.Log("Port 1 is open on localhost")
	}
}

func TestGuessService(t *testing.T) {
	tests := []struct {
		port    int
		service string
	}{
		{22, "ssh"},
		{80, "http"},
		{443, "https"},
		{3306, "mysql"},
		{5432, "postgresql"},
		{6379, "redis"},
		{27017, "mongodb"},
		{9999, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.service, func(t *testing.T) {
			service := guessService(tt.port)
			if service != tt.service {
				t.Errorf("expected %s, got %s", tt.service, service)
			}
		})
	}
}

func TestNewWebRecon(t *testing.T) {
	config := DefaultOSINTConfig()
	recon := NewWebRecon(config)

	if recon == nil {
		t.Fatal("recon should not be nil")
	}

	if recon.client == nil {
		t.Fatal("client should not be nil")
	}
}

func TestNewPersonRecon(t *testing.T) {
	config := DefaultOSINTConfig()
	recon := NewPersonRecon(config)

	if recon == nil {
		t.Fatal("recon should not be nil")
	}
}

func TestNewCloudRecon(t *testing.T) {
	config := DefaultOSINTConfig()
	recon := NewCloudRecon(config)

	if recon == nil {
		t.Fatal("recon should not be nil")
	}
}

func TestCloudReconCheckMetadata(t *testing.T) {
	config := DefaultOSINTConfig()
	recon := NewCloudRecon(config)

	_, err := recon.CheckMetadataService()
	if err != nil {
		t.Logf("Metadata service not found (expected in non-cloud env): %v", err)
	}
}

func TestGetStats(t *testing.T) {
	config := DefaultOSINTConfig()
	engine := NewOSINTEngine(config)

	stats := engine.GetStats()
	if stats == nil {
		t.Fatal("stats should not be nil")
	}

	if stats["timeout"] == nil {
		t.Error("timeout should be set in stats")
	}
}

func TestCommonPorts(t *testing.T) {
	ports := commonPorts()
	if len(ports) == 0 {
		t.Error("commonPorts should return non-empty list")
	}
}
