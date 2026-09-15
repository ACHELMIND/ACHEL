package threatintel

import (
	"testing"
)

func TestIOCGeneration(t *testing.T) {
	engine := NewEngine(ThreatIntelConfig{
		MITREMapping: true,
	})

	result := engine.IOCGeneration("malware-sample.com")

	if len(result.IOCs) == 0 {
		t.Error("Expected IOCs")
	}
	for _, ioc := range result.IOCs {
		if ioc.Value == "" {
			t.Error("IOC value should not be empty")
		}
		if ioc.Confidence <= 0 {
			t.Error("Confidence should be > 0")
		}
	}
}

func TestMITREATTACKMapping(t *testing.T) {
	engine := NewEngine(ThreatIntelConfig{})

	iocs := []IOC{
		{Type: IOCTypeDomain, Value: "c2.example.com", Confidence: 0.9, Tags: []string{"c2"}},
		{Type: IOCTypeURL, Value: "http://phish.example.com", Confidence: 0.8, Tags: []string{"phishing"}},
	}

	result := engine.MITREATTACKMapping(iocs)

	if len(result.MITREMapping) == 0 {
		t.Error("Expected MITRE mappings")
	}
}

func TestThreatFeed(t *testing.T) {
	engine := NewEngine(ThreatIntelConfig{})

	result := engine.ThreatFeed("https://feeds.example.com/threats.json")

	if len(result.ThreatActors) == 0 {
		t.Error("Expected threat actors")
	}
	for _, actor := range result.ThreatActors {
		if actor.Name == "" {
			t.Error("Actor name should not be empty")
		}
	}
}

func TestIntelReport(t *testing.T) {
	engine := NewEngine(ThreatIntelConfig{})

	result := engine.IntelReport("target-company.com")

	if len(result.Reports) == 0 {
		t.Error("Expected reports")
	}
	if result.Reports[0].Title == "" {
		t.Error("Report title should not be empty")
	}
}

func TestEngineCreation(t *testing.T) {
	engine := NewEngine(ThreatIntelConfig{})
	if engine == nil {
		t.Fatal("Engine should not be nil")
	}
}

func TestIOCTypes(t *testing.T) {
	types := []IOCType{
		IOCTypeIP, IOCTypeDomain, IOCTypeURL, IOCTypeFileHash,
		IOCTypeEmailAddress, IOCTypeMutex, IOCTypeRegistryKey, IOCTypeJA3,
	}
	for _, it := range types {
		if it.String() == "" {
			t.Errorf("IOCType %d should have string", it)
		}
	}
}
