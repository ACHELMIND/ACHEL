package deser

import "testing"

func TestJavaDeserExploit(t *testing.T) {
	config := DeserConfig{
		TargetURL:   "http://target:8080/api",
		Format:      DeserFormatJava,
		Payload:     "id",
		GadgetChain: []string{"commons-collections", "Runtime"},
	}
	engine := NewEngine(config)
	result := engine.JavaDeserExploit()
	if result.Format != DeserFormatJava {
		t.Errorf("expected Java format, got %d", result.Format)
	}
	if result.ChainDepth < 1 {
		t.Error("expected chain depth >= 1")
	}
	if result.RiskScore <= 0 {
		t.Error("expected positive risk score")
	}
}

func TestPythonPickle(t *testing.T) {
	config := DeserConfig{
		TargetURL: "http://target:5000/api",
		Format:    DeserFormatPython,
		Payload:   "import os; os.system('id')",
	}
	engine := NewEngine(config)
	result := engine.PythonPickle()
	if result.Format != DeserFormatPython {
		t.Errorf("expected Python format, got %d", result.Format)
	}
	if !result.Vulnerable {
		t.Error("expected vulnerable result")
	}
}

func TestPHPSerialize(t *testing.T) {
	config := DeserConfig{
		TargetURL: "http://target:8080/api",
		Format:    DeserFormatPHP,
		Payload:   "system('id')",
	}
	engine := NewEngine(config)
	result := engine.PHPSerialize()
	if result.Format != DeserFormatPHP {
		t.Errorf("expected PHP format, got %d", result.Format)
	}
}

func TestDotNetDeserialization(t *testing.T) {
	config := DeserConfig{
		TargetURL: "http://target:443/api",
		Format:    DeserFormatDotNet,
		Payload:   "cmd /c whoami",
	}
	engine := NewEngine(config)
	result := engine.DotNetDeserialization()
	if result.Format != DeserFormatDotNet {
		t.Errorf("expected DotNet format, got %d", result.Format)
	}
	if result.ChainDepth < 1 {
		t.Error("expected chain depth >= 1")
	}
}
