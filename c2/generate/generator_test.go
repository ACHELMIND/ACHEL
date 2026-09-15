package generate

import (
	"os"
	"testing"
)

func TestGeneratorNew(t *testing.T) {
	gen := NewGenerator(nil, "/tmp/test-output")
	if gen == nil {
		t.Fatal("expected non-nil generator")
	}
}

func TestGeneratorSupportedPlatforms(t *testing.T) {
	gen := NewGenerator(nil, "/tmp/test-output")
	platforms := gen.GetSupportedPlatforms()
	if len(platforms) == 0 {
		t.Error("expected at least one supported platform")
	}
}

func TestGeneratorGenerate(t *testing.T) {
	gen := NewGenerator(nil, "/tmp/test-angel-output")
	outputPath, err := gen.Generate("https://teamserver.example.com")
	if err != nil {
		t.Fatalf("generation failed: %v", err)
	}
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Errorf("output file not found: %s", outputPath)
	}
}
