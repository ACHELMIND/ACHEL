package upload

import (
	"strings"
	"testing"
)

func newTestEngine() *Engine {
	return NewEngine(UploadConfig{
		TargetURL:   "https://target.com/upload",
		FieldName:   "file",
		AllowedExts: []string{"jpg", "png", "gif", "pdf"},
		MaxSize:     10 * 1024 * 1024,
	})
}

func TestExtensionBypass(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.ExtensionBypass("shell.php")
	if err != nil {
		t.Fatalf("ExtensionBypass failed: %v", err)
	}
	if !result.Success {
		t.Error("ExtensionBypass reported failure")
	}
	if result.Method != "Extension_Bypass" {
		t.Errorf("expected method Extension_Bypass, got %s", result.Method)
	}
	if len(result.Payload) == 0 {
		t.Error("payload is empty")
	}
}

func TestExtensionBypassCase(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.ExtensionBypass("test.PHP")
	if err != nil {
		t.Fatalf("ExtensionBypass failed: %v", err)
	}
	if !strings.Contains(result.Payload, "PHP") {
		t.Error("should contain case variation")
	}
}

func TestContentTypeBypass(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.ContentTypeBypass("shell.php", "application/x-php")
	if err != nil {
		t.Fatalf("ContentTypeBypass failed: %v", err)
	}
	if !result.Success {
		t.Error("ContentTypeBypass reported failure")
	}
	if result.Method != "Content_Type_Bypass" {
		t.Errorf("expected method Content_Type_Bypass, got %s", result.Method)
	}
}

func TestContentTypeBypassImage(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.ContentTypeBypass("image.jpg", "image/jpeg")
	if err != nil {
		t.Fatalf("ContentTypeBypass failed: %v", err)
	}
	if !strings.Contains(result.Payload, "image/jpeg") {
		t.Error("should contain original content type")
	}
}

func TestMagicBytesBypass(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.MagicBytesBypass("php")
	if err != nil {
		t.Fatalf("MagicBytesBypass failed: %v", err)
	}
	if !result.Success {
		t.Error("MagicBytesBypass reported failure")
	}
	if !strings.Contains(result.Payload, "3C 3F 70 68 70") {
		t.Error("should contain PHP magic bytes")
	}
}

func TestMagicBytesBypassPNG(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.MagicBytesBypass("png")
	if err != nil {
		t.Fatalf("MagicBytesBypass failed: %v", err)
	}
	if !strings.Contains(result.Payload, "89 50 4E 47") {
		t.Error("should contain PNG magic bytes")
	}
}

func TestDoubleExtension(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.DoubleExtension("shell")
	if err != nil {
		t.Fatalf("DoubleExtension failed: %v", err)
	}
	if !result.Success {
		t.Error("DoubleExtension reported failure")
	}
	if !strings.Contains(result.Payload, "shell.php.jpg") {
		t.Error("should contain double extension")
	}
}

func TestNullByteInject(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.NullByteInject("shell.php")
	if err != nil {
		t.Fatalf("NullByteInject failed: %v", err)
	}
	if !result.Success {
		t.Error("NullByteInject reported failure")
	}
	if !strings.Contains(result.Payload, "%00") {
		t.Error("should contain null byte")
	}
}

func TestAnalyzeUpload(t *testing.T) {
	eng := newTestEngine()
	analysis := eng.AnalyzeUpload("shell.php", "application/x-php", 1024)
	if !analysis.IsExecutable {
		t.Error("php should be executable")
	}
	if analysis.RiskLevel != "critical" {
		t.Errorf("expected critical risk, got %s", analysis.RiskLevel)
	}
}

func TestAnalyzeUploadImage(t *testing.T) {
	eng := newTestEngine()
	analysis := eng.AnalyzeUpload("photo.jpg", "image/jpeg", 5000)
	if analysis.IsExecutable {
		t.Error("jpg should not be executable")
	}
	if analysis.RiskLevel != "low" {
		t.Errorf("expected low risk, got %s", analysis.RiskLevel)
	}
}

func TestAnalyzeUploadHTML(t *testing.T) {
	eng := newTestEngine()
	analysis := eng.AnalyzeUpload("page.html", "text/html", 1000)
	if analysis.RiskLevel != "high" {
		t.Errorf("expected high risk for HTML, got %s", analysis.RiskLevel)
	}
}

func TestGenerateUploadHTML(t *testing.T) {
	eng := newTestEngine()
	html := eng.GenerateUploadHTML("https://target.com/upload", "file")
	if !strings.Contains(html, "target.com/upload") {
		t.Error("HTML missing target URL")
	}
	if !strings.Contains(html, "multipart/form-data") {
		t.Error("HTML missing enctype")
	}
}
