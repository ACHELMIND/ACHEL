package malleable

import (
	"fmt"
	"strings"
	"sync"
)

type ProfileValidator struct {
	mu       sync.RWMutex
	errors   []ValidationError
	warnings []ValidationWarning
}

type ValidationError struct {
	Field   string
	Message string
	Severity string
}

type ValidationWarning struct {
	Field   string
	Message string
	Suggestion string
}

type ValidationResult struct {
	Valid    bool
	Errors   []ValidationError
	Warnings []ValidationWarning
	Score    int
}

func NewProfileValidator() *ProfileValidator {
	return &ProfileValidator{
		errors:   make([]ValidationError, 0),
		warnings: make([]ValidationWarning, 0),
	}
}

func (pv *ProfileValidator) ValidateProfile(profile *Profile) ValidationResult {
	pv.mu.Lock()
	pv.errors = make([]ValidationError, 0)
	pv.warnings = make([]ValidationWarning, 0)
	pv.mu.Unlock()

	if profile == nil {
		pv.addError("profile", "Profile is nil", "critical")
		return pv.buildResult()
	}

	pv.validateHTTPGet(profile.HTTPGet)
	pv.validateHTTPPost(profile.HTTPPost)
	pv.validateMetadata(profile.Metadata)
	pv.validateTLS(profile.TLS)

	pv.checkSecurityIssues(profile)

	return pv.buildResult()
}

func (pv *ProfileValidator) validateHTTPGet(config HTTPGetConfig) {
	if config.Method == "" {
		pv.addError("http_get.method", "Method is empty", "high")
	}

	validMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
	methodValid := false
	for _, m := range validMethods {
		if strings.EqualFold(config.Method, m) {
			methodValid = true
			break
		}
	}
	if !methodValid {
		pv.addError("http_get.method", fmt.Sprintf("Invalid method: %s", config.Method), "high")
	}

	if len(config.URI) == 0 {
		pv.addError("http_get.uri", "URI list is empty", "high")
	}

	for i, uri := range config.URI {
		if !strings.HasPrefix(uri, "/") {
			pv.addWarning("http_get.uri", fmt.Sprintf("URI %d doesn't start with /", i), "Add leading /")
		}
	}

	if len(config.Port) == 0 {
		pv.addWarning("http_get.port", "No ports specified", "Add common ports like 80, 443")
	}

	if config.Jitter < 0 || config.Jitter > 1 {
		pv.addError("http_get.jitter", "Jitter must be between 0 and 1", "medium")
	}
}

func (pv *ProfileValidator) validateHTTPPost(config HTTPPostConfig) {
	if config.Method == "" {
		pv.addError("http_post.method", "Method is empty", "high")
	}

	if config.URI == "" {
		pv.addError("http_post.uri", "URI is empty", "high")
	}

	if config.Output == "" {
		pv.addWarning("http_post.output", "Output type not specified", "Specify base64 or raw")
	}

	validOutputs := []string{"base64", "raw", "print"}
	outputValid := false
	for _, o := range validOutputs {
		if strings.EqualFold(config.Output, o) {
			outputValid = true
			break
		}
	}
	if !outputValid && config.Output != "" {
		pv.addError("http_post.output", fmt.Sprintf("Invalid output type: %s", config.Output), "medium")
	}
}

func (pv *ProfileValidator) validateMetadata(config MetadataConfig) {
	if config.Generic == "" {
		pv.addWarning("metadata.generic", "Generic metadata not set", "Set a generic metadata value")
	}

	if config.OS == "" {
		pv.addWarning("metadata.os", "OS metadata not set", "Set OS metadata for better mimicry")
	}
}

func (pv *ProfileValidator) validateTLS(config TLSConfig) {
	if config.CertFile == "" {
		pv.addWarning("tls.cert_file", "Certificate file not specified", "Specify a certificate file")
	}

	if config.KeyFile == "" {
		pv.addWarning("tls.key_file", "Key file not specified", "Specify a key file")
	}
}

func (pv *ProfileValidator) checkSecurityIssues(profile *Profile) {
	for key, value := range profile.HTTPGet.Headers {
		if strings.EqualFold(key, "Authorization") && strings.Contains(value, "Bearer") {
			pv.addWarning("security.auth", "Hardcoded Bearer token in headers", "Use dynamic token generation")
		}
	}

	if profile.TLS.CertFile != "" && !strings.HasSuffix(profile.TLS.CertFile, ".pem") {
		pv.addWarning("security.tls", "Certificate file doesn't have .pem extension", "Use .pem extension for certificates")
	}

	commonUA := []string{"Mozilla/5.0", "curl", "wget"}
	for _, ua := range commonUA {
		if uaVal, ok := profile.HTTPGet.Headers["User-Agent"]; ok {
			if strings.Contains(uaVal, ua) {
				pv.addWarning("security.user_agent", "Using common User-Agent string", "Use a more unique User-Agent")
			}
		}
	}
}

func (pv *ProfileValidator) addError(field, message, severity string) {
	pv.mu.Lock()
	defer pv.mu.Unlock()
	pv.errors = append(pv.errors, ValidationError{
		Field:    field,
		Message:  message,
		Severity: severity,
	})
}

func (pv *ProfileValidator) addWarning(field, message, suggestion string) {
	pv.mu.Lock()
	defer pv.mu.Unlock()
	pv.warnings = append(pv.warnings, ValidationWarning{
		Field:      field,
		Message:    message,
		Suggestion: suggestion,
	})
}

func (pv *ProfileValidator) buildResult() ValidationResult {
	pv.mu.RLock()
	defer pv.mu.RUnlock()

	score := 100
	for _, e := range pv.errors {
		switch e.Severity {
		case "critical":
			score -= 30
		case "high":
			score -= 20
		case "medium":
			score -= 10
		case "low":
			score -= 5
		}
	}

	for range pv.warnings {
		score -= 2
	}

	if score < 0 {
		score = 0
	}

	return ValidationResult{
		Valid:    len(pv.errors) == 0,
		Errors:   pv.errors,
		Warnings: pv.warnings,
		Score:    score,
	}
}

func (pv *ProfileValidator) GetErrors() []ValidationError {
	pv.mu.RLock()
	defer pv.mu.RUnlock()
	return pv.errors
}

func (pv *ProfileValidator) GetWarnings() []ValidationWarning {
	pv.mu.RLock()
	defer pv.mu.RUnlock()
	return pv.warnings
}
