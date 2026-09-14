package evidence

import "regexp"

type Redactor struct {
	piiPatterns     []*regexp.Regexp
	secretPatterns  []*regexp.Regexp
	certPatterns    []*regexp.Regexp
}

func NewRedactor() *Redactor {
	r := &Redactor{}

	r.piiPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
		regexp.MustCompile(`\b\d{3}[\s-]?\d{3}[\s-]?\d{4}\b`),
		regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`),
	}

	r.secretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)['":\s]*['"]?[A-Za-z0-9\-_\.]{20,}['"]?`),
		regexp.MustCompile(`(?i)(password|passwd|pwd)['":\s]*['"]?[^\s'"]{8,}['"]?`),
		regexp.MustCompile(`eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_\.]+`),
	}

	r.certPatterns = []*regexp.Regexp{
		regexp.MustCompile(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC |DSA )?PRIVATE KEY-----`),
		regexp.MustCompile(`-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----`),
	}

	return r
}

func (r *Redactor) RedactPII(data []byte) []byte {
	result := data
	for _, p := range r.piiPatterns {
		result = p.ReplaceAll(result, []byte("[REDACTED]"))
	}
	return result
}

func (r *Redactor) RedactSecrets(data []byte) []byte {
	result := data
	for _, p := range r.secretPatterns {
		result = p.ReplaceAll(result, []byte("[REDACTED]"))
	}
	return result
}

func (r *Redactor) RedactCerts(data []byte) []byte {
	result := data
	for _, p := range r.certPatterns {
		result = p.ReplaceAll(result, []byte("[REDACTED]"))
	}
	return result
}
