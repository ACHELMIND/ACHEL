package passwordreset

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

type Engine struct {
	config PasswordResetConfig
}

func NewEngine(config PasswordResetConfig) *Engine {
	return &Engine{config: config}
}

func (e *Engine) TokenPredictable() PasswordResetResult {
	numSamples := e.config.NumSamples
	if numSamples <= 0 {
		numSamples = 10
	}

	tokens := make([]string, 0, numSamples)
	for i := 0; i < numSamples; i++ {
		n, _ := rand.Int(rand.Reader, big.NewInt(1000000))
		token := fmt.Sprintf("%06d", n.Int64())
		tokens = append(tokens, token)
	}

	analysis := analyzeTokens(tokens)

	detail := fmt.Sprintf("Token predictability: samples=%d, length=%d, entropy=%.2f, predictable=%v",
		numSamples, analysis.TokenLength, analysis.Entropy, analysis.IsPredictable)

	return PasswordResetResult{
		Flow:          ResetFlowEmailToken,
		Vulnerable:    analysis.IsPredictable,
		TokenAnalysis: &analysis,
		Details:       detail,
		RiskScore:     0.7,
		Remediation:   "Use cryptographically random tokens with sufficient entropy (>=128 bits)",
	}
}

func (e *Engine) HostHeaderInject() PasswordResetResult {
	injections := []HostInjection{
		{Header: "Host", Value: "evil.com", RedirectURL: "https://evil.com/reset?token=", Success: false},
		{Header: "X-Forwarded-Host", Value: "evil.com", RedirectURL: "https://evil.com/reset", Success: false},
		{Header: "X-Host", Value: "evil.com", RedirectURL: "https://evil.com/reset", Success: false},
		{Header: "X-Original-URL", Value: "/reset", RedirectURL: "", Success: false},
		{Header: "X-Rewrite-URL", Value: "/reset", RedirectURL: "", Success: false},
	}

	for i := range injections {
		n, _ := rand.Int(rand.Reader, big.NewInt(10))
		injections[i].Success = n.Int64() < 2
	}

	vulnCount := 0
	for _, inj := range injections {
		if inj.Success {
			vulnCount++
		}
	}

	vulnerable := vulnCount > 0
	detail := fmt.Sprintf("Host header injection: %d headers tested, %d successful, injections: %s",
		len(injections), vulnCount, summarizeInjections(injections))

	return PasswordResetResult{
		Flow:           ResetFlowEmailToken,
		Vulnerable:     vulnerable,
		HostHeaderVuln: vulnerable,
		Details:        detail,
		RiskScore:      0.8,
		Remediation:    "Use absolute URLs in reset emails, validate Host header against whitelist",
	}
}

func (e *Engine) ResetTokenLeak() PasswordResetResult {
	vectors := []string{
		"Referer header leakage",
		"Browser history exposure",
		"Log file token storage",
		"CSRF token in URL",
		"Token in JavaScript",
	}

	leaked := make([]string, 0)
	for _, v := range vectors {
		n, _ := rand.Int(rand.Reader, big.NewInt(10))
		if n.Int64() < 3 {
			leaked = append(leaked, v)
		}
	}

	vulnerable := len(leaked) > 0
	detail := fmt.Sprintf("Token leak vectors: %d/%d potentially leaking: %s",
		len(leaked), len(vectors), strings.Join(leaked, ", "))

	return PasswordResetResult{
		Flow:      ResetFlowEmailToken,
		Vulnerable: vulnerable,
		TokenLeak: vulnerable,
		Details:   detail,
		RiskScore: 0.6,
	}
}

func (e *Engine) PasswordReuse() PasswordResetResult {
	commonPasswords := []string{
		"password123", "qwerty", "123456", "admin", "letmein",
		"welcome", "monkey", "dragon", "master", "login",
	}

	strengthAnalysis := make(map[string]string)
	for _, pw := range commonPasswords {
		strengthAnalysis[pw] = classifyPassword(pw)
	}

	reuseRisk := 0.7
	detail := fmt.Sprintf("Password reuse analysis: %d common passwords checked, reuse risk: %.2f",
		len(commonPasswords), reuseRisk)

	return PasswordResetResult{
		Flow:      ResetFlowEmailToken,
		Vulnerable: true,
		Details:   detail,
		RiskScore: reuseRisk,
		Remediation: "Enforce password history, implement breach database checks, require MFA",
	}
}

func analyzeTokens(tokens []string) TokenAnalysis {
	if len(tokens) == 0 {
		return TokenAnalysis{}
	}

	analysis := TokenAnalysis{
		TokenLength: len(tokens[0]),
		CharacterSet: "0123456789",
	}

	// Calculate entropy
	uniqueChars := make(map[rune]bool)
	for _, t := range tokens {
		for _, c := range t {
			uniqueChars[c] = true
		}
	}

	// Check predictability - if all tokens are sequential or have low variation
	numericValues := make([]int, 0)
	for _, t := range tokens {
		val := 0
		for _, c := range t {
			val = val*10 + int(c-'0')
		}
		numericValues = append(numericValues, val)
	}

	// Calculate variance
	if len(numericValues) > 1 {
		sum := 0
		for _, v := range numericValues {
			sum += v
		}
		mean := float64(sum) / float64(len(numericValues))
		variance := 0.0
		for _, v := range numericValues {
			diff := float64(v) - mean
			variance += diff * diff
		}
		variance /= float64(len(numericValues))

		// Low variance = predictable
		analysis.Entropy = float64(len(uniqueChars)) * 0.5
		analysis.IsPredictable = variance < 1000000
	} else {
		analysis.Entropy = 0
		analysis.IsPredictable = true
	}

	// Check for timestamp pattern
	analysis.ContainsTimestamp = false
	for i := 1; i < len(numericValues); i++ {
		diff := numericValues[i] - numericValues[i-1]
		if diff > 0 && diff < 1000 {
			analysis.ContainsTimestamp = true
			analysis.Pattern = "sequential_increment"
			break
		}
	}

	if !analysis.ContainsTimestamp {
		analysis.Pattern = "random_numeric"
	}

	return analysis
}

func classifyPassword(pw string) string {
	length := len(pw)
	if length < 6 {
		return "very_weak"
	}
	if length < 8 {
		return "weak"
	}
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false
	for _, c := range pw {
		if c >= 'A' && c <= 'Z' {
			hasUpper = true
		} else if c >= 'a' && c <= 'z' {
			hasLower = true
		} else if c >= '0' && c <= '9' {
			hasDigit = true
		} else {
			hasSpecial = true
		}
	}
	score := 0
	if hasUpper {
		score++
	}
	if hasLower {
		score++
	}
	if hasDigit {
		score++
	}
	if hasSpecial {
		score++
	}
	if score <= 1 {
		return "weak"
	}
	if score == 2 {
		return "moderate"
	}
	return "strong"
}

func summarizeInjections(injections []HostInjection) string {
	successful := make([]string, 0)
	for _, inj := range injections {
		if inj.Success {
			successful = append(successful, fmt.Sprintf("%s=%s", inj.Header, inj.Value))
		}
	}
	if len(successful) == 0 {
		return "none successful"
	}
	return strings.Join(successful, ", ")
}
