package authbypass

import (
	"testing"
	"time"
)

func TestNewAuthBypassEngine(t *testing.T) {
	engine := NewAuthBypassEngine(nil)
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	if engine.config == nil {
		t.Fatal("expected non-nil config")
	}
	if engine.jwt == nil {
		t.Error("expected non-nil jwt module")
	}
	if engine.oauth == nil {
		t.Error("expected non-nil oauth module")
	}
	if engine.bf == nil {
		t.Error("expected non-nil bruteforce module")
	}
	if engine.sess == nil {
		t.Error("expected non-nil session module")
	}
}

func TestNewAuthBypassEngineWithConfig(t *testing.T) {
	config := &AuthBypassConfig{
		Target:          "https://example.com",
		Timeout:         10 * time.Second,
		Methods:         []AuthBypassMethod{MethodSQLiAuth},
		UsernameField:   "user",
		PasswordField:   "pass",
		LoginEndpoint:   "/auth",
		Verbose:         true,
	}
	engine := NewAuthBypassEngine(config)
	if engine.config.Target != "https://example.com" {
		t.Error("expected target to be set")
	}
}

func TestTestBypassSQLiAuth(t *testing.T) {
	engine := NewAuthBypassEngine(nil)
	result, err := engine.TestBypass("https://example.com", "sqli_auth")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Method != MethodSQLiAuth {
		t.Errorf("expected method sqli_auth, got %s", result.Method)
	}
	if result.Duration == 0 {
		t.Error("expected non-zero duration")
	}
	if result.Data == nil {
		t.Error("expected non-nil data")
	}
}

func TestTestBypassNoSQLAuth(t *testing.T) {
	engine := NewAuthBypassEngine(nil)
	result, err := engine.TestBypass("https://example.com", "nosql_auth")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Method != MethodNoSQLAuth {
		t.Errorf("expected method nosql_auth, got %s", result.Method)
	}
}

func TestTestBypassJWTBypass(t *testing.T) {
	engine := NewAuthBypassEngine(nil)
	result, err := engine.TestBypass("https://example.com", "jwt_bypass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Method != MethodJWTBypass {
		t.Errorf("expected method jwt_bypass, got %s", result.Method)
	}
}

func TestTestBypassJSONTampering(t *testing.T) {
	engine := NewAuthBypassEngine(nil)
	result, err := engine.TestBypass("https://example.com", "json_tampering")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Method != MethodJSONTampering {
		t.Errorf("expected method json_tampering, got %s", result.Method)
	}
}

func TestTestBypassDefaultCred(t *testing.T) {
	engine := NewAuthBypassEngine(nil)
	result, err := engine.TestBypass("https://example.com", "default_cred")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Method != MethodDefaultCred {
		t.Errorf("expected method default_cred, got %s", result.Method)
	}
	if result.Data["username"] == "" {
		t.Error("expected username in data")
	}
}

func TestTestBypassOAuthBypass(t *testing.T) {
	engine := NewAuthBypassEngine(nil)
	result, err := engine.TestBypass("https://example.com", "oauth_bypass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Method != MethodOAuthBypass {
		t.Errorf("expected method oauth_bypass, got %s", result.Method)
	}
}

func TestTestBypassSessionHijack(t *testing.T) {
	engine := NewAuthBypassEngine(nil)
	result, err := engine.TestBypass("https://example.com", "session_hijack")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Method != MethodSessionHijack {
		t.Errorf("expected method session_hijack, got %s", result.Method)
	}
}

func TestTestBypassUnknownMethod(t *testing.T) {
	engine := NewAuthBypassEngine(nil)
	_, err := engine.TestBypass("https://example.com", "unknown_method")
	if err == nil {
		t.Fatal("expected error for unknown method")
	}
}

func TestFullBypass(t *testing.T) {
	engine := NewAuthBypassEngine(nil)
	results, err := engine.FullBypass("https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Error("expected at least one result")
	}

	methodsSeen := make(map[AuthBypassMethod]bool)
	for _, r := range results {
		methodsSeen[r.Method] = true
		if r.Duration == 0 {
			t.Errorf("expected non-zero duration for method %s", r.Method)
		}
	}

	expectedMethods := AllAuthBypassMethods()
	for _, m := range expectedMethods {
		if !methodsSeen[m] {
			t.Errorf("expected method %s in results", m)
		}
	}
}

func TestJWTNoneAttack(t *testing.T) {
	module := NewJWTModule()
	header := base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64URLEncode([]byte(`{"sub":"user1","role":"admin"}`))
	token := header + "." + payload + ".fakesig"

	result, err := module.JWTNoneAttack(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.Data["attack_type"] != "alg_none" {
		t.Error("expected alg_none attack type")
	}
}

func TestJWTNoneAttackInvalidToken(t *testing.T) {
	module := NewJWTModule()
	_, err := module.JWTNoneAttack("invalid.token")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestJWTWeakSecret(t *testing.T) {
	module := NewJWTModule()
	header := base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64URLEncode([]byte(`{"sub":"user1"}`))

	secret := "password123"
	signingInput := header + "." + payload
	sig := computeHMACSign(signingInput, secret)
	token := signingInput + "." + base64URLEncode(sig)

	wordlist := []string{"wrong", "bad", "password123"}
	result, err := module.JWTWeakSecret(token, wordlist)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success finding weak secret")
	}
	if result.Data["secret"] != "password123" {
		t.Errorf("expected secret password123, got %s", result.Data["secret"])
	}
}

func TestJWTWeakSecretNotFound(t *testing.T) {
	module := NewJWTModule()
	header := base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64URLEncode([]byte(`{"sub":"user1"}`))

	secret := "strongsecret"
	signingInput := header + "." + payload
	sig := computeHMACSign(signingInput, secret)
	token := signingInput + "." + base64URLEncode(sig)

	wordlist := []string{"wrong", "bad", "other"}
	_, err := module.JWTWeakSecret(token, wordlist)
	if err == nil {
		t.Fatal("expected error when secret not found")
	}
}

func TestJWTKidInjection(t *testing.T) {
	module := NewJWTModule()
	header := base64URLEncode([]byte(`{"alg":"HS256","kid":"old-key"}`))
	payload := base64URLEncode([]byte(`{"sub":"user1"}`))
	token := header + "." + payload + ".sig"

	result, err := module.JWTKidInjection(token, "/etc/passwd")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.Data["injected_kid"] != "/etc/passwd" {
		t.Error("expected kid injection")
	}
}

func TestJWTKeyConfusion(t *testing.T) {
	module := NewJWTModule()
	header := base64URLEncode([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64URLEncode([]byte(`{"sub":"user1"}`))
	token := header + "." + payload + ".sig"

	result, err := module.JWTKeyConfusion(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.Data["tampered_alg"] != "HS256" {
		t.Error("expected HS256 tampered alg")
	}
}

func TestJWTClaimTamper(t *testing.T) {
	module := NewJWTModule()
	header := base64URLEncode([]byte(`{"alg":"HS256"}`))
	payload := base64URLEncode([]byte(`{"sub":"user1","role":"user"}`))
	token := header + "." + payload + ".sig"

	tampered, err := module.JWTClaimTamper(token, map[string]interface{}{
		"role": "admin",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tampered == "" {
		t.Error("expected non-empty tampered token")
	}
}

func TestJWTSessionHijack(t *testing.T) {
	module := NewJWTModule()
	header := base64URLEncode([]byte(`{"alg":"HS256"}`))
	payload := base64URLEncode([]byte(`{"sub":"admin","role":"admin","admin":true}`))
	token := header + "." + payload + ".sig"

	result, err := module.JWTSessionHijack(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.Data["subject"] != "admin" {
		t.Error("expected subject admin")
	}
}

func TestOAuthRedirectManip(t *testing.T) {
	module := NewOAuthModule()
	manipulated, err := module.OAuthRedirectManip(
		"https://auth.example.com/oauth?redirect_uri=https://legit.com/callback",
		"attacker.com",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if manipulated == "" {
		t.Error("expected non-empty manipulated URL")
	}
}

func TestOAuthRedirectManipInvalidURL(t *testing.T) {
	module := NewOAuthModule()
	_, err := module.OAuthRedirectManip("://invalid", "attacker.com")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestOAuthScopeEscalation(t *testing.T) {
	module := NewOAuthModule()
	result, err := module.OAuthScopeEscalation("tok123", []string{"read", "write", "admin"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success detecting admin scope")
	}
}

func TestOAuthScopeEscalationNone(t *testing.T) {
	module := NewOAuthModule()
	result, err := module.OAuthScopeEscalation("tok123", []string{"read", "profile"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("expected no escalation for read/profile scopes")
	}
}

func TestOAuthTokenTheft(t *testing.T) {
	module := NewOAuthModule()
	result, err := module.OAuthTokenTheft("some-oauth-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
}

func TestOAuthDeviceCodeFlow(t *testing.T) {
	module := NewOAuthModule()
	result, err := module.OAuthDeviceCodeFlowPoll("client-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.Data["client_id"] != "client-123" {
		t.Error("expected client_id in data")
	}
}

func TestSessionFixation(t *testing.T) {
	config := DefaultAuthBypassConfig()
	module := NewSessionModule(config)
	result, err := module.SessionFixation("https://example.com/login")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.Data["session_id"] == "" {
		t.Error("expected session_id in data")
	}
}

func TestSessionHijack(t *testing.T) {
	config := DefaultAuthBypassConfig()
	module := NewSessionModule(config)
	result, err := module.SessionHijack("abc123session")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if result.Data["session_id"] != "abc123session" {
		t.Error("expected session_id match")
	}
}

func TestHTTPBruteforce(t *testing.T) {
	config := DefaultAuthBypassConfig()
	module := NewBruteforceModule(config)

	bfConfig := &BruteforceConfig{
		Target:      "https://example.com",
		Port:        443,
		Method:      BruteForceHTTP,
		Username:    "admin",
		Wordlist:    []string{"pass1", "pass2", "pass3"},
		MaxAttempts: 10,
		Delay:       0,
	}

	result, err := module.HTTPBruteforce(bfConfig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", result.Attempts)
	}
	if result.TotalTried != 3 {
		t.Errorf("expected total tried 3, got %d", result.TotalTried)
	}
}

func TestHTTPBruteforceMaxAttempts(t *testing.T) {
	config := DefaultAuthBypassConfig()
	module := NewBruteforceModule(config)

	bfConfig := &BruteforceConfig{
		Target:      "https://example.com",
		Wordlist:    []string{"pass1", "pass2", "pass3", "pass4", "pass5"},
		MaxAttempts: 2,
		Delay:       0,
	}

	result, err := module.HTTPBruteforce(bfConfig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Attempts != 2 {
		t.Errorf("expected 2 attempts (max), got %d", result.Attempts)
	}
}

func TestHTTPBruteforceNilConfig(t *testing.T) {
	config := DefaultAuthBypassConfig()
	module := NewBruteforceModule(config)
	_, err := module.HTTPBruteforce(nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestCredentialStuffing(t *testing.T) {
	config := DefaultAuthBypassConfig()
	module := NewBruteforceModule(config)

	creds := []CredentialPair{
		{Username: "admin", Password: "pass1"},
		{Username: "user", Password: "pass2"},
	}

	result, err := module.CredentialStuffing("https://example.com", creds)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", result.Attempts)
	}
}

func TestPasswordSpray(t *testing.T) {
	config := DefaultAuthBypassConfig()
	module := NewBruteforceModule(config)

	passwords := []string{"pass1", "pass2"}

	result, err := module.PasswordSpray("https://example.com", passwords)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Attempts != 20 {
		t.Errorf("expected 20 attempts (10 users x 2 passwords), got %d", result.Attempts)
	}
}

func TestRateLimitBypass(t *testing.T) {
	config := DefaultAuthBypassConfig()
	module := NewBruteforceModule(config)

	bypassed, err := module.RateLimitBypass("https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bypassed {
		t.Error("expected bypassed to be true")
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultAuthBypassConfig()
	if config.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", config.Timeout)
	}
	if config.UsernameField != "username" {
		t.Error("expected username field")
	}
	if config.PasswordField != "password" {
		t.Error("expected password field")
	}
	if config.LoginEndpoint != "/login" {
		t.Error("expected /login endpoint")
	}
	if len(config.Methods) != len(AllAuthBypassMethods()) {
		t.Error("expected all methods in default config")
	}
}

func TestAllAuthBypassMethods(t *testing.T) {
	methods := AllAuthBypassMethods()
	if len(methods) != 7 {
		t.Errorf("expected 7 methods, got %d", len(methods))
	}
}
