package api

import (
	"testing"
)

func TestOAuthRedirectAttack(t *testing.T) {
	engine := NewEngine(APIConfig{
		BaseURL: "https://api.example.com",
	})

	result := engine.OAuthRedirectAttack(OAuthConfig{
		ClientID:     "client123",
		ClientSecret: "secret456",
		RedirectURI:  "http://localhost/callback",
		AuthURL:      "https://auth.example.com/authorize",
		TokenURL:     "https://auth.example.com/token",
		Scope:        "read write",
		Flow:         OAuthFlowAuthorizationCode,
	})

	if len(result.OAuthIssues) == 0 {
		t.Error("Expected OAuth issues")
	}
	for _, issue := range result.OAuthIssues {
		if issue.Issue == "" {
			t.Error("Issue should not be empty")
		}
	}
}

func TestJWTAlgorithmBypass(t *testing.T) {
	engine := NewEngine(APIConfig{BaseURL: "https://api.example.com"})

	result := engine.JWTAlgorithmBypass("")

	if len(result.JWTIssues) == 0 {
		t.Error("Expected JWT issues")
	}
}

func TestRateLimitBypass(t *testing.T) {
	engine := NewEngine(APIConfig{
		BaseURL:   "https://api.example.com",
		RateLimit: 100,
	})

	result := engine.RateLimitBypass("/api/v1/login")

	if len(result.RateLimitFindings) == 0 {
		t.Error("Expected rate limit findings")
	}
	for _, finding := range result.RateLimitFindings {
		if finding.Bypass == "" {
			t.Error("Bypass should not be empty")
		}
	}
}

func TestIDOREnum(t *testing.T) {
	engine := NewEngine(APIConfig{BaseURL: "https://api.example.com"})

	result := engine.IDOREnum("/api/v1")

	if len(result.IDORFindings) == 0 {
		t.Error("Expected IDOR findings")
	}
	for _, idor := range result.IDORFindings {
		if idor.Path == "" {
			t.Error("Path should not be empty")
		}
		if idor.Parameter == "" {
			t.Error("Parameter should not be empty")
		}
	}
}

func TestEngineCreation(t *testing.T) {
	engine := NewEngine(APIConfig{})
	if engine == nil {
		t.Fatal("Engine should not be nil")
	}
	if engine.config.BaseURL != "https://api.example.com" {
		t.Error("Default base URL should be set")
	}
}

func TestAuthMethods(t *testing.T) {
	methods := []AuthMethod{
		AuthMethodBearer, AuthMethodAPIKey, AuthMethodOAuth2,
		AuthMethodBasicAuth, AuthMethodJWT,
	}
	for _, m := range methods {
		if m.String() == "" {
			t.Errorf("AuthMethod %d should have string", m)
		}
	}
}
