package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type JWTClaims struct {
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
	Issuer    string    `json:"iss"`
}

type JWTManager struct {
	secret     []byte
	expiry     time.Duration
	issuer     string
	blacklist  map[string]time.Time
}

func NewJWTManager(secret string, expiry time.Duration) *JWTManager {
	return &JWTManager{
		secret:    []byte(secret),
		expiry:    expiry,
		issuer:    "angel-gateway",
		blacklist: make(map[string]time.Time),
	}
}

func (m *JWTManager) GenerateToken(userID, username, role string) (string, error) {
	claims := JWTClaims{
		UserID:    userID,
		Username:  username,
		Role:      role,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(m.expiry),
		Issuer:    m.issuer,
	}

	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := fmt.Sprintf("%s.%s", headerB64, claimsB64)
	signature := m.sign(signingInput)

	return fmt.Sprintf("%s.%s", signingInput, signature), nil
}

func (m *JWTManager) ValidateToken(tokenStr string) (*JWTClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	signingInput := fmt.Sprintf("%s.%s", parts[0], parts[1])
	expectedSig := m.sign(signingInput)

	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return nil, errors.New("invalid signature")
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid claims encoding")
	}

	var claims JWTClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, errors.New("invalid claims format")
	}

	if time.Now().After(claims.ExpiresAt) {
		return nil, errors.New("token expired")
	}

	if _, blacklisted := m.blacklist[tokenStr]; blacklisted {
		return nil, errors.New("token revoked")
	}

	return &claims, nil
}

func (m *JWTManager) RevokeToken(tokenStr string) {
	m.blacklist[tokenStr] = time.Now()
}

func (m *JWTManager) sign(input string) string {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(input))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

type RBACManager struct {
	roles map[string][]string
}

func NewRBACManager() *RBACManager {
	return &RBACManager{
		roles: map[string][]string{
			"admin":   {"read", "write", "delete", "execute", "manage"},
			"operator": {"read", "write", "execute"},
			"viewer":  {"read"},
			"guest":   {},
		},
	}
}

func (r *RBACManager) HasPermission(role, permission string) bool {
	perms, exists := r.roles[role]
	if !exists {
		return false
	}
	for _, p := range perms {
		if p == permission {
			return true
		}
	}
	return false
}

func (r *RBACManager) RequireRole(role string, requiredRole string) error {
	roleLevel := map[string]int{"guest": 0, "viewer": 1, "operator": 2, "admin": 3}
	if roleLevel[role] < roleLevel[requiredRole] {
		return fmt.Errorf("insufficient permissions: requires %s role", requiredRole)
	}
	return nil
}
