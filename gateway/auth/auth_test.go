package auth

import (
	"strings"
	"testing"
	"time"
)

func TestJWTManager_GenerateAndValidate(t *testing.T) {
	mgr := NewJWTManager("test-secret-key", time.Hour)

	token, err := mgr.GenerateToken("user-1", "admin", "admin")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 token parts, got %d", len(parts))
	}

	claims, err := mgr.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}

	if claims.UserID != "user-1" {
		t.Errorf("UserID = %q, want %q", claims.UserID, "user-1")
	}
	if claims.Username != "admin" {
		t.Errorf("Username = %q, want %q", claims.Username, "admin")
	}
	if claims.Role != "admin" {
		t.Errorf("Role = %q, want %q", claims.Role, "admin")
	}
	if claims.Issuer != "angel-gateway" {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, "angel-gateway")
	}
	if claims.ExpiresAt.Before(time.Now()) {
		t.Error("token should not be expired yet")
	}
}

func TestJWTManager_InvalidToken(t *testing.T) {
	mgr := NewJWTManager("test-secret", time.Hour)

	_, err := mgr.ValidateToken("invalid.token")
	if err == nil {
		t.Error("expected error for invalid token format")
	}

	_, err = mgr.ValidateToken("aaa.bbb.ccc")
	if err == nil {
		t.Error("expected error for invalid signature")
	}

	_, err = mgr.ValidateToken("")
	if err == nil {
		t.Error("expected error for empty token")
	}
}

func TestJWTManager_RevokeToken(t *testing.T) {
	mgr := NewJWTManager("test-secret", time.Hour)

	token, _ := mgr.GenerateToken("user-1", "admin", "admin")

	_, err := mgr.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken before revoke: %v", err)
	}

	mgr.RevokeToken(token)

	_, err = mgr.ValidateToken(token)
	if err == nil {
		t.Error("expected error for revoked token")
	}
}

func TestJWTManager_WrongSecret(t *testing.T) {
	mgr1 := NewJWTManager("secret-1", time.Hour)
	mgr2 := NewJWTManager("secret-2", time.Hour)

	token, _ := mgr1.GenerateToken("user-1", "admin", "admin")

	_, err := mgr2.ValidateToken(token)
	if err == nil {
		t.Error("expected error for wrong secret")
	}
}

func TestRBACManager_HasPermission(t *testing.T) {
	rbac := NewRBACManager()

	tests := []struct {
		role       string
		perm       string
		wantResult bool
	}{
		{"admin", "read", true},
		{"admin", "write", true},
		{"admin", "delete", true},
		{"admin", "execute", true},
		{"admin", "manage", true},
		{"operator", "read", true},
		{"operator", "write", true},
		{"operator", "execute", true},
		{"operator", "delete", false},
		{"viewer", "read", true},
		{"viewer", "write", false},
		{"guest", "read", false},
		{"unknown", "read", false},
	}

	for _, tt := range tests {
		got := rbac.HasPermission(tt.role, tt.perm)
		if got != tt.wantResult {
			t.Errorf("HasPermission(%q, %q) = %v, want %v", tt.role, tt.perm, got, tt.wantResult)
		}
	}
}

func TestRBACManager_RequireRole(t *testing.T) {
	rbac := NewRBACManager()

	tests := []struct {
		role         string
		requiredRole string
		wantErr      bool
	}{
		{"admin", "admin", false},
		{"admin", "operator", false},
		{"admin", "viewer", false},
		{"operator", "operator", false},
		{"operator", "viewer", false},
		{"operator", "admin", true},
		{"viewer", "admin", true},
		{"viewer", "operator", true},
		{"guest", "viewer", true},
	}

	for _, tt := range tests {
		err := rbac.RequireRole(tt.role, tt.requiredRole)
		if (err != nil) != tt.wantErr {
			t.Errorf("RequireRole(%q, %q) error = %v, wantErr %v", tt.role, tt.requiredRole, err, tt.wantErr)
		}
	}
}
