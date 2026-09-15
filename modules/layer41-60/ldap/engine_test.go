package ldap

import (
	"strings"
	"testing"
)

func newTestEngine() *Engine {
	eng := NewEngine(LDAPConfig{
		Host:     "ldap.test.local",
		Port:     389,
		BaseDN:   "DC=test,DC=local",
		BindDN:   "cn=admin,DC=test,DC=local",
		BindPass: "password",
		PageSize: 100,
	})

	eng.AddEntry("cn=alice,DC=test,DC=local", map[string][]string{
		"cn":             {"alice"},
		"sAMAccountName": {"alice"},
		"mail":           {"alice@test.local"},
		"memberOf":       {"cn=admins,DC=test,DC=local"},
		"objectClass":    {"user"},
	})
	eng.AddEntry("cn=bob,DC=test,DC=local", map[string][]string{
		"cn":             {"bob"},
		"sAMAccountName": {"bob"},
		"mail":           {"bob@test.local"},
		"objectClass":    {"user"},
	})
	eng.AddEntry("cn=svc-ldap,DC=test,DC=local", map[string][]string{
		"cn":                   {"svc-ldap"},
		"servicePrincipalName": {"LDAP/ldap.test.local:389"},
		"objectClass":          {"user"},
	})

	return eng
}

func TestFilterInjection(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.FilterInjection("admin", "(uid=%s)")
	if err != nil {
		t.Fatalf("FilterInjection failed: %v", err)
	}
	if !result.Success {
		t.Error("FilterInjection reported failure")
	}
	if result.Method != "Filter_Injection" {
		t.Errorf("expected method Filter_Injection, got %s", result.Method)
	}
}

func TestFilterInjectionEscapeChars(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.FilterInjection("admin*)(|(cn=*", "")
	if err != nil {
		t.Fatalf("FilterInjection failed: %v", err)
	}
	if !strings.Contains(result.Message, "admin") {
		t.Error("message should contain the username")
	}
}

func TestNullBind(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.NullBind()
	if err != nil {
		t.Fatalf("NullBind failed: %v", err)
	}
	if result.Method != "Null_Bind" {
		t.Errorf("expected method Null_Bind, got %s", result.Method)
	}
}

func TestNullBindAnonymous(t *testing.T) {
	eng := NewEngine(LDAPConfig{
		Host: "ldap.test.local",
		Port: 389,
	})
	result, err := eng.NullBind()
	if err != nil {
		t.Fatalf("NullBind failed: %v", err)
	}
	if !result.Success {
		t.Error("null bind should be accepted for anonymous config")
	}
}

func TestWildcardInjection(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.WildcardInjection("DC=test,DC=local", "cn")
	if err != nil {
		t.Fatalf("WildcardInjection failed: %v", err)
	}
	if !result.Success {
		t.Error("WildcardInjection reported failure")
	}
	if result.Count == 0 {
		t.Error("expected some results from wildcard injection")
	}
}

func TestUserEnum(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.UserEnum("a")
	if err != nil {
		t.Fatalf("UserEnum failed: %v", err)
	}
	if !result.Success {
		t.Error("UserEnum reported failure")
	}
	if result.Count == 0 {
		t.Error("expected some users from enumeration")
	}
}

func TestSPNEnum(t *testing.T) {
	eng := newTestEngine()
	result, err := eng.SPNEnum("LDAP")
	if err != nil {
		t.Fatalf("SPNEnum failed: %v", err)
	}
	if !result.Success {
		t.Error("SPNEnum reported failure")
	}
}

func TestParseSPN(t *testing.T) {
	eng := newTestEngine()
	service, host, port := eng.ParseSPN("HTTP/webserver.example.com:443")
	if service != "HTTP" {
		t.Errorf("expected service HTTP, got %s", service)
	}
	if host != "webserver.example.com" {
		t.Errorf("expected host webserver.example.com, got %s", host)
	}
	if port != 443 {
		t.Errorf("expected port 443, got %d", port)
	}
}

func TestParseSPNNoPort(t *testing.T) {
	eng := newTestEngine()
	service, host, _ := eng.ParseSPN("LDAP/ldap.example.com")
	if service != "LDAP" {
		t.Errorf("expected LDAP, got %s", service)
	}
	if host != "ldap.example.com" {
		t.Errorf("expected ldap.example.com, got %s", host)
	}
}

func TestBuildSearchFilter(t *testing.T) {
	eng := newTestEngine()
	tests := []struct {
		attr, val, op, want string
	}{
		{"cn", "admin", "equals", "(cn=admin)"},
		{"cn", "adm", "contains", "(cn=*adm*)"},
		{"cn", "adm", "starts", "(cn=adm*)"},
		{"cn", "min", "ends", "(cn=*min)"},
	}
	for _, tt := range tests {
		got := eng.BuildSearchFilter(tt.attr, tt.val, tt.op)
		if got != tt.want {
			t.Errorf("BuildSearchFilter(%s,%s,%s) = %s, want %s", tt.attr, tt.val, tt.op, got, tt.want)
		}
	}
}

func TestAddEntry(t *testing.T) {
	eng := NewEngine(LDAPConfig{Host: "test", BaseDN: "DC=test"})
	eng.AddEntry("cn=test,DC=test", map[string][]string{"cn": {"test"}})
	entries := eng.GetEntries()
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].DN != "cn=test,DC=test" {
		t.Errorf("wrong DN: %s", entries[0].DN)
	}
}

func TestMatchesFilter(t *testing.T) {
	eng := newTestEngine()
	entry := LDAPEntry{
		DN:         "cn=test,DC=test,DC=local",
		Attributes: map[string][]string{"cn": {"test"}, "objectClass": {"user"}},
	}
	tests := []struct {
		filter string
		want   bool
	}{
		{"(cn=test)", true},
		{"(cn=other)", false},
		{"", true},
		{"(cn=*)", true},
	}
	for _, tt := range tests {
		got := eng.matchesFilter(entry, tt.filter)
		if got != tt.want {
			t.Errorf("matchesFilter(%s) = %v, want %v", tt.filter, got, tt.want)
		}
	}
}
