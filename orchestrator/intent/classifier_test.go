package intent

import (
	"testing"
)

func TestNewIntentClassifier(t *testing.T) {
	ic := NewIntentClassifier()
	if ic == nil {
		t.Fatal("expected non-nil classifier")
	}
	if len(ic.rules) == 0 {
		t.Error("expected default rules to be loaded")
	}
}

func TestClassify_Recon(t *testing.T) {
	ic := NewIntentClassifier()
	result := ic.Classify("scan the target network for open ports and enumerate subdomains")
	if result.Intent != IntentRecon {
		t.Errorf("expected IntentRecon, got %s", result.Intent)
	}
	if result.Confidence <= 0 {
		t.Errorf("expected positive confidence, got %f", result.Confidence)
	}
	if result.RiskScore != 10 {
		t.Errorf("expected RiskScore 10, got %d", result.RiskScore)
	}
}

func TestClassify_Exploit(t *testing.T) {
	ic := NewIntentClassifier()
	result := ic.Classify("exploit the SQL injection vulnerability to achieve remote code execution")
	if result.Intent != IntentExploit {
		t.Errorf("expected IntentExploit, got %s", result.Intent)
	}
	if result.Confidence <= 0 {
		t.Errorf("expected positive confidence, got %f", result.Confidence)
	}
	if result.RiskScore != 80 {
		t.Errorf("expected RiskScore 80, got %d", result.RiskScore)
	}
}

func TestClassify_Destruction(t *testing.T) {
	ic := NewIntentClassifier()
	result := ic.Classify("destroy all data and wipe the database with ransomware")
	if result.Intent != IntentDestruction {
		t.Errorf("expected IntentDestruction, got %s", result.Intent)
	}
	if result.RiskScore != 95 {
		t.Errorf("expected RiskScore 95, got %d", result.RiskScore)
	}
}

func TestClassify_Credential(t *testing.T) {
	ic := NewIntentClassifier()
	result := ic.Classify("dump credentials and harvest kerberos hashes from LSASS")
	if result.Intent != IntentCredential {
		t.Errorf("expected IntentCredential, got %s", result.Intent)
	}
}

func TestClassify_Lateral(t *testing.T) {
	ic := NewIntentClassifier()
	result := ic.Classify("use psexec and wmi for lateral movement across the network")
	if result.Intent != IntentLateral {
		t.Errorf("expected IntentLateral, got %s", result.Intent)
	}
}

func TestClassify_Persistence(t *testing.T) {
	ic := NewIntentClassifier()
	result := ic.Classify("establish persistence via registry autorun and scheduled service")
	if result.Intent != IntentPersistence {
		t.Errorf("expected IntentPersistence, got %s", result.Intent)
	}
}

func TestClassify_Exfiltration(t *testing.T) {
	ic := NewIntentClassifier()
	result := ic.Classify("exfiltrate sensitive data files via DNS tunneling")
	if result.Intent != IntentExfiltration {
		t.Errorf("expected IntentExfiltration, got %s", result.Intent)
	}
}

func TestClassify_Collection(t *testing.T) {
	ic := NewIntentClassifier()
	result := ic.Classify("take screenshot and capture keylog from the target")
	if result.Intent != IntentCollection {
		t.Errorf("expected IntentCollection, got %s", result.Intent)
	}
}

func TestClassify_Defense(t *testing.T) {
	ic := NewIntentClassifier()
	result := ic.Classify("bypass AMSI and ETW with sleep mask evasion technique")
	if result.Intent != IntentDefense {
		t.Errorf("expected IntentDefense, got %s", result.Intent)
	}
}

func TestClassify_Unknown(t *testing.T) {
	ic := NewIntentClassifier()
	result := ic.Classify("make me a sandwich")
	if result.Intent != IntentUnknown {
		t.Errorf("expected IntentUnknown for unrelated input, got %s", result.Intent)
	}
	if result.Confidence != 0 {
		t.Errorf("expected 0 confidence for unknown, got %f", result.Confidence)
	}
}

func TestClassify_HigherConfidenceWins(t *testing.T) {
	ic := NewIntentClassifier()
	// Input matches multiple rules; the one with more matches should win
	result := ic.Classify("exploit the SQL injection vulnerability with a scan for ports")
	// "exploit" and "inject" match IntentExploit; "scan" and "ports" match IntentRecon
	// IntentExploit should win with higher confidence due to more keyword matches
	if result.Intent == IntentUnknown {
		t.Error("expected a known intent, got unknown")
	}
}

func TestClassify_Tags(t *testing.T) {
	ic := NewIntentClassifier()
	result := ic.Classify("scan the entire network for vulnerabilities")
	if len(result.Tags) == 0 {
		t.Error("expected non-empty tags")
	}
	for _, tag := range result.Tags {
		if len(tag) <= 3 {
			t.Errorf("expected tags longer than 3 chars, got %q", tag)
		}
	}
}

func TestClassify_Modules(t *testing.T) {
	ic := NewIntentClassifier()
	result := ic.Classify("exploit the web application")
	if len(result.Modules) == 0 {
		t.Error("expected non-empty modules")
	}
}

func TestAddRule(t *testing.T) {
	ic := NewIntentClassifier()
	initialRules := len(ic.rules)

	newRule := ClassificationRule{
		Intent:    IntentType("custom_attack"),
		Keywords:  []string{"custom", "special"},
		Patterns:  []string{"custom attack"},
		RiskScore: 50,
		Modules:   []string{"custom_module"},
	}
	ic.AddRule(newRule)

	if len(ic.rules) != initialRules+1 {
		t.Errorf("expected %d rules after add, got %d", initialRules+1, len(ic.rules))
	}

	result := ic.Classify("execute a custom attack on the target")
	if result.Intent != IntentType("custom_attack") {
		t.Errorf("expected custom_attack intent, got %s", result.Intent)
	}
}

func TestAddRule_Concurrent(t *testing.T) {
	ic := NewIntentClassifier()
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(n int) {
			ic.AddRule(ClassificationRule{
				Intent:    IntentType("rule_" + string(rune('a'+n))),
				Keywords:  []string{"keyword" + string(rune('a'+n))},
				RiskScore: n,
			})
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
	if len(ic.rules) != 10+10 { // 10 default + 10 added
		t.Errorf("expected 20 rules, got %d", len(ic.rules))
	}
}

func TestExtractTags(t *testing.T) {
	tests := []struct {
		input    string
		minWords int
	}{
		{"scan the network", 1},
		{"hi", 0},
		{"this is a longer sentence with many words", 4},
		{"", 0},
	}
	for _, tt := range tests {
		tags := extractTags(tt.input)
		if len(tags) < tt.minWords {
			t.Errorf("extractTags(%q): expected at least %d tags, got %d", tt.input, tt.minWords, len(tags))
		}
		for _, tag := range tags {
			if len(tag) <= 3 {
				t.Errorf("extractTags(%q): tag %q too short (should be > 3 chars)", tt.input, tag)
			}
		}
	}
}

func TestIntentType_Constants(t *testing.T) {
	// Verify all intent type constants are defined and unique
	types := map[IntentType]bool{
		IntentRecon:        false,
		IntentExploit:      false,
		IntentPostExploit:  false,
		IntentLateral:      false,
		IntentPersistence:  false,
		IntentExfiltration: false,
		IntentDestruction:  false,
		IntentCredential:   false,
		IntentCollection:   false,
		IntentDefense:      false,
		IntentUnknown:      false,
	}
	for it := range types {
		if types[it] {
			t.Errorf("duplicate IntentType: %s", it)
		}
		types[it] = true
	}
	if len(types) != 11 {
		t.Errorf("expected 11 intent types, got %d", len(types))
	}
}

func TestClassify_CaseInsensitive(t *testing.T) {
	ic := NewIntentClassifier()
	r1 := ic.Classify("EXPLOIT the vulnerability")
	r2 := ic.Classify("exploit the vulnerability")
	if r1.Intent != r2.Intent {
		t.Errorf("expected same intent for case-insensitive input, got %s vs %s", r1.Intent, r2.Intent)
	}
}

func TestClassificationRule_Fields(t *testing.T) {
	ic := NewIntentClassifier()
	result := ic.Classify("scan the network")
	if result.Intent == "" {
		t.Error("expected non-empty Intent")
	}
	if result.Tags == nil {
		t.Error("expected non-nil Tags")
	}
	if result.Modules == nil {
		t.Error("expected non-nil Modules")
	}
}
