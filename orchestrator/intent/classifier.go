package intent

import (
	"strings"
	"sync"
)

type IntentClassifier struct {
	rules   []ClassificationRule
	patterns map[string][]string
	mu      sync.RWMutex
}

type IntentType string

const (
	IntentRecon         IntentType = "recon"
	IntentExploit       IntentType = "exploit"
	IntentPostExploit   IntentType = "post_exploit"
	IntentLateral       IntentType = "lateral_movement"
	IntentPersistence   IntentType = "persistence"
	IntentExfiltration  IntentType = "exfiltration"
	IntentDestruction   IntentType = "destruction"
	IntentCredential    IntentType = "credential_access"
	IntentCollection    IntentType = "collection"
	IntentDefense       IntentType = "defense_evasion"
	IntentUnknown       IntentType = "unknown"
)

type ClassificationResult struct {
	Intent     IntentType
	Confidence float64
	Tags       []string
	RiskScore  int
	Modules    []string
}

type ClassificationRule struct {
	Intent    IntentType
	Keywords  []string
	Patterns  []string
	RiskScore int
	Modules   []string
}

func NewIntentClassifier() *IntentClassifier {
	ic := &IntentClassifier{
		rules:    make([]ClassificationRule, 0),
		patterns: make(map[string][]string),
	}
	ic.loadDefaultRules()
	return ic
}

func (ic *IntentClassifier) loadDefaultRules() {
	ic.rules = []ClassificationRule{
		{
			Intent:    IntentRecon,
			Keywords:  []string{"scan", "recon", "enumerate", "discover", "find", "search", "lookup", "whois", "dns", "nmap"},
			Patterns:  []string{"subdomain", "port scan", "service detect"},
			RiskScore: 10,
			Modules:   []string{"osint", "recon", "scan"},
		},
		{
			Intent:    IntentExploit,
			Keywords:  []string{"exploit", "attack", "inject", "overflow", "rce", "sqli", "xss", "ssrf", "lfi"},
			Patterns:  []string{"remote code", "command injection", "file inclusion"},
			RiskScore: 80,
			Modules:   []string{"exploit", "sqli", "xss", "ssrf"},
		},
		{
			Intent:    IntentPostExploit,
			Keywords:  []string{"post", "privilege", "escalate", "dump", "extract", "harvest", "mimikatz"},
			Patterns:  []string{"privilege escalation", "credential dump"},
			RiskScore: 70,
			Modules:   []string{"credential", "collector"},
		},
		{
			Intent:    IntentLateral,
			Keywords:  []string{"lateral", "pivot", "move", "jump", "smb", "wmi", "psexec", "ssh"},
			Patterns:  []string{"lateral movement", "pass the hash"},
			RiskScore: 60,
			Modules:   []string{"lateral", "smb_beacon"},
		},
		{
			Intent:    IntentPersistence,
			Keywords:  []string{"persist", "backdoor", "autorun", "startup", "cron", "registry", "service"},
			Patterns:  []string{"persistence mechanism", "establish foothold"},
			RiskScore: 65,
			Modules:   []string{"persistence", "implant"},
		},
		{
			Intent:    IntentExfiltration,
			Keywords:  []string{"exfil", "steal", "download", "upload", "extract", "data", "sensitive"},
			Patterns:  []string{"data exfiltration", "sensitive data"},
			RiskScore: 85,
			Modules:   []string{"collector", "exfil"},
		},
		{
			Intent:    IntentDestruction,
			Keywords:  []string{"destroy", "wipe", "delete", "encrypt", "ransom", "impact", "corrupt"},
			Patterns:  []string{"data destruction", "ransomware"},
			RiskScore: 95,
			Modules:   []string{"destruction", "destructionchain"},
		},
		{
			Intent:    IntentCredential,
			Keywords:  []string{"password", "hash", "credential", "token", "key", "secret", "kerberos"},
			Patterns:  []string{"credential access", "password spray"},
			RiskScore: 75,
			Modules:   []string{"credential", "authbypass"},
		},
		{
			Intent:    IntentCollection,
			Keywords:  []string{"collect", "screenshot", "keylog", "clipboard", "audio", "video", "browser"},
			Patterns:  []string{"info stealer", "data collection"},
			RiskScore: 55,
			Modules:   []string{"collector"},
		},
		{
			Intent:    IntentDefense,
			Keywords:  []string{"evade", "bypass", "disable", "unhook", "patch", "sleep mask", "amsi", "etw"},
			Patterns:  []string{"defense evasion", "bypass security"},
			RiskScore: 50,
			Modules:   []string{"evasion"},
		},
	}
}

func (ic *IntentClassifier) Classify(input string) *ClassificationResult {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	inputLower := strings.ToLower(input)
	bestMatch := &ClassificationResult{
		Intent:     IntentUnknown,
		Confidence: 0,
		RiskScore:  0,
	}

	for _, rule := range ic.rules {
		score := 0.0
		matchedKeywords := 0

		for _, keyword := range rule.Keywords {
			if strings.Contains(inputLower, keyword) {
				score += 0.15
				matchedKeywords++
			}
		}

		for _, pattern := range rule.Patterns {
			if strings.Contains(inputLower, pattern) {
				score += 0.25
				matchedKeywords++
			}
		}

		if matchedKeywords > 0 {
			confidence := score
			if confidence > 1.0 {
				confidence = 1.0
			}

			if confidence > bestMatch.Confidence {
				bestMatch = &ClassificationResult{
					Intent:     rule.Intent,
					Confidence: confidence,
					Tags:       extractTags(inputLower),
					RiskScore:  rule.RiskScore,
					Modules:    rule.Modules,
				}
			}
		}
	}

	return bestMatch
}

func (ic *IntentClassifier) AddRule(rule ClassificationRule) {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	ic.rules = append(ic.rules, rule)
}

func extractTags(input string) []string {
	tags := make([]string, 0)
	words := strings.Fields(input)
	for _, word := range words {
		if len(word) > 3 {
			tags = append(tags, word)
		}
	}
	return tags
}
