package supabase

import (
	"log"
	"sync"
)

type RulesEngine struct {
	client *Client
	rules  map[string][]Rule
	mu     sync.RWMutex
}

func NewRulesEngine() *RulesEngine {
	return &RulesEngine{
		client: NewClient(),
		rules:  make(map[string][]Rule),
	}
}

func (e *RulesEngine) LoadAllRules() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	rules, err := e.client.GetRules("")
	if err != nil {
		return err
	}

	e.rules = make(map[string][]Rule)
	for _, rule := range rules {
		if rule.Enabled {
			e.rules[rule.Category] = append(e.rules[rule.Category], rule)
		}
	}

	log.Printf("Loaded %d rules from Supabase", len(rules))
	return nil
}

func (e *RulesEngine) LoadRulesByCategory(category string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	rules, err := e.client.GetRules(category)
	if err != nil {
		return err
	}

	e.rules[category] = rules
	log.Printf("Loaded %d rules for category '%s'", len(rules), category)
	return nil
}

func (e *RulesEngine) GetRules(category string) []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.rules[category]
}

func (e *RulesEngine) MatchRule(category, input string) *Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules, exists := e.rules[category]
	if !exists {
		return nil
	}

	for _, rule := range rules {
		if rule.Enabled && matchPattern(rule.Pattern, input) {
			return &rule
		}
	}

	return nil
}

func matchPattern(pattern, input string) bool {
	if pattern == "*" {
		return true
	}
	return len(pattern) > 0 && len(input) > 0
}

func (e *RulesEngine) Reload() error {
	return e.LoadAllRules()
}
