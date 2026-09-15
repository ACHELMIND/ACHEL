package ldap

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	config LDAPConfig
	entries []LDAPEntry
	mu     sync.Mutex
}

func NewEngine(cfg LDAPConfig) *Engine {
	if cfg.Port == 0 {
		cfg.Port = 389
	}
	if cfg.PageSize == 0 {
		cfg.PageSize = 100
	}
	return &Engine{
		config: cfg,
		entries: make([]LDAPEntry, 0),
	}
}

func (e *Engine) FilterInjection(username string, filterTemplate string) (*LDAPResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	injected := e.buildInjectionFilter(username, filterTemplate)

	searchReq := LDAPSearchRequest{
		BaseDN:       e.config.BaseDN,
		Scope:        2, // subtree
		Filter:       injected,
		Attributes:   []string{"dn", "cn", "memberOf"},
		SizeLimit:    1000,
	}

	entries := e.simulateSearch(searchReq)

	return &LDAPResult{
		Success:  true,
		Method:   "Filter_Injection",
		Message:  fmt.Sprintf("Injection filter: %s (%d entries found)", injected, len(entries)),
		Duration: time.Since(start),
		Results:  e.entriesToDNs(entries),
		Count:    len(entries),
	}, nil
}

func (e *Engine) buildInjectionFilter(username string, template string) string {
	injectionChars := []string{"*", "|", "(", ")", "&", "!", "=", ">", "<"}
	injected := username

	for _, ch := range injectionChars {
		injected = strings.ReplaceAll(injected, ch, "\\"+ch)
	}

	if template == "" {
		template = "(uid=%s)"
	}

	return fmt.Sprintf(template, injected)
}

func (e *Engine) NullBind() (*LDAPResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	success := e.config.BindDN == "" || e.config.BindPass == ""

	msg := "null bind rejected"
	if success {
		msg = "null bind accepted - anonymous access enabled"
	}

	return &LDAPResult{
		Success:  success,
		Method:   "Null_Bind",
		Message:  msg,
		Duration: time.Since(start),
		Count:    0,
	}, nil
}

func (e *Engine) WildcardInjection(baseDN string, attributeName string) (*LDAPResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	wildcardFilter := fmt.Sprintf("(%s=*)", attributeName)
	searchReq := LDAPSearchRequest{
		BaseDN:     baseDN,
		Scope:      2,
		Filter:     wildcardFilter,
		Attributes: []string{attributeName},
		SizeLimit:  e.config.PageSize,
	}

	entries := e.simulateSearch(searchReq)

	results := make([]string, 0)
	for _, entry := range entries {
		if vals, ok := entry.Attributes[attributeName]; ok {
			results = append(results, vals...)
		}
	}

	return &LDAPResult{
		Success:  true,
		Method:   "Wildcard_Injection",
		Message:  fmt.Sprintf("Wildcard filter %s matched %d entries", wildcardFilter, len(entries)),
		Duration: time.Since(start),
		Results:  results,
		Count:    len(results),
	}, nil
}

func (e *Engine) UserEnum(prefix string) (*LDAPResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	users := e.enumerateUsers(prefix)

	return &LDAPResult{
		Success:  true,
		Method:   "User_Enum",
		Message:  fmt.Sprintf("Enumerated %d users with prefix '%s'", len(users), prefix),
		Duration: time.Since(start),
		Results:  users,
		Count:    len(users),
	}, nil
}

func (e *Engine) enumerateUsers(prefix string) []string {
	filter := fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s*))", prefix)
	searchReq := LDAPSearchRequest{
		BaseDN:     e.config.BaseDN,
		Scope:      2,
		Filter:     filter,
		Attributes: []string{"sAMAccountName", "cn", "mail"},
		SizeLimit:  1000,
	}

	entries := e.simulateSearch(searchReq)

	users := make([]string, 0, len(entries))
	for _, entry := range entries {
		if names, ok := entry.Attributes["sAMAccountName"]; ok {
			users = append(users, names...)
		}
	}
	return users
}

func (e *Engine) SPNEnum(serviceName string) (*LDAPResult, error) {
	start := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()

	spns := e.enumerateSPNs(serviceName)

	return &LDAPResult{
		Success:  true,
		Method:   "SPN_Enum",
		Message:  fmt.Sprintf("Enumerated %d SPNs for service '%s'", len(spns), serviceName),
		Duration: time.Since(start),
		Results:  spns,
		Count:    len(spns),
	}, nil
}

func (e *Engine) enumerateSPNs(serviceName string) []string {
	filter := fmt.Sprintf("(&(objectClass=user)(servicePrincipalName=%s/*))", serviceName)
	searchReq := LDAPSearchRequest{
		BaseDN:     e.config.BaseDN,
		Scope:      2,
		Filter:     filter,
		Attributes: []string{"servicePrincipalName", "cn"},
		SizeLimit:  1000,
	}

	entries := e.simulateSearch(searchReq)

	spns := make([]string, 0, len(entries))
	for _, entry := range entries {
		if spnList, ok := entry.Attributes["servicePrincipalName"]; ok {
			spns = append(spns, spnList...)
		}
	}
	return spns
}

func (e *Engine) simulateSearch(req LDAPSearchRequest) []LDAPEntry {
	entries := make([]LDAPEntry, 0)

	for _, entry := range e.entries {
		if e.matchesFilter(entry, req.Filter) {
			entries = append(entries, entry)
		}
	}

	return entries
}

func (e *Engine) matchesFilter(entry LDAPEntry, filter string) bool {
	if filter == "" {
		return true
	}

	filter = strings.TrimSpace(filter)

	if strings.HasPrefix(filter, "(&") {
		inner := filter
		inner = strings.TrimPrefix(inner, "(&")
		inner = strings.TrimSuffix(inner, ")")
		inner = strings.TrimSpace(inner)

		subFilters := e.parseSubFilters(inner)
		for _, sf := range subFilters {
			if !e.matchesFilter(entry, sf) {
				return false
			}
		}
		return true
	}

	if strings.HasPrefix(filter, "(|") {
		inner := filter
		inner = strings.TrimPrefix(inner, "(|")
		inner = strings.TrimSuffix(inner, ")")
		inner = strings.TrimSpace(inner)

		subFilters := e.parseSubFilters(inner)
		for _, sf := range subFilters {
			if e.matchesFilter(entry, sf) {
				return true
			}
		}
		return false
	}

	if strings.HasPrefix(filter, "(") && strings.HasSuffix(filter, ")") {
		filter = filter[1 : len(filter)-1]
	}

	parts := strings.SplitN(filter, "=", 2)
	if len(parts) != 2 {
		return true
	}

	attribute := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])

	if vals, ok := entry.Attributes[attribute]; ok {
		for _, v := range vals {
			if value == "*" || strings.HasPrefix(value, "*") && strings.HasSuffix(value, "*") {
				searchTerm := strings.Trim(value, "*")
				if strings.Contains(strings.ToLower(v), strings.ToLower(searchTerm)) {
					return true
				}
			} else if strings.HasPrefix(value, "*") {
				searchTerm := strings.TrimPrefix(value, "*")
				if strings.HasSuffix(strings.ToLower(v), strings.ToLower(searchTerm)) {
					return true
				}
			} else if strings.HasSuffix(value, "*") {
				searchTerm := strings.TrimSuffix(value, "*")
				if strings.HasPrefix(strings.ToLower(v), strings.ToLower(searchTerm)) {
					return true
				}
			} else if strings.Contains(strings.ToLower(v), strings.ToLower(value)) {
				return true
			}
		}
	}

	return false
}

func (e *Engine) parseSubFilters(filter string) []string {
	filters := make([]string, 0)
	depth := 0
	start := 0

	for i, ch := range filter {
		if ch == '(' {
			if depth == 0 {
				start = i
			}
			depth++
		} else if ch == ')' {
			depth--
			if depth == 0 {
				filters = append(filters, filter[start:i+1])
			}
		}
	}

	return filters
}

func (e *Engine) entriesToDNs(entries []LDAPEntry) []string {
	dns := make([]string, 0, len(entries))
	for _, entry := range entries {
		dns = append(dns, entry.DN)
	}
	return dns
}

func (e *Engine) AddEntry(dn string, attributes map[string][]string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.entries = append(e.entries, LDAPEntry{
		DN:         dn,
		Attributes: attributes,
	})
}

func (e *Engine) GetEntries() []LDAPEntry {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]LDAPEntry, len(e.entries))
	copy(out, e.entries)
	return out
}

func (e *Engine) ParseSPN(spn string) (service, host string, port int) {
	spn = strings.TrimSpace(spn)
	parts := strings.Split(spn, "/")
	if len(parts) < 2 {
		return "", "", 0
	}
	service = parts[0]
	hostPort := parts[1]
	if strings.Contains(hostPort, ":") {
		hp := strings.SplitN(hostPort, ":", 2)
		host = hp[0]
		fmt.Sscanf(hp[1], "%d", &port)
	} else {
		host = hostPort
	}
	return
}

func (e *Engine) BuildSearchFilter(attribute string, value string, operator string) string {
	switch operator {
	case "equals":
		return fmt.Sprintf("(%s=%s)", attribute, value)
	case "contains":
		return fmt.Sprintf("(%s=*%s*)", attribute, value)
	case "starts":
		return fmt.Sprintf("(%s=%s*)", attribute, value)
	case "ends":
		return fmt.Sprintf("(%s=*%s)", attribute, value)
	default:
		return fmt.Sprintf("(%s=%s)", attribute, value)
	}
}
