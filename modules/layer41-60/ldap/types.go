package ldap

import "time"

type LDAPConfig struct {
	Host       string        `json:"host"`
	Port       int           `json:"port"`
	BaseDN     string        `json:"base_dn"`
	BindDN     string        `json:"bind_dn"`
	BindPass   string        `json:"bind_pass"`
	UseTLS     bool          `json:"use_tls"`
	Timeout    time.Duration `json:"timeout"`
	PageSize   int           `json:"page_size"`
}

type LDAPResult struct {
	Success  bool          `json:"success"`
	Method   string        `json:"method"`
	Message  string        `json:"message"`
	Duration time.Duration `json:"duration"`
	Results  []string      `json:"results"`
	Count    int           `json:"count"`
}

type LDAPAttack struct {
	Filter    string `json:"filter"`
	BaseDN    string `json:"base_dn"`
	Scope     int    `json:"scope"`
	Attributes []string `json:"attributes"`
}

type LDAPEnum struct {
	Domain    string   `json:"domain"`
	DC        string   `json:"dc"`
	Forest    string   `json:"forest"`
	Users     []string `json:"users"`
	Groups    []string `json:"groups"`
	Servers   []string `json:"servers"`
	SPNs       []string `json:"spns"`
}

type LDAPEntry struct {
	DN         string            `json:"dn"`
	Attributes map[string][]string `json:"attributes"`
}

type LDAPSearchRequest struct {
	BaseDN       string   `json:"base_dn"`
	Scope        int      `json:"scope"`
	DerefAliases int      `json:"deref_aliases"`
	SizeLimit    int      `json:"size_limit"`
	TimeLimit    int      `json:"time_limit"`
	TypesOnly    bool     `json:"types_only"`
	Filter       string   `json:"filter"`
	Attributes   []string `json:"attributes"`
}

type InjectionPayload struct {
	Filter   string `json:"filter"`
	Username string `json:"username"`
	Password string `json:"password"`
	Encoded  string `json:"encoded"`
}

type SPNEntry struct {
	Service string `json:"service"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	DN      string `json:"dn"`
}

type LDAPResponse struct {
	Entries  []LDAPEntry `json:"entries"`
	Referrals []string   `json:"referrals"`
	ResultCode int       `json:"result_code"`
	ErrorMessage string  `json:"error_message"`
}
