package dnssec

import "time"

type DNSSECConfig struct {
	Domain    string        `json:"domain"`
	DNSServer string        `json:"dns_server"`
	ZoneFile  string        `json:"zone_file"`
	Timeout   time.Duration `json:"timeout"`
}

type DNSSECResult struct {
	Success  bool          `json:"success"`
	Method   string        `json:"method"`
	Message  string        `json:"message"`
	Duration time.Duration `json:"duration"`
	Records  []string      `json:"records"`
	Count    int           `json:"count"`
}

type DNSSECAttack struct {
	Algorithm   int    `json:"algorithm"`
	KeyTag      int    `json:"key_tag"`
	SignerName  string `json:"signer_name"`
	TypeCovered string `json:"type_covered"`
}

type NSECRecord struct {
	NextDomain  string   `json:"next_domain"`
	TypeBitmaps []string `json:"type_bitmaps"`
}

type DNSKEYRecord struct {
	Flags     int    `json:"flags"`
	Protocol  int    `json:"protocol"`
	Algorithm int    `json:"algorithm"`
	PublicKey string `json:"public_key"`
	Zone      string `json:"zone"`
}

type RRSIGRecord struct {
	TypeCovered string `json:"type_covered"`
	Algorithm   int    `json:"algorithm"`
	Labels      int    `json:"labels"`
	OriginalTTL uint32 `json:"original_ttl"`
	Expiration  string `json:"expiration"`
	Inception   string `json:"inception"`
	KeyTag      int    `json:"key_tag"`
	SignerName  string `json:"signer_name"`
	Signature   string `json:"signature"`
}

type ZoneInfo struct {
	Domain    string        `json:"domain"`
	Serial    int           `json:"serial"`
	SOA       string        `json:"soa"`
	NameServers []string    `json:"name_servers"`
	DNSKEY    []DNSKEYRecord `json:"dnskey"`
	RRSIG     []RRSIGRecord  `json:"rrsig"`
	NSEC      []NSECRecord   `json:"nsec"`
}

type ZoneWalkResult struct {
	Domain    string   `json:"domain"`
	Records   []string `json:"records"`
	Subdomains []string `json:"subdomains"`
	Total     int      `json:"total"`
}

type KeyRollResult struct {
	OldKeyTag  int    `json:"old_key_tag"`
	NewKeyTag  int    `json:"new_key_tag"`
	Algorithm  int    `json:"algorithm"`
	Rolled     bool   `json:"rolled"`
}
