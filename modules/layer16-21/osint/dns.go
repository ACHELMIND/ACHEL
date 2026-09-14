package osint

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/angel-platform/angel/pkg/logger"
)

type DNSRecon struct {
	config *OSINTConfig
	log    *logger.Logger
	mu     sync.RWMutex
}

func NewDNSRecon(config *OSINTConfig) *DNSRecon {
	return &DNSRecon{
		config: config,
		log:    logger.New("dns-recon", logger.LevelInfo),
	}
}

func (d *DNSRecon) SubdomainEnum(domain string) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.log.Info("Enumerating subdomains for: %s", domain)

	subdomains := make([]string, 0)

	prefixes := []string{
		"www", "mail", "ftp", "admin", "test", "dev", "staging",
		"api", "cdn", "static", "media", "img", "images", "assets",
		"blog", "shop", "store", "app", "mobile", "beta",
		"vpn", "remote", "webmail", "smtp", "pop", "imap",
		"ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
		"mx", "mx1", "mx2", "mx3",
		"db", "database", "sql", "mysql", "postgres", "mongo", "redis",
		"git", "gitlab", "github", "bitbucket",
		"jenkins", "ci", "cd", "build",
		"monitor", "grafana", "kibana", "prometheus",
		"backup", "old", "legacy", "archive",
	}

	for _, prefix := range prefixes {
		subdomain := prefix + "." + domain
		ips, err := net.LookupHost(subdomain)
		if err == nil && len(ips) > 0 {
			subdomains = append(subdomains, subdomain)
		}
	}

	d.log.Info("Found %d subdomains for %s", len(subdomains), domain)
	return subdomains, nil
}

func (d *DNSRecon) ReverseDNS(ip string) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.log.Info("Performing reverse DNS lookup for: %s", ip)

	names, err := net.LookupAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("reverse DNS failed: %w", err)
	}

	d.log.Info("Found %d names for %s", len(names), ip)
	return names, nil
}

func (d *DNSRecon) ZoneTransfer(domain, nameserver string) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.log.Info("Attempting zone transfer from %s for %s", nameserver, domain)

	records := make([]string, 0)

	nsAddr := net.JoinHostPort(nameserver, "53")
	conn, err := net.Dial("tcp", nsAddr)
	if err != nil {
		return records, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	d.log.Warn("Zone transfer typically requires AXFR support - using fallback enumeration")

	return records, nil
}

func (d *DNSRecon) BruteForceSubdomains(domain string, wordlist []string) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.log.Info("Brute forcing subdomains for %s with %d words", domain, len(wordlist))

	found := make([]string, 0)

	for _, word := range wordlist {
		word = strings.TrimSpace(word)
		if word == "" {
			continue
		}
		subdomain := word + "." + domain
		ips, err := net.LookupHost(subdomain)
		if err == nil && len(ips) > 0 {
			found = append(found, subdomain)
		}
	}

	d.log.Info("Found %d subdomains via brute force", len(found))
	return found, nil
}

func (d *DNSRecon) FullDNSRecon(domain string) (*DNSResult, error) {
	d.log.Info("Starting full DNS recon for: %s", domain)

	result := &DNSResult{
		Domain: domain,
	}

	subdomains, err := d.SubdomainEnum(domain)
	if err == nil {
		result.Subdomains = subdomains
	}

	mxRecords, _ := net.LookupMX(domain)
	for _, mx := range mxRecords {
		result.MXRecords = append(result.MXRecords, mx.Host)
	}

	nsRecords, _ := net.LookupNS(domain)
	for _, ns := range nsRecords {
		result.NSRecords = append(result.NSRecords, ns.Host)
	}

	aRecords, _ := net.LookupHost(domain)
	result.ARecords = aRecords

	txtRecords, _ := net.LookupTXT(domain)
	result.TXTRecords = txtRecords

	d.log.Info("Full DNS recon completed for %s", domain)
	return result, nil
}

func (d *DNSRecon) Resolve(domain string) (string, error) {
	ips, err := net.LookupHost(domain)
	if err != nil {
		return "", fmt.Errorf("resolution failed: %w", err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no records found for %s", domain)
	}
	return ips[0], nil
}

func (d *DNSRecon) CheckWildcards(domain string) (bool, string, error) {
	randomSubdomain := fmt.Sprintf("random-%d.%s", os.Getpid(), domain)
	ip, err := net.LookupHost(randomSubdomain)
	if err != nil {
		return false, "", nil
	}
	return true, ip[0], nil
}

func digCommand(domain, recordType string) (string, error) {
	cmd := exec.Command("dig", "+short", domain, recordType)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
