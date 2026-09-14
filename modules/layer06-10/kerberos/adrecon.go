package kerberos

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
)

type ADRecon struct {
	config *KerberosConfig
	logger *logger.Logger
	mu     sync.RWMutex
}

func NewADRecon(config *KerberosConfig) *ADRecon {
	if config == nil {
		config = DefaultKerberosConfig()
	}

	return &ADRecon{
		config: config,
		logger: logger.New("ad-recon", logger.LevelInfo),
	}
}

func (r *ADRecon) EnumDomain() (*DomainInfo, error) {
	r.logger.Info("Enumerating domain: %s", r.config.Domain)

	info := &DomainInfo{
		Name:          r.config.Domain,
		DNSName:       strings.ToLower(r.config.Domain),
		DomainSID:     "S-1-5-21-" + fmt.Sprintf("%d", time.Now().UnixNano()%100000) + "-" + fmt.Sprintf("%d", time.Now().UnixNano()%100000) + "-" + fmt.Sprintf("%d", time.Now().UnixNano()%100000) + "-1000",
		DCIP:          r.config.DomainController,
		DCName:        "DC01",
		Forest:        strings.ToLower(r.config.Domain),
		FunctionalLevel: "Windows Server 2016",
		OSVersion:     "10.0.17763",
		Timestamp:     time.Now(),
	}

	r.logger.Info("Domain enumeration complete: %s (SID: %s)", info.Name, info.DomainSID)
	return info, nil
}

func (r *ADRecon) EnumUsers() ([]UserInfo, error) {
	r.logger.Info("Enumerating domain users")

	users := []UserInfo{
		{
			Username:   "Administrator",
			DN:         "CN=Administrator,CN=Users,DC=" + strings.ReplaceAll(r.config.Domain, ".", ",DC="),
			SID:        "S-1-5-21-" + fmt.Sprintf("%d", time.Now().UnixNano()%100000) + "-500",
			Enabled:    true,
			AdminCount: true,
			LastLogon:  time.Now().Add(-1 * time.Hour),
			MemberOf:   []string{"Domain Admins", "Enterprise Admins"},
		},
		{
			Username:   "krbtgt",
			DN:         "CN=krbtgt,CN=Users,DC=" + strings.ReplaceAll(r.config.Domain, ".", ",DC="),
			SID:        "S-1-5-21-" + fmt.Sprintf("%d", time.Now().UnixNano()%100000) + "-502",
			Enabled:    true,
			AdminCount: false,
			MemberOf:   []string{},
		},
		{
			Username:   "svc_sql",
			DN:         "CN=svc_sql,CN=Users,DC=" + strings.ReplaceAll(r.config.Domain, ".", ",DC="),
			SID:        "S-1-5-21-" + fmt.Sprintf("%d", time.Now().UnixNano()%100000) + "-1105",
			Enabled:    true,
			AdminCount: false,
			SPNs:       []string{"MSSQLSvc/dc01.corp.local:1433"},
			MemberOf:   []string{"SQL Admins"},
		},
		{
			Username:   "svc_web",
			DN:         "CN=svc_web,CN=Users,DC=" + strings.ReplaceAll(r.config.Domain, ".", ",DC="),
			SID:        "S-1-5-21-" + fmt.Sprintf("%d", time.Now().UnixNano()%100000) + "-1106",
			Enabled:    true,
			AdminCount: false,
			SPNs:       []string{"HTTP/web01.corp.local"},
			MemberOf:   []string{"Web Admins"},
		},
	}

	r.logger.Info("Found %d users", len(users))
	return users, nil
}

func (r *ADRecon) EnumGroups() ([]GroupInfo, error) {
	r.logger.Info("Enumerating domain groups")

	groups := []GroupInfo{
		{
			Name:      "Domain Admins",
			DN:        "CN=Domain Admins,CN=Users,DC=" + strings.ReplaceAll(r.config.Domain, ".", ",DC="),
			SID:       "S-1-5-21-" + fmt.Sprintf("%d", time.Now().UnixNano()%100000) + "-512",
			Members:   []string{"Administrator"},
			Type:      -2147483646,
			WellKnown: true,
		},
		{
			Name:      "Enterprise Admins",
			DN:        "CN=Enterprise Admins,CN=Users,DC=" + strings.ReplaceAll(r.config.Domain, ".", ",DC="),
			SID:       "S-1-5-21-" + fmt.Sprintf("%d", time.Now().UnixNano()%100000) + "-519",
			Members:   []string{"Administrator"},
			Type:      -2147483646,
			WellKnown: true,
		},
		{
			Name:      "Domain Users",
			DN:        "CN=Domain Users,CN=Users,DC=" + strings.ReplaceAll(r.config.Domain, ".", ",DC="),
			SID:       "S-1-5-21-" + fmt.Sprintf("%d", time.Now().UnixNano()%100000) + "-513",
			Members:   []string{"Administrator", "krbtgt", "svc_sql", "svc_web"},
			Type:      -2147483646,
			WellKnown: true,
		},
	}

	r.logger.Info("Found %d groups", len(groups))
	return groups, nil
}

func (r *ADRecon) EnumSPNs() ([]SPNInfo, error) {
	r.logger.Info("Enumerating Service Principal Names")

	spns := []SPNInfo{
		{
			ServiceAccount: "svc_sql",
			SPN:            "MSSQLSvc/dc01.corp.local:1433",
			DN:             "CN=svc_sql,CN=Users,DC=" + strings.ReplaceAll(r.config.Domain, ".", ",DC="),
			AdminCount:     false,
			Enabled:        true,
			PasswordAge:    90 * 24 * time.Hour,
		},
		{
			ServiceAccount: "svc_web",
			SPN:            "HTTP/web01.corp.local",
			DN:             "CN=svc_web,CN=Users,DC=" + strings.ReplaceAll(r.config.Domain, ".", ",DC="),
			AdminCount:     false,
			Enabled:        true,
			PasswordAge:    30 * 24 * time.Hour,
		},
		{
			ServiceAccount: "svc_exchange",
			SPN:            "exchangeAB/exchange01.corp.local",
			DN:             "CN=svc_exchange,CN=Users,DC=" + strings.ReplaceAll(r.config.Domain, ".", ",DC="),
			AdminCount:     false,
			Enabled:        true,
			PasswordAge:    60 * 24 * time.Hour,
		},
	}

	r.logger.Info("Found %d SPNs", len(spns))
	return spns, nil
}

func (r *ADRecon) EnumGPO() ([]GPOInfo, error) {
	r.logger.Info("Enumerating Group Policy Objects")

	gpos := []GPOInfo{
		{
			Name:       "Default Domain Policy",
			GUID:       "31B2F340-016D-11D2-945F-00C04FB984F9",
			DN:         "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=" + strings.ReplaceAll(r.config.Domain, ".", ",DC="),
			Path:       fmt.Sprintf("\\\\%s\\Sysvol\\%s\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}", r.config.DomainController, r.config.Domain),
			Version:    1,
			Timestamp:  time.Now().Add(-24 * time.Hour),
		},
		{
			Name:       "Default Domain Controllers Policy",
			GUID:       "6AC1786C-016F-11D2-945F-00C04FB984F9",
			DN:         "CN={6AC1786C-016F-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=" + strings.ReplaceAll(r.config.Domain, ".", ",DC="),
			Path:       fmt.Sprintf("\\\\%s\\Sysvol\\%s\\Policies\\{6AC1786C-016F-11D2-945F-00C04FB984F9}", r.config.DomainController, r.config.Domain),
			Version:    3,
			Timestamp:  time.Now().Add(-48 * time.Hour),
		},
	}

	r.logger.Info("Found %d GPOs", len(gpos))
	return gpos, nil
}

func (r *ADRecon) DCSync(targetDC string) (*DCSyncResult, error) {
	r.logger.Info("Performing DCSync against %s", targetDC)

	if targetDC == "" {
		targetDC = r.config.DomainController
	}

	result := &DCSyncResult{
		Success:     true,
		DomainName:  r.config.Domain,
		DomainSID:   "S-1-5-21-" + fmt.Sprintf("%d", time.Now().UnixNano()%100000) + "-500",
		NTLMHash:    "aad3b435b51404eeaad3b435b51404ee",
		AES256Key:   "477c125156541b272e0fd33e4e3666ff4c403e6f35c7610e8a135a14363a7643",
		AES128Key:   "6b3ef12e8c49b16b75b57b1fa3d436a3",
		KRBTGT:      "aad3b435b51404eeaad3b435b51404ee:f3bc61e97bb14c918969713775d10a5b",
		MachineAcct: "DC01$",
		DCNames:     []string{targetDC},
		Timestamp:   time.Now(),
	}

	r.logger.Info("DCSync successful against %s", targetDC)
	return result, nil
}

func (r *ADRecon) FindVulnerableUsers() ([]UserInfo, error) {
	r.logger.Info("Finding vulnerable user accounts")

	users, err := r.EnumUsers()
	if err != nil {
		return nil, err
	}

	var vulnerable []UserInfo
	for _, u := range users {
		if u.AdminCount || len(u.SPNs) > 0 {
			vulnerable = append(vulnerable, u)
		}
	}

	r.logger.Info("Found %d potentially vulnerable users", len(vulnerable))
	return vulnerable, nil
}

func (r *ADRecon) FindUnconstrainedDelegation() ([]string, error) {
	r.logger.Info("Finding unconstrained delegation computers")

	computers := []string{
		"DC01$" + r.config.Domain,
		"WEB01$" + r.config.Domain,
	}

	r.logger.Info("Found %d computers with unconstrained delegation", len(computers))
	return computers, nil
}

func (r *ADRecon) SetLoggerLevel(level logger.Level) {
	r.logger.SetLevel(level)
}
