package mobile

import "time"

type PlatformType int

const (
	PlatformTypeIOS PlatformType = iota
	PlatformTypeAndroid
	PlatformTypeHarmonyOS
)

func (p PlatformType) String() string {
	return [...]string{"iOS", "Android", "HarmonyOS"}[p]
}

type MobileAttack int

const (
	MobileAttackKeychainDump MobileAttack = iota
	MobileAttackSSLPinning
	MobileAttackSharedPrefs
	MobileAttackBackupExtract
	MobileAttackClipboardDump
	MobileAttackDebuggerAttach
	MobileAttackRootDetection
	MobileAttackJailbreakDetect
)

func (m MobileAttack) String() string {
	return [...]string{
		"KeychainDump", "SSLPinning", "SharedPrefs",
		"BackupExtract", "ClipboardDump", "DebuggerAttach",
		"RootDetection", "JailbreakDetect",
	}[m]
}

type MobileConfig struct {
	Platform      PlatformType
	APKPath       string
	IPAPath       string
	DeviceID      string
	DeviceIP      string
	ADBPath       string
	USBEnabled    bool
	FridaServer   string
	ProxyPort     int
	Attack        MobileAttack
	PackageName   string
}

type MobileResult struct {
	ID            string              `json:"id"`
	Platform      PlatformType        `json:"platform"`
	Attacks       []MobileAttackResult `json:"attacks"`
	KeychainItems []KeychainItem      `json:"keychain_items"`
	PrefsFiles    []PrefsFile         `json:"prefs_files"`
	SSLCerts      []SSLCertInfo       `json:"ssl_certs"`
	Backups       []BackupInfo        `json:"backups"`
	Timestamp     time.Time           `json:"timestamp"`
}

type MobileAttackResult struct {
	Type    MobileAttack `json:"type"`
	Success bool         `json:"success"`
	Details string       `json:"details"`
	Data    string       `json:"data,omitempty"`
}

type KeychainItem struct {
	Service  string `json:"service"`
	Account  string `json:"account"`
	Value    string `json:"value"`
	Type     string `json:"type"`
	Access   string `json:"access_group"`
	Protected bool  `json:"protected"`
}

type PrefsFile struct {
	Path     string            `json:"path"`
	Format   string            `json:"format"`
	Content  map[string]string `json:"content"`
	Contains bool              `json:"contains_sensitive"`
}

type SSLCertInfo struct {
	Host       string `json:"host"`
	Pinned     bool   `json:"pinned"`
	Issuer     string `json:"issuer"`
	Expires    string `json:"expires"`
	Algorithm  string `json:"algorithm"`
	Bypassable bool   `json:"bypassable"`
}

type BackupInfo struct {
	Path      string `json:"path"`
	Encrypted bool   `json:"encrypted"`
	Size      int64  `json:"size"`
	Files     []string `json:"files"`
}

type KeychainConfig struct {
	AccessGroup string
	KeychainDB  string
	Export      bool
	Format      string
}

type SSLPinningConfig struct {
	ProxyHost   string
	ProxyPort   int
	CertPath    string
	FridaScript string
	BypassAll   bool
}
