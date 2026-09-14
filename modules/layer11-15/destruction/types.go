package destruction

import (
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

type DamageLevel int

const (
	DamageLevelNone DamageLevel = iota
	DamageLevelLow
	DamageLevelMedium
	DamageLevelHigh
	DamageLevelCritical
)

func (d DamageLevel) String() string {
	switch d {
	case DamageLevelNone:
		return "none"
	case DamageLevelLow:
		return "low"
	case DamageLevelMedium:
		return "medium"
	case DamageLevelHigh:
		return "high"
	case DamageLevelCritical:
		return "critical"
	default:
		return "unknown"
	}
}

type DestructionMethod string

func (d DestructionMethod) String() string {
	return string(d)
}

const (
	MethodDatabaseDrop    DestructionMethod = "database_drop"
	MethodFKDrop          DestructionMethod = "fk_drop"
	MethodAESEncrypt      DestructionMethod = "aes_encrypt"
	MethodCorruptData     DestructionMethod = "corrupt_data"
	MethodDeleteBackup    DestructionMethod = "delete_backup"
	MethodDisableRecovery DestructionMethod = "disable_recovery"
	MethodEncryptFiles    DestructionMethod = "encrypt_files"
	MethodEncryptDB       DestructionMethod = "encrypt_database"
	MethodRansomNote      DestructionMethod = "ransom_note"
	MethodKeyDestroy      DestructionMethod = "key_destroy"
	MethodZeroOverwrite   DestructionMethod = "zero_overwrite"
	MethodRandomOverwrite DestructionMethod = "random_overwrite"
	MethodMBRDestroy      DestructionMethod = "mbr_destroy"
	MethodMFTDestroy      DestructionMethod = "mft_destroy"
	MethodVolumeDismount  DestructionMethod = "volume_dismount"
	MethodRestorePtDelete DestructionMethod = "restore_point_delete"
	MethodUSNJournalClear DestructionMethod = "usn_journal_clear"
)

type TargetType string

const (
	TargetDatabase TargetType = "database"
	TargetFiles    TargetType = "files"
	TargetDisk     TargetType = "disk"
	TargetSystem   TargetType = "system"
	TargetBackup   TargetType = "backup"
)

type DestructionConfig struct {
	Target         types.Platform     `json:"target"`
	Methods        []DestructionMethod `json:"methods"`
	MaxParallel    int                `json:"max_parallel"`
	Stealth        bool               `json:"stealth"`
	DryRun         bool               `json:"dry_run"`
	Timeout        time.Duration      `json:"timeout"`
	EncryptionKey  []byte             `json:"-"`
	Metadata       map[string]string  `json:"metadata"`
}

func DefaultDestructionConfig() *DestructionConfig {
	return &DestructionConfig{
		Target:      types.PlatformLinux,
		Methods:     []DestructionMethod{},
		MaxParallel: 1,
		Stealth:     false,
		DryRun:      true,
		Timeout:     60 * time.Second,
		Metadata:    make(map[string]string),
	}
}

type DestructionChain struct {
	Steps       []DestructionStep `json:"steps"`
	Sequential  bool              `json:"sequential"`
	BreakOnError bool             `json:"break_on_error"`
}

type DestructionStep struct {
	Method   DestructionMethod     `json:"method"`
	Target   string                `json:"target"`
	Params   map[string]interface{} `json:"params"`
	Priority int                   `json:"priority"`
}

type DestructionResult struct {
	Success     bool                `json:"success"`
	Method      DestructionMethod   `json:"method"`
	Target      string              `json:"target"`
	Error       string              `json:"error"`
	Duration    time.Duration       `json:"duration"`
	Timestamp   time.Time           `json:"timestamp"`
	Details     map[string]string   `json:"details"`
	ChainID     string              `json:"chain_id"`
}

type BlastRadius struct {
	Target          string            `json:"target"`
	PrimaryDamage   DamageLevel       `json:"primary_damage"`
	CollateralDamage DamageLevel      `json:"collateral_damage"`
	AffectedSystems []string          `json:"affected_systems"`
	AffectedData    []string          `json:"affected_data"`
	RecoveryTime    time.Duration     `json:"recovery_time"`
	EscalationPath  []string          `json:"escalation_path"`
	Metadata        map[string]string `json:"metadata"`
}

type Finding struct {
	ID          string          `json:"id"`
	Target      string          `json:"target"`
	Type        string          `json:"type"`
	Severity    types.Severity  `json:"severity"`
	Description string          `json:"description"`
	Timestamp   time.Time       `json:"timestamp"`
}

type ScoredFinding struct {
	Finding     *Finding        `json:"finding"`
	Score       float64         `json:"score"`
	Priority    int             `json:"priority"`
	RiskLevel   DamageLevel     `json:"risk_level"`
}

type DatabaseTarget struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	User     string `json:"user"`
	Password string `json:"-"`
}

type FileTarget struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive"`
	Pattern   string `json:"pattern"`
}

type DiskTarget struct {
	Device string `json:"device"`
	Mount  string `json:"mount"`
	FSType string `json:"fs_type"`
}
