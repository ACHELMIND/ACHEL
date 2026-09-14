package persistence

import (
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

type PersistenceMethod string

const (
	MethodRegistryRun      PersistenceMethod = "registry_run"
	MethodScheduledTask    PersistenceMethod = "scheduled_task"
	MethodServiceInstall   PersistenceMethod = "service_install"
	MethodWMIEvent         PersistenceMethod = "wmi_event"
	MethodStartupFolder    PersistenceMethod = "startup_folder"
	MethodADS              PersistenceMethod = "ads"
	MethodDLLSideload      PersistenceMethod = "dll_sideload"
	MethodCOMHijack        PersistenceMethod = "com_hijack"
	MethodAppInit          PersistenceMethod = "app_init"
	MethodIFEO             PersistenceMethod = "ifeo"
	MethodAccessibility    PersistenceMethod = "accessibility"
	MethodCronJob          PersistenceMethod = "cron_job"
	MethodSystemdService   PersistenceMethod = "systemd_service"
	MethodRCLocal          PersistenceMethod = "rc_local"
	MethodProfileScript    PersistenceMethod = "profile_script"
	MethodBashrc           PersistenceMethod = "bashrc"
	MethodSSHKeys          PersistenceMethod = "ssh_keys"
	MethodPAMModule        PersistenceMethod = "pam_module"
	MethodUdevRule         PersistenceMethod = "udev_rule"
	MethodInitramfsHook    PersistenceMethod = "initramfs_hook"
	MethodLaunchDaemon     PersistenceMethod = "launch_daemon"
	MethodLaunchAgent      PersistenceMethod = "launch_agent"
	MethodDarwinCronJob    PersistenceMethod = "darwin_cron_job"
	MethodDarwinSSHKeys    PersistenceMethod = "darwin_ssh_keys"
	MethodLoginItem        PersistenceMethod = "login_item"
	MethodKernelExtension  PersistenceMethod = "kernel_extension"
	MethodMagiskModule     PersistenceMethod = "magisk_module"
	MethodBootCompleted    PersistenceMethod = "boot_completed"
	MethodForegroundService PersistenceMethod = "foreground_service"
	MethodDeviceAdmin      PersistenceMethod = "device_admin"
	MethodAndroidAccessibility PersistenceMethod = "android_accessibility"
)

type PersistenceConfig struct {
	Platform    types.Platform  `json:"platform"`
	AgentPath   string          `json:"agent_path"`
	AgentArgs   string          `json:"agent_args"`
	MethodName  string          `json:"method_name"`
	Priority    int             `json:"priority"`
	Stealth     bool            `json:"stealth"`
	Timeout     time.Duration   `json:"timeout"`
	RetryCount  int             `json:"retry_count"`
	RetryDelay  time.Duration   `json:"retry_delay"`
	Metadata    map[string]string `json:"metadata"`
}

func DefaultPersistenceConfig() *PersistenceConfig {
	return &PersistenceConfig{
		Platform:   types.PlatformWindows,
		AgentPath:  "/tmp/agent",
		Priority:   1,
		Stealth:    false,
		Timeout:    30 * time.Second,
		RetryCount: 3,
		RetryDelay: 5 * time.Second,
		Metadata:   make(map[string]string),
	}
}

type PersistenceParams struct {
	Method      PersistenceMethod `json:"method"`
	AgentPath   string            `json:"agent_path"`
	AgentArgs   string            `json:"agent_args"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Extra       map[string]string `json:"extra"`
}

type PersistenceResult struct {
	Success     bool                `json:"success"`
	Method      PersistenceMethod   `json:"method"`
	InstalledAt time.Time           `json:"installed_at"`
	Details     map[string]string   `json:"details"`
	Error       string              `json:"error"`
	TaskID      string              `json:"task_id"`
}

type PersistenceMethodInterface interface {
	Install(params *PersistenceParams) (*PersistenceResult, error)
	Remove(params *PersistenceParams) error
	Verify(params *PersistenceParams) (bool, error)
	Name() string
	Platform() types.Platform
	RequiresElevation() bool
}

type WatchdogEvent struct {
	Type      string              `json:"type"`
	Method    PersistenceMethod   `json:"method"`
	Status    string              `json:"status"`
	Timestamp time.Time           `json:"timestamp"`
	Details   map[string]string   `json:"details"`
}

type WatchdogConfig struct {
	Interval      time.Duration     `json:"interval"`
	Methods       []PersistenceMethod `json:"methods"`
	AutoRepair    bool              `json:"auto_repair"`
	MaxRetries    int               `json:"max_retries"`
	OnFailure     func(event WatchdogEvent) `json:"-"`
	OnRepair      func(event WatchdogEvent) `json:"-"`
}

func DefaultWatchdogConfig() *WatchdogConfig {
	return &WatchdogConfig{
		Interval:   60 * time.Second,
		Methods:    []PersistenceMethod{},
		AutoRepair: true,
		MaxRetries: 3,
	}
}
