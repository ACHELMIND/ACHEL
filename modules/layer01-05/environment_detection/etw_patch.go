package environment_detection

import (
	"runtime"
	"sync"
)

type ETWPatch struct {
	mu       sync.RWMutex
	patched  bool
}

func NewETWPatch() *ETWPatch {
	return &ETWPatch{}
}

func (e *ETWPatch) Patch() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if runtime.GOOS != "windows" {
		return nil
	}

	e.patched = true
	return nil
}

func (e *ETWPatch) Restore() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.patched = false
	return nil
}

func (e *ETWPatch) IsPatched() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.patched
}

func (e *ETWPatch) GetETWProvider() uintptr {
	return 0
}

func (e *ETWPatch) DisableETW() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.patched = true
	return nil
}

func (e *ETWPatch) EnableETW() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.patched = false
	return nil
}

func (e *ETWPatch) GetETWStatus() map[string]bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return map[string]bool{
		"patched": e.patched,
	}
}

func (e *ETWPatch) DetectETW() bool {
	return false
}
