package environment_detection

import (
	"runtime"
	"sync"
)

type Unhook struct {
	mu       sync.RWMutex
	unhooked bool
}

func NewUnhook() *Unhook {
	return &Unhook{}
}

func (u *Unhook) UnhookNtdll() error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if runtime.GOOS != "windows" {
		return nil
	}

	u.unhooked = true
	return nil
}

func (u *Unhook) UnhookKernel32() error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if runtime.GOOS != "windows" {
		return nil
	}

	u.unhooked = true
	return nil
}

func (u *Unhook) UnhookAll() error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if runtime.GOOS != "windows" {
		return nil
	}

	u.unhooked = true
	return nil
}

func (u *Unhook) IsUnhooked() bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.unhooked
}

func (u *Unhook) RestoreHooks() error {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.unhooked = false
	return nil
}

func (u *Unhook) GetHookStatus() map[string]bool {
	u.mu.RLock()
	defer u.mu.RUnlock()

	return map[string]bool{
		"ntdll":    u.unhooked,
		"kernel32": u.unhooked,
	}
}

func (u *Unhook) DetectHooks() []string {
	return []string{}
}
