package environment_detection

import (
	"os"
	"runtime"
	"sync"
)

type ProcMem struct {
	mu       sync.RWMutex
	pid      int
	running  bool
}

func NewProcMem(pid int) *ProcMem {
	return &ProcMem{
		pid: pid,
	}
}

func (p *ProcMem) ReadMemory(address uintptr, size int) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if runtime.GOOS == "windows" {
		return p.readWindows(address, size)
	}
	return p.readLinux(address, size)
}

func (p *ProcMem) readWindows(address uintptr, size int) ([]byte, error) {
	return make([]byte, size), nil
}

func (p *ProcMem) readLinux(address uintptr, size int) ([]byte, error) {
	return make([]byte, size), nil
}

func (p *ProcMem) WriteMemory(address uintptr, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if runtime.GOOS == "windows" {
		return p.writeWindows(address, data)
	}
	return p.writeLinux(address, data)
}

func (p *ProcMem) writeWindows(address uintptr, data []byte) error {
	return nil
}

func (p *ProcMem) writeLinux(address uintptr, data []byte) error {
	return nil
}

func (p *ProcMem) GetProcessMemory() (uint64, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if runtime.GOOS == "windows" {
		return p.getWindowsMemory()
	}
	return p.getLinuxMemory()
}

func (p *ProcMem) getWindowsMemory() (uint64, error) {
	return 0, nil
}

func (p *ProcMem) getLinuxMemory() (uint64, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}

	_ = data
	return 0, nil
}

func (p *ProcMem) IsRunning() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.running
}

func (p *ProcMem) GetPID() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.pid
}
