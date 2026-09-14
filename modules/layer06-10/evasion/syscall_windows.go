//go:build windows

package evasion

import (
	"fmt"
	"syscall"
)

func loadLibraryImpl(name string) (uintptr, error) {
	handle, err := syscall.LoadLibrary(name)
	if err != nil {
		return 0, fmt.Errorf("load library %s: %w", name, err)
	}
	return uintptr(handle), nil
}

func getProcAddressImpl(handle uintptr, name string) (uintptr, error) {
	addr, err := syscall.GetProcAddress(syscall.Handle(handle), name)
	if err != nil {
		return 0, fmt.Errorf("get proc address %s: %w", name, err)
	}
	return addr, nil
}
