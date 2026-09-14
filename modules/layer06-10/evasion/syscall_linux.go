//go:build !windows

package evasion

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

var errNotSupported = errors.New("library loading not supported on this platform")

func loadLibraryImpl(name string) (uintptr, error) {
	return 0, fmt.Errorf("%w: %s", errNotSupported, name)
}

func getProcAddressImpl(handle uintptr, name string) (uintptr, error) {
	_ = handle
	data, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return 0, fmt.Errorf("read maps: %w", err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "ntdll") || strings.Contains(line, name) {
			return 0, nil
		}
	}

	return 0, fmt.Errorf("symbol %s not found", name)
}
