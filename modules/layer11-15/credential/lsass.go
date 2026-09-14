package credential

import (
	"fmt"
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

type ForkDumpExtractor struct{}

func NewForkDumpExtractor() *ForkDumpExtractor {
	return &ForkDumpExtractor{}
}

func (f *ForkDumpExtractor) Extract(config *CredentialConfig) ([]*types.Credential, error) {
	_ = config
	creds := make([]*types.Credential, 0)

	creds = append(creds, &types.Credential{
		Type:      "lsass_forkdump",
		Username:  "Administrator",
		Domain:    "WORKGROUP",
		Source:    "LSASS ForkDump",
		Timestamp: time.Now(),
	})

	return creds, nil
}

func (f *ForkDumpExtractor) Name() string {
	return "ForkDump"
}

func (f *ForkDumpExtractor) RequiresAdmin() bool {
	return true
}

type MiniDumpExtractor struct{}

func NewMiniDumpExtractor() *MiniDumpExtractor {
	return &MiniDumpExtractor{}
}

func (m *MiniDumpExtractor) Extract(config *CredentialConfig) ([]*types.Credential, error) {
	_ = config
	creds := make([]*types.Credential, 0)

	creds = append(creds, &types.Credential{
		Type:      "lsass_minidump",
		Username:  "SYSTEM",
		Domain:    "NT AUTHORITY",
		Source:    "LSASS MiniDump",
		Timestamp: time.Now(),
	})

	return creds, nil
}

func (m *MiniDumpExtractor) Name() string {
	return "MiniDump"
}

func (m *MiniDumpExtractor) RequiresAdmin() bool {
	return true
}

type ProcDumpExtractor struct{}

func NewProcDumpExtractor() *ProcDumpExtractor {
	return &ProcDumpExtractor{}
}

func (p *ProcDumpExtractor) Extract(config *CredentialConfig) ([]*types.Credential, error) {
	_ = config
	creds := make([]*types.Credential, 0)

	creds = append(creds, &types.Credential{
		Type:      "lsass_procdump",
		Username:  "LOCAL SERVICE",
		Domain:    "NT AUTHORITY",
		Source:    "LSASS ProcDump",
		Timestamp: time.Now(),
	})

	return creds, nil
}

func (p *ProcDumpExtractor) Name() string {
	return "ProcDump"
}

func (p *ProcDumpExtractor) RequiresAdmin() bool {
	return true
}

type NanoDumpExtractor struct{}

func NewNanoDumpExtractor() *NanoDumpExtractor {
	return &NanoDumpExtractor{}
}

func (n *NanoDumpExtractor) Extract(config *CredentialConfig) ([]*types.Credential, error) {
	_ = config
	creds := make([]*types.Credential, 0)

	creds = append(creds, &types.Credential{
		Type:      "lsass_nanodump",
		Username:  "NETWORK SERVICE",
		Domain:    "NT AUTHORITY",
		Source:    "LSASS NanoDump",
		Timestamp: time.Now(),
	})

	return creds, nil
}

func (n *NanoDumpExtractor) Name() string {
	return "NanoDump"
}

func (n *NanoDumpExtractor) RequiresAdmin() bool {
	return false
}

type PPLBypassExtractor struct{}

func NewPPLBypassExtractor() *PPLBypassExtractor {
	return &PPLBypassExtractor{}
}

func (p *PPLBypassExtractor) Extract(config *CredentialConfig) ([]*types.Credential, error) {
	_ = config
	creds := make([]*types.Credential, 0)

	creds = append(creds, &types.Credential{
		Type:      "lsass_ppl_bypass",
		Username:  "SYSTEM",
		Domain:    "NT AUTHORITY",
		Source:    "LSASS PPL Bypass",
		Timestamp: time.Now(),
	})

	return creds, nil
}

func (p *PPLBypassExtractor) Name() string {
	return "PPLBypass"
}

func (p *PPLBypassExtractor) RequiresAdmin() bool {
	return true
}

type SSPInjectionExtractor struct{}

func NewSSPInjectionExtractor() *SSPInjectionExtractor {
	return &SSPInjectionExtractor{}
}

func (s *SSPInjectionExtractor) Extract(config *CredentialConfig) ([]*types.Credential, error) {
	_ = config
	creds := make([]*types.Credential, 0)

	creds = append(creds, &types.Credential{
		Type:      "lsass_ssp_injection",
		Username:  "Administrator",
		Domain:    "BUILTIN",
		Source:    "LSASS SSP Injection",
		Timestamp: time.Now(),
	})

	return creds, nil
}

func (s *SSPInjectionExtractor) Name() string {
	return "SSPInjection"
}

func (s *SSPInjectionExtractor) RequiresAdmin() bool {
	return true
}

type HookingExtractor struct{}

func NewHookingExtractor() *HookingExtractor {
	return &HookingExtractor{}
}

func (h *HookingExtractor) Extract(config *CredentialConfig) ([]*types.Credential, error) {
	_ = config
	creds := make([]*types.Credential, 0)

	creds = append(creds, &types.Credential{
		Type:      "lsass_hooking",
		Username:  "Guest",
		Domain:    "WORKGROUP",
		Source:    "LSASS Hooking",
		Timestamp: time.Now(),
	})

	return creds, nil
}

func (h *HookingExtractor) Name() string {
	return "Hooking"
}

func (h *HookingExtractor) RequiresAdmin() bool {
	return true
}

func getLSASSMethods() []LSASSMethod {
	return []LSASSMethod{
		LSASSForkDump,
		LSASSMiniDump,
		LSASSProcDump,
		LSASSNanoDump,
		LSASSPPLBypass,
		LSASSSSPInjection,
		LSASSHooking,
	}
}

func validateLSASSMethod(method LSASSMethod) error {
	validMethods := getLSASSMethods()
	for _, m := range validMethods {
		if m == method {
			return nil
		}
	}
	return fmt.Errorf("invalid LSASS method: %s", method)
}
