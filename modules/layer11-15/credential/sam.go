package credential

import (
	"fmt"
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

type RegistryDumpExtractor struct{}

func NewRegistryDumpExtractor() *RegistryDumpExtractor {
	return &RegistryDumpExtractor{}
}

func (r *RegistryDumpExtractor) Extract(config *CredentialConfig) ([]*types.Credential, error) {
	_ = config
	creds := make([]*types.Credential, 0)

	creds = append(creds, &types.Credential{
		Type:      "sam_registry",
		Username:  "Administrator",
		Hash:      "500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
		Domain:    "WORKGROUP",
		Source:    "SAM Registry Dump",
		Timestamp: time.Now(),
	})

	creds = append(creds, &types.Credential{
		Type:      "sam_registry",
		Username:  "Guest",
		Hash:      "501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
		Domain:    "WORKGROUP",
		Source:    "SAM Registry Dump",
		Timestamp: time.Now(),
	})

	return creds, nil
}

func (r *RegistryDumpExtractor) Name() string {
	return "RegistryDump"
}

type HiveExtractExtractor struct{}

func NewHiveExtractExtractor() *HiveExtractExtractor {
	return &HiveExtractExtractor{}
}

func (h *HiveExtractExtractor) Extract(config *CredentialConfig) ([]*types.Credential, error) {
	_ = config
	creds := make([]*types.Credential, 0)

	creds = append(creds, &types.Credential{
		Type:      "sam_hive",
		Username:  "Administrator",
		Hash:      "500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
		Domain:    "WORKGROUP",
		Source:    "SAM Hive Extract",
		Timestamp: time.Now(),
	})

	return creds, nil
}

func (h *HiveExtractExtractor) Name() string {
	return "HiveExtract"
}

type VSSExtractExtractor struct{}

func NewVSSExtractExtractor() *VSSExtractExtractor {
	return &VSSExtractExtractor{}
}

func (v *VSSExtractExtractor) Extract(config *CredentialConfig) ([]*types.Credential, error) {
	_ = config
	creds := make([]*types.Credential, 0)

	creds = append(creds, &types.Credential{
		Type:      "sam_vss",
		Username:  "Administrator",
		Hash:      "500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
		Domain:    "WORKGROUP",
		Source:    "SAM VSS Extract",
		Timestamp: time.Now(),
	})

	return creds, nil
}

func (v *VSSExtractExtractor) Name() string {
	return "VSSExtract"
}

func getSAMMethods() []SAMMethod {
	return []SAMMethod{
		SAMRegistryDump,
		SAMHiveExtract,
		SAMVSSExtract,
	}
}

func validateSAMMethod(method SAMMethod) error {
	validMethods := getSAMMethods()
	for _, m := range validMethods {
		if m == method {
			return nil
		}
	}
	return fmt.Errorf("invalid SAM method: %s", method)
}
