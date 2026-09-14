package cleanup

import (
	"fmt"
	"time"
)

type CleanupEngine struct {
	config     *CleanupConfig
	credClean  *CredentialCleanup
	artClean   *ArtifactCleanup
	dbClean    *DatabaseCleanup
}

func NewCleanupEngine(config *CleanupConfig) *CleanupEngine {
	return &CleanupEngine{
		config:    config,
		credClean: NewCredentialCleanup(config),
		artClean:  NewArtifactCleanup(config),
		dbClean:   NewDatabaseCleanup(config),
	}
}

func (ce *CleanupEngine) FullCleanup() (*CleanupResult, error) {
	start := time.Now()
	result := &CleanupResult{
		CleanedItems: make([]string, 0),
		FailedItems:  make([]string, 0),
	}

	if err := ce.credClean.RevokeTempCredentials(); err != nil {
		result.FailedItems = append(result.FailedItems, fmt.Sprintf("revoke-creds: %v", err))
	} else {
		result.CleanedItems = append(result.CleanedItems, "revoke-creds")
	}

	if err := ce.credClean.RotateTokens(); err != nil {
		result.FailedItems = append(result.FailedItems, fmt.Sprintf("rotate-tokens: %v", err))
	} else {
		result.CleanedItems = append(result.CleanedItems, "rotate-tokens")
	}

	if err := ce.credClean.DeleteSSHKeys(); err != nil {
		result.FailedItems = append(result.FailedItems, fmt.Sprintf("delete-ssh-keys: %v", err))
	} else {
		result.CleanedItems = append(result.CleanedItems, "delete-ssh-keys")
	}

	if err := ce.artClean.DeleteTools(); err != nil {
		result.FailedItems = append(result.FailedItems, fmt.Sprintf("delete-tools: %v", err))
	} else {
		result.CleanedItems = append(result.CleanedItems, "delete-tools")
	}

	if err := ce.artClean.DeleteLogs(); err != nil {
		result.FailedItems = append(result.FailedItems, fmt.Sprintf("delete-logs: %v", err))
	} else {
		result.CleanedItems = append(result.CleanedItems, "delete-logs")
	}

	if err := ce.artClean.DeleteConfigs(); err != nil {
		result.FailedItems = append(result.FailedItems, fmt.Sprintf("delete-configs: %v", err))
	} else {
		result.CleanedItems = append(result.CleanedItems, "delete-configs")
	}

	if err := ce.artClean.DeleteBackups(); err != nil {
		result.FailedItems = append(result.FailedItems, fmt.Sprintf("delete-backups: %v", err))
	} else {
		result.CleanedItems = append(result.CleanedItems, "delete-backups")
	}

	if err := ce.dbClean.DeleteJavaObjects(); err != nil {
		result.FailedItems = append(result.FailedItems, fmt.Sprintf("delete-java-objects: %v", err))
	} else {
		result.CleanedItems = append(result.CleanedItems, "delete-java-objects")
	}

	if err := ce.dbClean.DeleteStoredProcs(); err != nil {
		result.FailedItems = append(result.FailedItems, fmt.Sprintf("delete-stored-procs: %v", err))
	} else {
		result.CleanedItems = append(result.CleanedItems, "delete-stored-procs")
	}

	if err := ce.dbClean.DeleteAdminAccounts(); err != nil {
		result.FailedItems = append(result.FailedItems, fmt.Sprintf("delete-admin-accounts: %v", err))
	} else {
		result.CleanedItems = append(result.CleanedItems, "delete-admin-accounts")
	}

	if err := ce.dbClean.RevertChanges(); err != nil {
		result.FailedItems = append(result.FailedItems, fmt.Sprintf("revert-changes: %v", err))
	} else {
		result.CleanedItems = append(result.CleanedItems, "revert-changes")
	}

	result.Duration = time.Since(start)
	result.Timestamp = time.Now().UTC()
	result.Success = len(result.FailedItems) == 0

	return result, nil
}

func (ce *CleanupEngine) PartialCleanup(categories []string) (*CleanupResult, error) {
	start := time.Now()
	result := &CleanupResult{
		CleanedItems: make([]string, 0),
		FailedItems:  make([]string, 0),
	}

	for _, cat := range categories {
		switch cat {
		case "credentials":
			if err := ce.credClean.RevokeTempCredentials(); err != nil {
				result.FailedItems = append(result.FailedItems, fmt.Sprintf("revoke-creds: %v", err))
			} else {
				result.CleanedItems = append(result.CleanedItems, "revoke-creds")
			}
		case "tokens":
			if err := ce.credClean.RotateTokens(); err != nil {
				result.FailedItems = append(result.FailedItems, fmt.Sprintf("rotate-tokens: %v", err))
			} else {
				result.CleanedItems = append(result.CleanedItems, "rotate-tokens")
			}
		case "ssh_keys":
			if err := ce.credClean.DeleteSSHKeys(); err != nil {
				result.FailedItems = append(result.FailedItems, fmt.Sprintf("delete-ssh-keys: %v", err))
			} else {
				result.CleanedItems = append(result.CleanedItems, "delete-ssh-keys")
			}
		case "tools":
			if err := ce.artClean.DeleteTools(); err != nil {
				result.FailedItems = append(result.FailedItems, fmt.Sprintf("delete-tools: %v", err))
			} else {
				result.CleanedItems = append(result.CleanedItems, "delete-tools")
			}
		case "logs":
			if err := ce.artClean.DeleteLogs(); err != nil {
				result.FailedItems = append(result.FailedItems, fmt.Sprintf("delete-logs: %v", err))
			} else {
				result.CleanedItems = append(result.CleanedItems, "delete-logs")
			}
		case "configs":
			if err := ce.artClean.DeleteConfigs(); err != nil {
				result.FailedItems = append(result.FailedItems, fmt.Sprintf("delete-configs: %v", err))
			} else {
				result.CleanedItems = append(result.CleanedItems, "delete-configs")
			}
		case "backups":
			if err := ce.artClean.DeleteBackups(); err != nil {
				result.FailedItems = append(result.FailedItems, fmt.Sprintf("delete-backups: %v", err))
			} else {
				result.CleanedItems = append(result.CleanedItems, "delete-backups")
			}
		case "database":
			if err := ce.dbClean.DeleteJavaObjects(); err != nil {
				result.FailedItems = append(result.FailedItems, fmt.Sprintf("delete-java-objects: %v", err))
			} else {
				result.CleanedItems = append(result.CleanedItems, "delete-java-objects")
			}
			if err := ce.dbClean.DeleteStoredProcs(); err != nil {
				result.FailedItems = append(result.FailedItems, fmt.Sprintf("delete-stored-procs: %v", err))
			} else {
				result.CleanedItems = append(result.CleanedItems, "delete-stored-procs")
			}
		case "admin_accounts":
			if err := ce.dbClean.DeleteAdminAccounts(); err != nil {
				result.FailedItems = append(result.FailedItems, fmt.Sprintf("delete-admin-accounts: %v", err))
			} else {
				result.CleanedItems = append(result.CleanedItems, "delete-admin-accounts")
			}
		case "revert":
			if err := ce.dbClean.RevertChanges(); err != nil {
				result.FailedItems = append(result.FailedItems, fmt.Sprintf("revert-changes: %v", err))
			} else {
				result.CleanedItems = append(result.CleanedItems, "revert-changes")
			}
		default:
			result.FailedItems = append(result.FailedItems, fmt.Sprintf("unknown category: %s", cat))
		}
	}

	result.Duration = time.Since(start)
	result.Timestamp = time.Now().UTC()
	result.Success = len(result.FailedItems) == 0

	return result, nil
}

func (ce *CleanupEngine) VerifyClean() (*CleanupVerification, error) {
	v := &CleanupVerification{
		IsClean:   true,
		Remaining: make([]string, 0),
		Verified:  make([]string, 0),
		Timestamp: time.Now().UTC(),
	}

	checks := []string{"tools", "logs", "configs", "backups", "credentials", "database"}

	for _, check := range checks {
		clean, err := ce.verifyCategory(check)
		if err != nil {
			v.Remaining = append(v.Remaining, fmt.Sprintf("%s: %v", check, err))
			v.IsClean = false
		} else if clean {
			v.Verified = append(v.Verified, check)
		}
	}

	return v, nil
}

func (ce *CleanupEngine) verifyCategory(category string) (bool, error) {
	switch category {
	case "tools":
		return ce.artClean.verifyToolsClean()
	case "logs":
		return ce.artClean.verifyLogsClean()
	case "configs":
		return ce.artClean.verifyConfigsClean()
	case "backups":
		return ce.artClean.verifyBackupsClean()
	case "credentials":
		return ce.credClean.verifyCredentialsClean()
	case "database":
		return ce.dbClean.verifyDatabaseClean()
	default:
		return false, fmt.Errorf("unknown category: %s", category)
	}
}
