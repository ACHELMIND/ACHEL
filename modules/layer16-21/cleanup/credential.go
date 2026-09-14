package cleanup

import (
	"fmt"
	"os"
	"path/filepath"
)

type CredentialCleanup struct {
	config *CleanupConfig
}

func NewCredentialCleanup(config *CleanupConfig) *CredentialCleanup {
	return &CredentialCleanup{config: config}
}

func (cc *CredentialCleanup) RevokeTempCredentials() error {
	credPaths := []string{
		filepath.Join(cc.config.BasePath, ".credentials"),
		filepath.Join(cc.config.BasePath, "credentials.json"),
		filepath.Join(cc.config.BasePath, "creds.tmp"),
	}

	for _, p := range credPaths {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}

	return nil
}

func (cc *CredentialCleanup) RotateTokens() error {
	tokenPaths := []string{
		filepath.Join(cc.config.BasePath, ".tokens"),
		filepath.Join(cc.config.BasePath, "token.json"),
		filepath.Join(cc.config.BasePath, "session.token"),
		filepath.Join(cc.config.BasePath, ".access_token"),
	}

	for _, p := range tokenPaths {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}

	return nil
}

func (cc *CredentialCleanup) DeleteSSHKeys() error {
	keyPaths := []string{
		filepath.Join(cc.config.BasePath, ".ssh", "id_rsa"),
		filepath.Join(cc.config.BasePath, ".ssh", "id_rsa.pub"),
		filepath.Join(cc.config.BasePath, ".ssh", "authorized_keys"),
		filepath.Join(cc.config.BasePath, "ssh_key"),
	}

	for _, p := range keyPaths {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}

	return nil
}

func (cc *CredentialCleanup) verifyCredentialsClean() (bool, error) {
	checkPaths := []string{
		filepath.Join(cc.config.BasePath, ".credentials"),
		filepath.Join(cc.config.BasePath, "credentials.json"),
		filepath.Join(cc.config.BasePath, "creds.tmp"),
		filepath.Join(cc.config.BasePath, ".tokens"),
		filepath.Join(cc.config.BasePath, "token.json"),
		filepath.Join(cc.config.BasePath, "session.token"),
		filepath.Join(cc.config.BasePath, "ssh_key"),
	}

	for _, p := range checkPaths {
		if _, err := os.Stat(p); err == nil {
			return false, nil
		}
	}

	return true, nil
}
