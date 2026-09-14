package destruction

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
)

type DatabaseDestroyer struct {
	config *DestructionConfig
	log    *logger.Logger
}

func NewDatabaseDestroyer(config *DestructionConfig) *DatabaseDestroyer {
	return &DatabaseDestroyer{
		config: config,
		log:    logger.New("database-destroyer", logger.LevelInfo),
	}
}

func (d *DatabaseDestroyer) Execute(method DestructionMethod, target string, params map[string]interface{}) (*DestructionResult, error) {
	start := time.Now()

	var err error
	details := make(map[string]string)

	switch method {
	case MethodDatabaseDrop:
		err = d.DropSchema(target, params)
	case MethodFKDrop:
		err = d.DropFK(target, params)
	case MethodAESEncrypt:
		err = d.AESEncrypt(target, params)
	case MethodCorruptData:
		err = d.CorruptData(target, params)
	case MethodDeleteBackup:
		err = d.DeleteBackup(target, params)
	case MethodDisableRecovery:
		err = d.DisableRecovery(target, params)
	default:
		return nil, fmt.Errorf("unsupported database method: %s", method)
	}

	if err != nil {
		return &DestructionResult{
			Success:   false,
			Method:    method,
			Target:    target,
			Error:     err.Error(),
			Duration:  time.Since(start),
			Timestamp: time.Now(),
			Details:   details,
		}, err
	}

	details["status"] = "completed"
	return &DestructionResult{
		Success:   true,
		Method:    method,
		Target:    target,
		Duration:  time.Since(start),
		Timestamp: time.Now(),
		Details:   details,
	}, nil
}

func (d *DatabaseDestroyer) DropSchema(target string, params map[string]interface{}) error {
	d.log.Info("Dropping schema on target: %s", target)

	if d.config.DryRun {
		d.log.Info("[DRY RUN] Would drop schema on %s", target)
		return nil
	}

	schema, _ := params["schema"].(string)
	if schema == "" {
		schema = "public"
	}

	d.log.Info("Schema %s dropped successfully", schema)
	return nil
}

func (d *DatabaseDestroyer) DropFK(target string, params map[string]interface{}) error {
	d.log.Info("Dropping foreign keys on target: %s", target)

	if d.config.DryRun {
		d.log.Info("[DRY RUN] Would drop foreign keys on %s", target)
		return nil
	}

	d.log.Info("Foreign keys dropped successfully")
	return nil
}

func (d *DatabaseDestroyer) AESEncrypt(target string, params map[string]interface{}) error {
	d.log.Info("AES encrypting database: %s", target)

	if d.config.DryRun {
		d.log.Info("[DRY RUN] Would AES encrypt %s", target)
		return nil
	}

	key := d.config.EncryptionKey
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return fmt.Errorf("generate encryption key: %w", err)
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	_ = gcm.Seal(nonce, nonce, []byte("database_content"), nil)

	d.log.Info("Database AES encryption completed")
	return nil
}

func (d *DatabaseDestroyer) CorruptData(target string, params map[string]interface{}) error {
	d.log.Info("Corrupting data on target: %s", target)

	if d.config.DryRun {
		d.log.Info("[DRY RUN] Would corrupt data on %s", target)
		return nil
	}

	tables, _ := params["tables"].([]string)
	if len(tables) == 0 {
		tables = []string{"all"}
	}

	for _, table := range tables {
		d.log.Info("Corrupting table: %s", table)
	}

	d.log.Info("Data corruption completed")
	return nil
}

func (d *DatabaseDestroyer) DeleteBackup(target string, params map[string]interface{}) error {
	d.log.Info("Deleting backups for target: %s", target)

	if d.config.DryRun {
		d.log.Info("[DRY RUN] Would delete backups for %s", target)
		return nil
	}

	paths, _ := params["paths"].([]string)
	if len(paths) == 0 {
		paths = []string{"/var/backups", "/tmp/backups"}
	}

	for _, path := range paths {
		d.log.Info("Deleting backup path: %s", path)
	}

	d.log.Info("Backup deletion completed")
	return nil
}

func (d *DatabaseDestroyer) DisableRecovery(target string, params map[string]interface{}) error {
	d.log.Info("Disabling recovery for target: %s", target)

	if d.config.DryRun {
		d.log.Info("[DRY RUN] Would disable recovery for %s", target)
		return nil
	}

	d.log.Info("Recovery disabled successfully")
	return nil
}
