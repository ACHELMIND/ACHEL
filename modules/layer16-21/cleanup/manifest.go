package cleanup

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

type ManifestGenerator struct {
	config *CleanupConfig
}

func NewManifestGenerator(config *CleanupConfig) *ManifestGenerator {
	return &ManifestGenerator{config: config}
}

func (mg *ManifestGenerator) GenerateManifest() (*Manifest, error) {
	manifest := &Manifest{
		ID:        types.GenerateID(),
		CreatedAt: time.Now().UTC(),
		Items:     make([]ManifestItem, 0),
	}

	dirs := []string{
		mg.config.ToolsDir,
		mg.config.LogsDir,
		mg.config.ConfigsDir,
		mg.config.BackupsDir,
	}

	for _, dir := range dirs {
		if dir == "" {
			continue
		}

		items, err := mg.scanDir(dir)
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", dir, err)
		}

		manifest.Items = append(manifest.Items, items...)
	}

	manifest.Hash = mg.computeManifestHash(manifest)

	return manifest, nil
}

func (mg *ManifestGenerator) VerifyManifest(manifest *Manifest) (bool, error) {
	expected := mg.computeManifestHash(manifest)
	return manifest.Hash == expected, nil
}

func (mg *ManifestGenerator) ExportManifest(manifest *Manifest, path string) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}

func (mg *ManifestGenerator) scanDir(dir string) ([]ManifestItem, error) {
	var items []ManifestItem

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		h := sha256.Sum256(data)
		items = append(items, ManifestItem{
			Path: path,
			Hash: fmt.Sprintf("%x", h),
			Size: info.Size(),
		})

		return nil
	})

	return items, err
}

func (mg *ManifestGenerator) computeManifestHash(m *Manifest) string {
	data := fmt.Sprintf("%s%d", m.ID, m.CreatedAt.UnixNano())
	for _, item := range m.Items {
		data += fmt.Sprintf("%s%s%d", item.Path, item.Hash, item.Size)
	}
	h := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", h)
}
