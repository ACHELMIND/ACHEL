package cleanup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialCleanupRevoke(t *testing.T) {
	dir := t.TempDir()

	// Create dummy credential files
	os.WriteFile(filepath.Join(dir, "credentials.json"), []byte("test"), 0600)
	os.WriteFile(filepath.Join(dir, ".credentials"), []byte("test"), 0600)
	os.WriteFile(filepath.Join(dir, "creds.tmp"), []byte("test"), 0600)

	config := &CleanupConfig{BasePath: dir}
	cc := NewCredentialCleanup(config)

	if err := cc.RevokeTempCredentials(); err != nil {
		t.Fatalf("RevokeTempCredentials failed: %v", err)
	}

	for _, f := range []string{"credentials.json", ".credentials", "creds.tmp"} {
		if _, err := os.Stat(filepath.Join(dir, f)); !os.IsNotExist(err) {
			t.Errorf("Expected %s to be deleted", f)
		}
	}
}

func TestCredentialCleanupRotateTokens(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, ".tokens"), []byte("test"), 0600)
	os.WriteFile(filepath.Join(dir, "token.json"), []byte("test"), 0600)
	os.WriteFile(filepath.Join(dir, "session.token"), []byte("test"), 0600)

	config := &CleanupConfig{BasePath: dir}
	cc := NewCredentialCleanup(config)

	if err := cc.RotateTokens(); err != nil {
		t.Fatalf("RotateTokens failed: %v", err)
	}

	for _, f := range []string{".tokens", "token.json", "session.token"} {
		if _, err := os.Stat(filepath.Join(dir, f)); !os.IsNotExist(err) {
			t.Errorf("Expected %s to be deleted", f)
		}
	}
}

func TestCredentialCleanupDeleteSSHKeys(t *testing.T) {
	dir := t.TempDir()

	sshDir := filepath.Join(dir, ".ssh")
	os.MkdirAll(sshDir, 0700)
	os.WriteFile(filepath.Join(sshDir, "id_rsa"), []byte("key"), 0600)
	os.WriteFile(filepath.Join(sshDir, "id_rsa.pub"), []byte("pub"), 0600)
	os.WriteFile(filepath.Join(dir, "ssh_key"), []byte("key"), 0600)

	config := &CleanupConfig{BasePath: dir}
	cc := NewCredentialCleanup(config)

	if err := cc.DeleteSSHKeys(); err != nil {
		t.Fatalf("DeleteSSHKeys failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "ssh_key")); !os.IsNotExist(err) {
		t.Error("Expected ssh_key to be deleted")
	}
}

func TestArtifactCleanupDeleteTools(t *testing.T) {
	dir := t.TempDir()
	toolsDir := filepath.Join(dir, "tools")
	os.MkdirAll(toolsDir, 0700)
	os.WriteFile(filepath.Join(toolsDir, "tool1"), []byte("data"), 0600)
	os.WriteFile(filepath.Join(toolsDir, "tool2"), []byte("data"), 0600)

	config := &CleanupConfig{ToolsDir: toolsDir}
	ac := NewArtifactCleanup(config)

	if err := ac.DeleteTools(); err != nil {
		t.Fatalf("DeleteTools failed: %v", err)
	}

	entries, _ := os.ReadDir(toolsDir)
	if len(entries) != 0 {
		t.Errorf("Expected tools dir to be empty, got %d entries", len(entries))
	}
}

func TestArtifactCleanupDeleteLogs(t *testing.T) {
	dir := t.TempDir()
	logsDir := filepath.Join(dir, "logs")
	os.MkdirAll(logsDir, 0700)
	os.WriteFile(filepath.Join(logsDir, "app.log"), []byte("data"), 0600)

	config := &CleanupConfig{LogsDir: logsDir}
	ac := NewArtifactCleanup(config)

	if err := ac.DeleteLogs(); err != nil {
		t.Fatalf("DeleteLogs failed: %v", err)
	}

	entries, _ := os.ReadDir(logsDir)
	if len(entries) != 0 {
		t.Errorf("Expected logs dir to be empty, got %d entries", len(entries))
	}
}

func TestArtifactCleanupDeleteConfigs(t *testing.T) {
	dir := t.TempDir()
	configsDir := filepath.Join(dir, "configs")
	os.MkdirAll(configsDir, 0700)
	os.WriteFile(filepath.Join(configsDir, "config.json"), []byte("data"), 0600)

	config := &CleanupConfig{ConfigsDir: configsDir}
	ac := NewArtifactCleanup(config)

	if err := ac.DeleteConfigs(); err != nil {
		t.Fatalf("DeleteConfigs failed: %v", err)
	}

	entries, _ := os.ReadDir(configsDir)
	if len(entries) != 0 {
		t.Errorf("Expected configs dir to be empty, got %d entries", len(entries))
	}
}

func TestArtifactCleanupDeleteBackups(t *testing.T) {
	dir := t.TempDir()
	backupsDir := filepath.Join(dir, "backups")
	os.MkdirAll(backupsDir, 0700)
	os.WriteFile(filepath.Join(backupsDir, "backup.tar.gz"), []byte("data"), 0600)

	config := &CleanupConfig{BackupsDir: backupsDir}
	ac := NewArtifactCleanup(config)

	if err := ac.DeleteBackups(); err != nil {
		t.Fatalf("DeleteBackups failed: %v", err)
	}

	entries, _ := os.ReadDir(backupsDir)
	if len(entries) != 0 {
		t.Errorf("Expected backups dir to be empty, got %d entries", len(entries))
	}
}

func TestEngineFullCleanup(t *testing.T) {
	dir := t.TempDir()

	toolsDir := filepath.Join(dir, "tools")
	logsDir := filepath.Join(dir, "logs")
	configsDir := filepath.Join(dir, "configs")
	backupsDir := filepath.Join(dir, "backups")

	os.MkdirAll(toolsDir, 0700)
	os.MkdirAll(logsDir, 0700)
	os.MkdirAll(configsDir, 0700)
	os.MkdirAll(backupsDir, 0700)

	os.WriteFile(filepath.Join(toolsDir, "tool1"), []byte("data"), 0600)
	os.WriteFile(filepath.Join(logsDir, "app.log"), []byte("data"), 0600)
	os.WriteFile(filepath.Join(configsDir, "config.json"), []byte("data"), 0600)
	os.WriteFile(filepath.Join(backupsDir, "backup.tar.gz"), []byte("data"), 0600)
	os.WriteFile(filepath.Join(dir, "credentials.json"), []byte("creds"), 0600)
	os.WriteFile(filepath.Join(dir, "token.json"), []byte("token"), 0600)

	config := &CleanupConfig{
		BasePath:   dir,
		ToolsDir:   toolsDir,
		LogsDir:    logsDir,
		ConfigsDir: configsDir,
		BackupsDir: backupsDir,
	}

	engine := NewCleanupEngine(config)

	result, err := engine.FullCleanup()
	if err != nil {
		t.Fatalf("FullCleanup failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success, got failures: %v", result.FailedItems)
	}
}

func TestEnginePartialCleanup(t *testing.T) {
	dir := t.TempDir()

	toolsDir := filepath.Join(dir, "tools")
	logsDir := filepath.Join(dir, "logs")
	os.MkdirAll(toolsDir, 0700)
	os.MkdirAll(logsDir, 0700)
	os.WriteFile(filepath.Join(toolsDir, "tool1"), []byte("data"), 0600)
	os.WriteFile(filepath.Join(logsDir, "app.log"), []byte("data"), 0600)

	config := &CleanupConfig{
		BasePath: dir,
		ToolsDir: toolsDir,
		LogsDir:  logsDir,
	}

	engine := NewCleanupEngine(config)

	result, err := engine.PartialCleanup([]string{"tools"})
	if err != nil {
		t.Fatalf("PartialCleanup failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success, got failures: %v", result.FailedItems)
	}

	entries, _ := os.ReadDir(toolsDir)
	if len(entries) != 0 {
		t.Error("Expected tools to be cleaned")
	}

	entries, _ = os.ReadDir(logsDir)
	if len(entries) != 1 {
		t.Error("Expected logs to remain")
	}
}

func TestEngineVerifyClean(t *testing.T) {
	dir := t.TempDir()

	config := &CleanupConfig{
		BasePath: dir,
		ToolsDir: filepath.Join(dir, "tools"),
		LogsDir:  filepath.Join(dir, "logs"),
	}

	engine := NewCleanupEngine(config)

	v, err := engine.VerifyClean()
	if err != nil {
		t.Fatalf("VerifyClean failed: %v", err)
	}

	if !v.IsClean {
		t.Errorf("Expected clean, got remaining: %v", v.Remaining)
	}
}

func TestManifestGenerateAndVerify(t *testing.T) {
	dir := t.TempDir()
	toolsDir := filepath.Join(dir, "tools")
	os.MkdirAll(toolsDir, 0700)
	os.WriteFile(filepath.Join(toolsDir, "tool1"), []byte("data"), 0600)

	config := &CleanupConfig{ToolsDir: toolsDir}
	mg := NewManifestGenerator(config)

	manifest, err := mg.GenerateManifest()
	if err != nil {
		t.Fatalf("GenerateManifest failed: %v", err)
	}

	if len(manifest.Items) != 1 {
		t.Errorf("Expected 1 item, got %d", len(manifest.Items))
	}

	valid, err := mg.VerifyManifest(manifest)
	if err != nil {
		t.Fatalf("VerifyManifest failed: %v", err)
	}

	if !valid {
		t.Error("Expected manifest to be valid")
	}
}

func TestManifestExport(t *testing.T) {
	dir := t.TempDir()

	config := &CleanupConfig{}
	mg := NewManifestGenerator(config)

	manifest := &Manifest{
		ID: "test-manifest",
		Items: []ManifestItem{
			{Path: "/test/file", Hash: "abc", Size: 100},
		},
	}

	exportPath := filepath.Join(dir, "manifest.json")
	if err := mg.ExportManifest(manifest, exportPath); err != nil {
		t.Fatalf("ExportManifest failed: %v", err)
	}

	if _, err := os.Stat(exportPath); os.IsNotExist(err) {
		t.Error("Expected manifest file to exist")
	}
}

func TestCredentialCleanupVerifyClean(t *testing.T) {
	dir := t.TempDir()

	config := &CleanupConfig{BasePath: dir}
	cc := NewCredentialCleanup(config)

	clean, err := cc.verifyCredentialsClean()
	if err != nil {
		t.Fatalf("verifyCredentialsClean failed: %v", err)
	}

	if !clean {
		t.Error("Expected credentials to be clean")
	}
}

func TestArtifactCleanupVerifyClean(t *testing.T) {
	dir := t.TempDir()

	config := &CleanupConfig{
		ToolsDir: filepath.Join(dir, "tools"),
		LogsDir:  filepath.Join(dir, "logs"),
	}

	ac := NewArtifactCleanup(config)

	clean, err := ac.verifyToolsClean()
	if err != nil {
		t.Fatalf("verifyToolsClean failed: %v", err)
	}

	if !clean {
		t.Error("Expected tools to be clean")
	}
}

func TestEnginePartialCleanupUnknownCategory(t *testing.T) {
	dir := t.TempDir()

	config := &CleanupConfig{BasePath: dir}
	engine := NewCleanupEngine(config)

	result, err := engine.PartialCleanup([]string{"nonexistent"})
	if err != nil {
		t.Fatalf("PartialCleanup failed: %v", err)
	}

	if result.Success {
		t.Error("Expected failure for unknown category")
	}
}

func TestEnginePartialCleanupDatabase(t *testing.T) {
	dir := t.TempDir()
	dbDir := filepath.Join(dir, "db")
	os.MkdirAll(dbDir, 0700)
	os.WriteFile(filepath.Join(dbDir, "test.ser"), []byte("data"), 0600)

	config := &CleanupConfig{
		BasePath: dir,
		DBPath:   dbDir,
	}

	engine := NewCleanupEngine(config)

	result, err := engine.PartialCleanup([]string{"database"})
	if err != nil {
		t.Fatalf("PartialCleanup failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success, got failures: %v", result.FailedItems)
	}
}

func TestEnginePartialCleanupAdminAccounts(t *testing.T) {
	dir := t.TempDir()
	dbDir := filepath.Join(dir, "db")
	os.MkdirAll(dbDir, 0700)
	os.WriteFile(filepath.Join(dbDir, "admin_accounts.json"), []byte("data"), 0600)

	config := &CleanupConfig{
		BasePath: dir,
		DBPath:   dbDir,
	}

	engine := NewCleanupEngine(config)

	result, err := engine.PartialCleanup([]string{"admin_accounts"})
	if err != nil {
		t.Fatalf("PartialCleanup failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success, got failures: %v", result.FailedItems)
	}

	if _, err := os.Stat(filepath.Join(dbDir, "admin_accounts.json")); !os.IsNotExist(err) {
		t.Error("Expected admin_accounts.json to be deleted")
	}
}

func TestEnginePartialCleanupRevert(t *testing.T) {
	dir := t.TempDir()
	dbDir := filepath.Join(dir, "db")
	changesDir := filepath.Join(dbDir, "changes")
	os.MkdirAll(changesDir, 0700)
	os.WriteFile(filepath.Join(changesDir, "change1.sql"), []byte("data"), 0600)

	config := &CleanupConfig{
		BasePath: dir,
		DBPath:   dbDir,
	}

	engine := NewCleanupEngine(config)

	result, err := engine.PartialCleanup([]string{"revert"})
	if err != nil {
		t.Fatalf("PartialCleanup failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success, got failures: %v", result.FailedItems)
	}
}

func TestDatabaseCleanupDeleteJavaObjects(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "obj.ser"), []byte("data"), 0600)
	os.WriteFile(filepath.Join(dir, "Main.class"), []byte("data"), 0600)
	os.WriteFile(filepath.Join(dir, "lib.jar"), []byte("data"), 0600)

	config := &CleanupConfig{DBPath: dir}
	dc := NewDatabaseCleanup(config)

	if err := dc.DeleteJavaObjects(); err != nil {
		t.Fatalf("DeleteJavaObjects failed: %v", err)
	}

	for _, f := range []string{"obj.ser", "Main.class", "lib.jar"} {
		if _, err := os.Stat(filepath.Join(dir, f)); !os.IsNotExist(err) {
			t.Errorf("Expected %s to be deleted", f)
		}
	}
}

func TestDatabaseCleanupDeleteStoredProcs(t *testing.T) {
	dir := t.TempDir()
	spDir := filepath.Join(dir, "stored_procs")
	os.MkdirAll(spDir, 0700)
	os.WriteFile(filepath.Join(spDir, "sp1.sql"), []byte("data"), 0600)

	config := &CleanupConfig{DBPath: dir}
	dc := NewDatabaseCleanup(config)

	if err := dc.DeleteStoredProcs(); err != nil {
		t.Fatalf("DeleteStoredProcs failed: %v", err)
	}

	if _, err := os.Stat(spDir); !os.IsNotExist(err) {
		t.Error("Expected stored_procs directory to be deleted")
	}
}

func TestDatabaseCleanupRevertChanges(t *testing.T) {
	dir := t.TempDir()
	changesDir := filepath.Join(dir, "changes")
	os.MkdirAll(changesDir, 0700)
	os.WriteFile(filepath.Join(changesDir, "change1.sql"), []byte("data"), 0600)

	config := &CleanupConfig{DBPath: dir}
	dc := NewDatabaseCleanup(config)

	if err := dc.RevertChanges(); err != nil {
		t.Fatalf("RevertChanges failed: %v", err)
	}

	entries, _ := os.ReadDir(changesDir)
	if len(entries) != 0 {
		t.Error("Expected changes dir to be empty")
	}
}
