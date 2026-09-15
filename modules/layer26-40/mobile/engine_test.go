package mobile

import (
	"testing"
)

func TestKeychainDump(t *testing.T) {
	engine := NewEngine(MobileConfig{
		Platform: PlatformTypeIOS,
	})

	result := engine.KeychainDump()

	if result.Platform != PlatformTypeIOS {
		t.Errorf("Expected iOS platform, got %v", result.Platform)
	}
	if len(result.KeychainItems) == 0 {
		t.Error("Expected keychain items")
	}
	for _, item := range result.KeychainItems {
		if item.Service == "" {
			t.Error("Service should not be empty")
		}
	}
}

func TestSSLPinningBypass(t *testing.T) {
	engine := NewEngine(MobileConfig{Platform: PlatformTypeIOS})

	result := engine.SSLPinningBypass()

	if len(result.SSLCerts) == 0 {
		t.Error("Expected SSL cert info")
	}
	bypassableCount := 0
	for _, cert := range result.SSLCerts {
		if cert.Bypassable {
			bypassableCount++
		}
	}
	if bypassableCount == 0 {
		t.Error("Expected at least one bypassable cert")
	}
}

func TestSharedPreferencesExtract(t *testing.T) {
	engine := NewEngine(MobileConfig{Platform: PlatformTypeAndroid})

	result := engine.SharedPreferencesExtract()

	if len(result.PrefsFiles) == 0 {
		t.Error("Expected prefs files")
	}
	for _, pref := range result.PrefsFiles {
		if pref.Path == "" {
			t.Error("Path should not be empty")
		}
	}
}

func TestBackupExtract(t *testing.T) {
	engine := NewEngine(MobileConfig{Platform: PlatformTypeIOS})

	result := engine.BackupExtract()

	if len(result.Backups) == 0 {
		t.Error("Expected backups")
	}
	for _, backup := range result.Backups {
		if backup.Path == "" {
			t.Error("Path should not be empty")
		}
	}
}

func TestEngineCreation(t *testing.T) {
	engine := NewEngine(MobileConfig{})
	if engine == nil {
		t.Fatal("Engine should not be nil")
	}
}

func TestPlatformTypes(t *testing.T) {
	types := []PlatformType{PlatformTypeIOS, PlatformTypeAndroid, PlatformTypeHarmonyOS}
	for _, pt := range types {
		if pt.String() == "" {
			t.Errorf("PlatformType %d should have string", pt)
		}
	}
}
