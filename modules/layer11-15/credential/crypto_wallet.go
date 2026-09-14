package credential

import (
	"fmt"
	"time"
)

type MetaMaskExtractor struct{}

func NewMetaMaskExtractor() *MetaMaskExtractor {
	return &MetaMaskExtractor{}
}

func (m *MetaMaskExtractor) ExtractKeys(config *CredentialConfig) ([]WalletKey, error) {
	_ = config
	keys := make([]WalletKey, 0)

	keys = append(keys, WalletKey{
		Address:    "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
		PublicKey:  "04a1b2c3d4e5f6...",
		PrivateKey: "encrypted_private_key_metamask",
		Mnemonic:   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		WalletType: WalletMetaMask,
		Browser:    BrowserChrome,
		Timestamp:  time.Now(),
	})

	return keys, nil
}

func (m *MetaMaskExtractor) Name() string {
	return "MetaMask"
}

func (m *MetaMaskExtractor) BrowserType() BrowserType {
	return BrowserChrome
}

type PhantomExtractor struct{}

func NewPhantomExtractor() *PhantomExtractor {
	return &PhantomExtractor{}
}

func (p *PhantomExtractor) ExtractKeys(config *CredentialConfig) ([]WalletKey, error) {
	_ = config
	keys := make([]WalletKey, 0)

	keys = append(keys, WalletKey{
		Address:    "7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV",
		PublicKey:  "7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV",
		PrivateKey: "encrypted_private_key_phantom",
		Mnemonic:   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		WalletType: WalletPhantom,
		Browser:    BrowserChrome,
		Timestamp:  time.Now(),
	})

	return keys, nil
}

func (p *PhantomExtractor) Name() string {
	return "Phantom"
}

func (p *PhantomExtractor) BrowserType() BrowserType {
	return BrowserChrome
}

type ExodusExtractor struct{}

func NewExodusExtractor() *ExodusExtractor {
	return &ExodusExtractor{}
}

func (e *ExodusExtractor) ExtractKeys(config *CredentialConfig) ([]WalletKey, error) {
	_ = config
	keys := make([]WalletKey, 0)

	keys = append(keys, WalletKey{
		Address:    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
		PublicKey:  "04a1b2c3d4e5f6...",
		PrivateKey: "encrypted_private_key_exodus",
		Mnemonic:   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		WalletType: WalletExodus,
		Browser:    "",
		Timestamp:  time.Now(),
	})

	return keys, nil
}

func (e *ExodusExtractor) Name() string {
	return "Exodus"
}

func (e *ExodusExtractor) BrowserType() BrowserType {
	return ""
}

type ElectrumExtractor struct{}

func NewElectrumExtractor() *ElectrumExtractor {
	return &ElectrumExtractor{}
}

func (el *ElectrumExtractor) ExtractKeys(config *CredentialConfig) ([]WalletKey, error) {
	_ = config
	keys := make([]WalletKey, 0)

	keys = append(keys, WalletKey{
		Address:    "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
		PublicKey:  "04a1b2c3d4e5f6...",
		PrivateKey: "encrypted_private_key_electrum",
		Mnemonic:   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		WalletType: WalletElectrum,
		Browser:    "",
		Timestamp:  time.Now(),
	})

	return keys, nil
}

func (el *ElectrumExtractor) Name() string {
	return "Electrum"
}

func (el *ElectrumExtractor) BrowserType() BrowserType {
	return ""
}

func getWalletTypes() []WalletType {
	return []WalletType{
		WalletMetaMask,
		WalletPhantom,
		WalletExodus,
		WalletElectrum,
	}
}

func validateWalletType(wallet WalletType) error {
	validWallets := getWalletTypes()
	for _, w := range validWallets {
		if w == wallet {
			return nil
		}
	}
	return fmt.Errorf("invalid wallet type: %s", wallet)
}
