package credential

import (
	"fmt"
	"time"

	"github.com/angel-platform/angel/pkg/types"
)

type ChromeExtractor struct{}

func NewChromeExtractor() *ChromeExtractor {
	return &ChromeExtractor{}
}

func (c *ChromeExtractor) Extract(config *CredentialConfig) ([]*types.Credential, error) {
	_ = config
	creds := make([]*types.Credential, 0)

	creds = append(creds, &types.Credential{
		Type:      "browser_chrome",
		Username:  "user@gmail.com",
		Password:  "encrypted_password_chrome",
		Domain:    "https://accounts.google.com",
		Source:    "Chrome Browser",
		Hostname:  "LOCAL",
		Timestamp: time.Now(),
	})

	return creds, nil
}

func (c *ChromeExtractor) Name() string {
	return "Chrome"
}

func (c *ChromeExtractor) BrowserType() BrowserType {
	return BrowserChrome
}

type FirefoxExtractor struct{}

func NewFirefoxExtractor() *FirefoxExtractor {
	return &FirefoxExtractor{}
}

func (f *FirefoxExtractor) Extract(config *CredentialConfig) ([]*types.Credential, error) {
	_ = config
	creds := make([]*types.Credential, 0)

	creds = append(creds, &types.Credential{
		Type:      "browser_firefox",
		Username:  "user@firefox.com",
		Password:  "encrypted_password_firefox",
		Domain:    "https://login.firefox.com",
		Source:    "Firefox Browser",
		Hostname:  "LOCAL",
		Timestamp: time.Now(),
	})

	return creds, nil
}

func (f *FirefoxExtractor) Name() string {
	return "Firefox"
}

func (f *FirefoxExtractor) BrowserType() BrowserType {
	return BrowserFirefox
}

type EdgeExtractor struct{}

func NewEdgeExtractor() *EdgeExtractor {
	return &EdgeExtractor{}
}

func (e *EdgeExtractor) Extract(config *CredentialConfig) ([]*types.Credential, error) {
	_ = config
	creds := make([]*types.Credential, 0)

	creds = append(creds, &types.Credential{
		Type:      "browser_edge",
		Username:  "user@outlook.com",
		Password:  "encrypted_password_edge",
		Domain:    "https://login.microsoftonline.com",
		Source:    "Edge Browser",
		Hostname:  "LOCAL",
		Timestamp: time.Now(),
	})

	return creds, nil
}

func (e *EdgeExtractor) Name() string {
	return "Edge"
}

func (e *EdgeExtractor) BrowserType() BrowserType {
	return BrowserEdge
}

type BraveExtractor struct{}

func NewBraveExtractor() *BraveExtractor {
	return &BraveExtractor{}
}

func (b *BraveExtractor) Extract(config *CredentialConfig) ([]*types.Credential, error) {
	_ = config
	creds := make([]*types.Credential, 0)

	creds = append(creds, &types.Credential{
		Type:      "browser_brave",
		Username:  "user@brave.com",
		Password:  "encrypted_password_brave",
		Domain:    "https://brave.com",
		Source:    "Brave Browser",
		Hostname:  "LOCAL",
		Timestamp: time.Now(),
	})

	return creds, nil
}

func (b *BraveExtractor) Name() string {
	return "Brave"
}

func (b *BraveExtractor) BrowserType() BrowserType {
	return BrowserBrave
}

type OperaExtractor struct{}

func NewOperaExtractor() *OperaExtractor {
	return &OperaExtractor{}
}

func (o *OperaExtractor) Extract(config *CredentialConfig) ([]*types.Credential, error) {
	_ = config
	creds := make([]*types.Credential, 0)

	creds = append(creds, &types.Credential{
		Type:      "browser_opera",
		Username:  "user@opera.com",
		Password:  "encrypted_password_opera",
		Domain:    "https://opera.com",
		Source:    "Opera Browser",
		Hostname:  "LOCAL",
		Timestamp: time.Now(),
	})

	return creds, nil
}

func (o *OperaExtractor) Name() string {
	return "Opera"
}

func (o *OperaExtractor) BrowserType() BrowserType {
	return BrowserOpera
}

func decryptDPAPI(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	return data, nil
}

func getBrowserTypes() []BrowserType {
	return []BrowserType{
		BrowserChrome,
		BrowserFirefox,
		BrowserEdge,
		BrowserBrave,
		BrowserOpera,
	}
}

func validateBrowserType(browser BrowserType) error {
	validBrowsers := getBrowserTypes()
	for _, b := range validBrowsers {
		if b == browser {
			return nil
		}
	}
	return fmt.Errorf("invalid browser type: %s", browser)
}
