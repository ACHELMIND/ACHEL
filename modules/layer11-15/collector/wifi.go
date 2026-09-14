package collector

import (
	"fmt"
	"sync"
)

type WiFiGrabber struct {
	mu sync.RWMutex
}

func NewWiFiGrabber() *WiFiGrabber {
	return &WiFiGrabber{}
}

func (w *WiFiGrabber) GetWiFiProfiles() ([]WiFiProfile, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	profiles := []WiFiProfile{
		{
			SSID:     "HomeNetwork",
			Auth:     "WPA2-Personal",
			EncType:  "AES",
			Password: "encrypted_password_1",
		},
		{
			SSID:     "OfficeWiFi",
			Auth:     "WPA2-Enterprise",
			EncType:  "AES",
			Password: "encrypted_password_2",
		},
		{
			SSID:     "CoffeeShop",
			Auth:     "Open",
			EncType:  "None",
			Password: "",
		},
	}

	return profiles, nil
}

func (w *WiFiGrabber) GetWiFiPassword(ssid string) (string, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	passwords := map[string]string{
		"HomeNetwork": "MySecretPass123!",
		"OfficeWiFi":  "CorpSecure456#",
	}

	if pass, ok := passwords[ssid]; ok {
		return pass, nil
	}

	return "", fmt.Errorf("SSID not found: %s", ssid)
}

func (w *WiFiGrabber) GetAllPasswords() (map[string]string, error) {
	profiles, err := w.GetWiFiProfiles()
	if err != nil {
		return nil, err
	}

	passwords := make(map[string]string)
	for _, p := range profiles {
		if p.Password != "" {
			passwords[p.SSID] = p.Password
		}
	}

	return passwords, nil
}
