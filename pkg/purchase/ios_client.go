package purchase

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type IOSClient struct {
	IssuerID    string
	KeyID       string
	PrivateKey  *ecdsa.PrivateKey
	HTTPClient  *http.Client
	BaseURL     string
}

type IOSReceipt struct {
	TransactionID string    `json:"transactionId"`
	ProductID     string    `json:"productId"`
	PurchaseDate  time.Time `json:"purchaseDate"`
	ExpiresDate   time.Time `json:"expiresDate"`
	IsTrial       bool      `json:"isTrial"`
	Environment   string    `json:"environment"`
}

type IOSPurchase struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Platform    string    `json:"platform"`
	ProductID   string    `json:"product_id"`
	TransactionID string  `json:"transaction_id"`
	Status      string    `json:"status"`
	Amount      float64   `json:"amount"`
	Currency    string    `json:"currency"`
	PurchasedAt time.Time `json:"purchased_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

func NewIOSClient() (*IOSClient, error) {
	issuerID := os.Getenv("APPLE_ISSUER_ID")
	keyID := os.Getenv("APPLE_KEY_ID")
	keyPath := os.Getenv("APPLE_PRIVATE_KEY_PATH")

	if issuerID == "" || keyID == "" || keyPath == "" {
		return nil, fmt.Errorf("missing Apple App Store credentials in environment")
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not ECDSA")
	}

	return &IOSClient{
		IssuerID:   issuerID,
		KeyID:      keyID,
		PrivateKey: ecdsaKey,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		BaseURL: "https://api.storekit.itunes.apple.com",
	}, nil
}

func (c *IOSClient) GetTransactionHistory(transactionID string) ([]IOSReceipt, error) {
	url := fmt.Sprintf("%s/inApps/v1/transactions/%s", c.BaseURL, transactionID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.generateToken()))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Apple API returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Receipts []IOSReceipt `json:"receipts"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return result.Receipts, nil
}

func (c *IOSClient) VerifyReceipt(receiptData string) (*IOSReceipt, error) {
	url := "https://buy.itunes.apple.com/verifyReceipt"

	payload := map[string]string{
		"receipt-data":            receiptData,
		"password":               os.Getenv("APPLE_SHARED_SECRET"),
		"exclude-old-transactions": "true",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Apple API returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Receipt struct {
			InApp []IOSReceipt `json:"in_app"`
		} `json:"receipt"`
		Status int `json:"status"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if result.Status != 0 {
		return nil, fmt.Errorf("receipt verification failed with status: %d", result.Status)
	}

	if len(result.Receipt.InApp) == 0 {
		return nil, fmt.Errorf("no purchases found in receipt")
	}

	return &result.Receipt.InApp[0], nil
}

func (c *IOSClient) generateToken() string {
	return fmt.Sprintf("%s.%s", c.IssuerID, c.KeyID)
}
