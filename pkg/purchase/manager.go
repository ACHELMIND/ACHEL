package purchase

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/angel-platform/angel/pkg/supabase"
)

type Manager struct {
	supabaseClient *supabase.Client
	iosClient      *IOSClient
}

type PurchaseRecord struct {
	ID            string     `json:"id"`
	UserID        string     `json:"user_id"`
	Platform      string     `json:"platform"`
	ProductID     string     `json:"product_id"`
	TransactionID string     `json:"transaction_id"`
	Status        string     `json:"status"`
	Amount        float64    `json:"amount"`
	Currency      string     `json:"currency"`
	PurchasedAt   time.Time  `json:"purchased_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

func NewManager() (*Manager, error) {
	supabaseClient := supabase.NewClient()

	iosClient, err := NewIOSClient()
	if err != nil {
		log.Printf("Warning: iOS client not configured: %v", err)
	}

	return &Manager{
		supabaseClient: supabaseClient,
		iosClient:      iosClient,
	}, nil
}

func (m *Manager) SyncIOSPurchases(userID string, receiptData string) (*PurchaseRecord, error) {
	if m.iosClient == nil {
		return nil, fmt.Errorf("iOS client not configured")
	}

	receipt, err := m.iosClient.VerifyReceipt(receiptData)
	if err != nil {
		return nil, fmt.Errorf("failed to verify receipt: %w", err)
	}

	record := &PurchaseRecord{
		UserID:        userID,
		Platform:      "ios",
		ProductID:     receipt.ProductID,
		TransactionID: receipt.TransactionID,
		Status:        "active",
		PurchasedAt:   receipt.PurchaseDate,
		ExpiresAt:     &receipt.ExpiresDate,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := m.savePurchase(record); err != nil {
		return nil, fmt.Errorf("failed to save purchase: %w", err)
	}

	return record, nil
}

func (m *Manager) GetUserPurchases(userID string) ([]PurchaseRecord, error) {
	url := fmt.Sprintf("%s/rest/v1/purchases?user_id=eq.%s&select=*&order=created_at.desc", 
		m.supabaseClient.URL, userID)

	req, err := createRequest("GET", url, nil, m.supabaseClient.Key)
	if err != nil {
		return nil, err
	}

	var purchases []PurchaseRecord
	if err := executeRequest(m.supabaseClient, req, &purchases); err != nil {
		return nil, err
	}

	return purchases, nil
}

func (m *Manager) savePurchase(record *PurchaseRecord) error {
	url := fmt.Sprintf("%s/rest/v1/purchases", m.supabaseClient.URL)

	req, err := createRequest("POST", url, record, m.supabaseClient.Key)
	if err != nil {
		return err
	}

	return executeRequest(m.supabaseClient, req, nil)
}

func (m *Manager) IsSubscriptionActive(userID string) (bool, error) {
	purchases, err := m.GetUserPurchases(userID)
	if err != nil {
		return false, err
	}

	now := time.Now()
	for _, p := range purchases {
		if p.ExpiresAt != nil && p.ExpiresAt.After(now) {
			return true, nil
		}
	}

	return false, nil
}

func createRequest(method, url string, body interface{}, apiKey string) (*http.Request, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("apikey", apiKey)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Prefer", "return=representation")

	return req, nil
}

func executeRequest(client *supabase.Client, req *http.Request, result interface{}) error {
	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("supabase returned status %d: %s", resp.StatusCode, string(body))
	}

	if result != nil {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return json.Unmarshal(body, result)
	}

	return nil
}
