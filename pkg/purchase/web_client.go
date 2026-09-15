package purchase

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type WebClient struct {
	StripeKey    string
	MidtransKey  string
	XenditKey    string
	HTTPClient   *http.Client
}

type WebPayment struct {
	ID            string     `json:"id"`
	UserID        string     `json:"user_id"`
	Platform      string     `json:"platform"`
	PaymentMethod string     `json:"payment_method"`
	Amount        float64    `json:"amount"`
	Currency      string     `json:"currency"`
	Status        string     `json:"status"`
	PaymentURL    string     `json:"payment_url,omitempty"`
	ExternalID    string     `json:"external_id"`
	CreatedAt     time.Time  `json:"created_at"`
	PaidAt        *time.Time `json:"paid_at,omitempty"`
}

type StripeCheckout struct {
	SessionID string `json:"session_id"`
	URL       string `json:"url"`
}

type MidtransToken struct {
	Token       string `json:"token"`
	RedirectURL string `json:"redirect_url"`
}

type XenditInvoice struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	PaymentURL  string `json:"payment_url"`
}

func NewWebClient() *WebClient {
	return &WebClient{
		StripeKey:   os.Getenv("STRIPE_SECRET_KEY"),
		MidtransKey: os.Getenv("MIDTRANS_SERVER_KEY"),
		XenditKey:   os.Getenv("XENDIT_SECRET_KEY"),
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *WebClient) CreateStripeCheckout(amount float64, currency, productID, userID string) (*StripeCheckout, error) {
	if c.StripeKey == "" {
		return nil, fmt.Errorf("Stripe key not configured")
	}

	url := "https://api.stripe.com/v1/checkout/sessions"

	payload := fmt.Sprintf("payment_method_types[]=card&line_items[0][price_data][currency]=%s&line_items[0][price_data][product_data][name]=%s&line_items[0][price_data][unit_amount]=%d&mode=payment&success_url=https://example.com/success&cancel_url=https://example.com/cancel&metadata[user_id]=%s",
		currency, productID, int(amount*100), userID)

	req, err := http.NewRequest("POST", url, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.StripeKey))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Stripe returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &StripeCheckout{
		SessionID: result.ID,
		URL:       result.URL,
	}, nil
}

func (c *WebClient) CreateMidtransToken(amount float64, orderID, userID string) (*MidtransToken, error) {
	if c.MidtransKey == "" {
		return nil, fmt.Errorf("Midtrans key not configured")
	}

	url := "https://api.sandbox.midtrans.com/v2/gesn"

	payload := map[string]interface{}{
		"transaction_details": map[string]interface{}{
			"order_id":     orderID,
			"gross_amount": amount,
		},
		"customer_details": map[string]interface{}{
			"first_name": userID,
		},
	}

	data, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", url, strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", c.MidtransKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Midtrans returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data struct {
			Token       string `json:"token"`
			RedirectURL string `json:"redirect_url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &MidtransToken{
		Token:       result.Data.Token,
		RedirectURL: result.Data.RedirectURL,
	}, nil
}

func (c *WebClient) CreateXenditInvoice(amount float64, orderID, userID string) (*XenditInvoice, error) {
	if c.XenditKey == "" {
		return nil, fmt.Errorf("Xendit key not configured")
	}

	url := "https://api.xendit.co/v2/invoices"

	payload := map[string]interface{}{
		"external_id": orderID,
		"amount":      amount,
		"payer_email": fmt.Sprintf("%s@example.com", userID),
		"description": fmt.Sprintf("Payment for order %s", orderID),
	}

	data, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", url, strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", c.XenditKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("Xendit returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		ID         string `json:"id"`
		Status     string `json:"status"`
		PaymentURL string `json:"payment_url"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &XenditInvoice{
		ID:         result.ID,
		Status:     result.Status,
		PaymentURL: result.PaymentURL,
	}, nil
}
