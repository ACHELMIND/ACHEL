package evidence

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"time"
)

type EvidenceCollector struct {
	client *http.Client
}

func NewEvidenceCollector() *EvidenceCollector {
	return &EvidenceCollector{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (ec *EvidenceCollector) CaptureRequest(req *http.Request) (*EvidenceCapture, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("read request body: %w", err)
	}
	defer req.Body.Close()

	h := sha256.Sum256(body)

	capture := &EvidenceCapture{
		ID:        fmt.Sprintf("req-%d", time.Now().UnixNano()),
		Type:      "http_request",
		Timestamp: time.Now().UTC(),
		Data:      body,
		Hash:      fmt.Sprintf("%x", h),
		Metadata: map[string]string{
			"method": req.Method,
			"url":    req.URL.String(),
			"host":   req.Host,
		},
	}

	return capture, nil
}

func (ec *EvidenceCollector) CaptureResponse(resp *http.Response) (*EvidenceCapture, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	defer resp.Body.Close()

	h := sha256.Sum256(body)

	capture := &EvidenceCapture{
		ID:        fmt.Sprintf("resp-%d", time.Now().UnixNano()),
		Type:      "http_response",
		Timestamp: time.Now().UTC(),
		Data:      body,
		Hash:      fmt.Sprintf("%x", h),
		Metadata: map[string]string{
			"status": resp.Status,
			"proto":  resp.Proto,
		},
	}

	return capture, nil
}

func (ec *EvidenceCollector) CaptureScreenshot(url string) (*EvidenceCapture, error) {
	resp, err := ec.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch url: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	h := sha256.Sum256(body)

	capture := &EvidenceCapture{
		ID:        fmt.Sprintf("ss-%d", time.Now().UnixNano()),
		Type:      "screenshot",
		Timestamp: time.Now().UTC(),
		Data:      body,
		Hash:      fmt.Sprintf("%x", h),
		Metadata: map[string]string{
			"url":    url,
			"status": resp.Status,
		},
	}

	return capture, nil
}

func (ec *EvidenceCollector) CaptureDiff(old, new string) (*EvidenceCapture, error) {
	data := fmt.Sprintf("--- OLD:\n%s\n+++ NEW:\n%s", old, new)
	h := sha256.Sum256([]byte(data))

	capture := &EvidenceCapture{
		ID:        fmt.Sprintf("diff-%d", time.Now().UnixNano()),
		Type:      "diff",
		Timestamp: time.Now().UTC(),
		Data:      []byte(data),
		Hash:      fmt.Sprintf("%x", h),
		Metadata:  map[string]string{},
	}

	return capture, nil
}
