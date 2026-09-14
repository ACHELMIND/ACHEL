package infra

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
)

type IPRotationManager struct {
	config    *InfraConfig
	log       *logger.Logger
	mu        sync.RWMutex
	proxies   []string
	currentIdx int
	maxRetries int
	timeout    time.Duration
}

func NewIPRotationManager(config *InfraConfig) *IPRotationManager {
	if config == nil {
		config = DefaultInfraConfig()
	}
	return &IPRotationManager{
		config:     config,
		log:        logger.New("ip-rotation", logger.LevelInfo),
		proxies:    make([]string, 0),
		currentIdx: 0,
		maxRetries: 3,
		timeout:    10 * time.Second,
	}
}

func (r *IPRotationManager) SetProxies(proxies []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.proxies = proxies
	r.currentIdx = 0
	r.log.Info("Set %d proxies for rotation", len(proxies))
}

func (r *IPRotationManager) RotateIP() (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.proxies) == 0 {
		return "", fmt.Errorf("no proxies configured")
	}

	maxAttempts := len(r.proxies)
	if maxAttempts > r.maxRetries {
		maxAttempts = r.maxRetries
	}

	for i := 0; i < maxAttempts; i++ {
		proxy := r.proxies[r.currentIdx]
		r.currentIdx = (r.currentIdx + 1) % len(r.proxies)

		if r.ValidateProxy(proxy) {
			r.log.Info("Rotated to proxy: %s", proxy)
			return proxy, nil
		}
		r.log.Warn("Proxy validation failed: %s", proxy)
	}

	return "", fmt.Errorf("all proxies failed validation")
}

func (r *IPRotationManager) GetProxyChain() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	chain := make([]string, len(r.proxies))
	copy(chain, r.proxies)
	return chain
}

func (r *IPRotationManager) ValidateProxy(proxy string) bool {
	if proxy == "" {
		return false
	}

	host, port, err := net.SplitHostPort(proxy)
	if err != nil {
		return false
	}

	if host == "" || port == "" {
		return false
	}

	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, r.timeout)
	if err != nil {
		return false
	}
	conn.Close()

	return true
}

func (r *IPRotationManager) TestProxyHTTP(proxy string, targetURL string) (int, error) {
	proxyURL, err := url.Parse("http://" + proxy)
	if err != nil {
		return 0, fmt.Errorf("invalid proxy URL: %w", err)
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		ResponseHeaderTimeout: r.timeout,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   r.timeout,
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	return resp.StatusCode, nil
}

func (r *IPRotationManager) GetProxyCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.proxies)
}

func (r *IPRotationManager) GetCurrentProxy() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.proxies) == 0 {
		return ""
	}
	return r.proxies[r.currentIdx]
}

func (r *IPRotationManager) RemoveProxy(proxy string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, p := range r.proxies {
		if p == proxy {
			r.proxies = append(r.proxies[:i], r.proxies[i+1:]...)
			if r.currentIdx >= len(r.proxies) {
				r.currentIdx = 0
			}
			r.log.Info("Removed proxy: %s", proxy)
			return true
		}
	}
	return false
}

func (r *IPRotationManager) AddProxy(proxy string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.proxies = append(r.proxies, proxy)
	r.log.Info("Added proxy: %s", proxy)
}
