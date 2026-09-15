package netevasion

import (
	"fmt"
	"sync"
	"time"
)

type IPRotator struct {
	mu          sync.RWMutex
	proxies     []*ProxyInfo
	currentIdx  int
	currentIP   string
}

func NewIPRotator(proxyList []string) *IPRotator {
	proxies := make([]*ProxyInfo, 0, len(proxyList))
	for _, p := range proxyList {
		proxies = append(proxies, &ProxyInfo{
			Address:  p,
			Protocol: detectProtocol(p),
			Alive:    true,
		})
	}

	return &IPRotator{
		proxies:    proxies,
		currentIdx: 0,
		currentIP:  "",
	}
}

func (r *IPRotator) Rotate() (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.proxies) == 0 {
		return "", fmt.Errorf("no proxies available")
	}

	aliveCount := 0
	for _, p := range r.proxies {
		if p.Alive {
			aliveCount++
		}
	}

	if aliveCount == 0 {
		return "", fmt.Errorf("no alive proxies available")
	}

	idx := r.currentIdx
	for {
		proxy := r.proxies[idx%len(r.proxies)]
		if proxy.Alive {
			r.currentIP = proxy.Address
			r.currentIdx = (idx + 1) % len(r.proxies)
			proxy.LastCheck = time.Now()
			return proxy.Address, nil
		}
		idx++
		if idx == r.currentIdx+len(r.proxies) {
			break
		}
	}

	return "", fmt.Errorf("failed to find alive proxy")
}

func (r *IPRotator) AddProxy(proxy string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, p := range r.proxies {
		if p.Address == proxy {
			return fmt.Errorf("proxy %s already exists", proxy)
		}
	}

	r.proxies = append(r.proxies, &ProxyInfo{
		Address:  proxy,
		Protocol: detectProtocol(proxy),
		Alive:    true,
	})

	return nil
}

func (r *IPRotator) RemoveProxy(proxy string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, p := range r.proxies {
		if p.Address == proxy {
			r.proxies = append(r.proxies[:i], r.proxies[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("proxy %s not found", proxy)
}

func (r *IPRotator) ValidateAll() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var invalid []string
	for _, p := range r.proxies {
		if p.Address == "" {
			invalid = append(invalid, p.Address)
		}
	}

	return invalid
}

func (r *IPRotator) GetCurrentIP() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.currentIP
}

func (r *IPRotator) ProxyCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.proxies)
}

func detectProtocol(addr string) string {
	if len(addr) > 0 {
		switch addr[:3] {
		case "sock":
			return "socks5"
		case "http":
			return "http"
		}
	}
	return "http"
}
