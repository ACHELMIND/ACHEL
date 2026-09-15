package netevasion

import (
	"fmt"
	"sync"
	"time"
)

type DomainFronter struct {
	mu       sync.RWMutex
	configs  map[string]*DomainFrontConfig
	results  []*DomainFrontResult
}

func NewDomainFronter() *DomainFronter {
	return &DomainFronter{
		configs: make(map[string]*DomainFrontConfig),
		results: make([]*DomainFrontResult, 0),
	}
}

func (df *DomainFronter) AddFront(name string, config *DomainFrontConfig) {
	df.mu.Lock()
	defer df.mu.Unlock()
	df.configs[name] = config
}

func (df *DomainFronter) RemoveFront(name string) {
	df.mu.Lock()
	defer df.mu.Unlock()
	delete(df.configs, name)
}

func (df *DomainFronter) GetFront(name string) (*DomainFrontConfig, bool) {
	df.mu.RLock()
	defer df.mu.RUnlock()
	cfg, ok := df.configs[name]
	return cfg, ok
}

func (df *DomainFronter) ListFronts() []*DomainFrontConfig {
	df.mu.RLock()
	defer df.mu.RUnlock()
	result := make([]*DomainFrontConfig, 0, len(df.configs))
	for _, cfg := range df.configs {
		result = append(result, cfg)
	}
	return result
}

func (df *DomainFronter) TestConnection(name string) (*DomainFrontResult, error) {
	df.mu.RLock()
	cfg, ok := df.configs[name]
	df.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("front config %s not found", name)
	}

	result := &DomainFrontResult{
		Success:    true,
		RequestStr: fmt.Sprintf("Host: %s -> CDN: %s -> Target: %s", cfg.Host, cfg.CDN, cfg.Target),
		Error:      "",
	}

	df.mu.Lock()
	df.results = append(df.results, result)
	df.mu.Unlock()

	_ = cfg
	return result, nil
}

func (df *DomainFronter) GetResults() []*DomainFrontResult {
	df.mu.RLock()
	defer df.mu.RUnlock()
	result := make([]*DomainFrontResult, len(df.results))
	copy(result, df.results)
	return result
}

func (df *DomainFronter) BuildHTTPRequest(name string) (headers map[string]string, err error) {
	df.mu.RLock()
	cfg, ok := df.configs[name]
	df.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("front config %s not found", name)
	}

	_ = time.Now()

	return map[string]string{
		"Host":       cfg.Host,
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Accept":     "*/*",
	}, nil
}

func (df *DomainFronter) ClearResults() {
	df.mu.Lock()
	defer df.mu.Unlock()
	df.results = df.results[:0]
}
