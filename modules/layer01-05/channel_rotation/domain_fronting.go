package channel_rotation

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type DomainFronting struct {
	mu          sync.RWMutex
	frontDomains []FrontDomain
	currentIndex int
}

type FrontDomain struct {
	ID          string
	Domain      string
	CDNProvider string
	IP          string
	Port        int
	Healthy     bool
	LastCheck   time.Time
}

func NewDomainFronting() *DomainFronting {
	return &DomainFronting{
		frontDomains: make([]FrontDomain, 0),
	}
}

func (df *DomainFronting) AddDomain(domain FrontDomain) {
	df.mu.Lock()
	defer df.mu.Unlock()

	if domain.ID == "" {
		domain.ID = generateFrontID()
	}
	domain.Healthy = true
	domain.LastCheck = time.Now()

	df.frontDomains = append(df.frontDomains, domain)
}

func (df *DomainFronting) RemoveDomain(domainID string) {
	df.mu.Lock()
	defer df.mu.Unlock()

	for i, d := range df.frontDomains {
		if d.ID == domainID {
			df.frontDomains = append(df.frontDomains[:i], df.frontDomains[i+1:]...)
			break
		}
	}
}

func (df *DomainFronting) GetNextDomain() *FrontDomain {
	df.mu.Lock()
	defer df.mu.Unlock()

	if len(df.frontDomains) == 0 {
		return nil
	}

	for i := 0; i < len(df.frontDomains); i++ {
		idx := (df.currentIndex + i) % len(df.frontDomains)
		if df.frontDomains[idx].Healthy {
			df.currentIndex = (idx + 1) % len(df.frontDomains)
			return &df.frontDomains[idx]
		}
	}

	return nil
}

func (df *DomainFronting) CreateFrontedRequest(url string, method string) (*http.Request, error) {
	domain := df.GetNextDomain()
	if domain == nil {
		return nil, fmt.Errorf("no healthy front domain available")
	}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	req.Host = domain.Domain
	req.Header.Set("Host", domain.Domain)

	return req, nil
}

func (df *DomainFronting) CheckHealth(domainID string) bool {
	df.mu.RLock()
	defer df.mu.RUnlock()

	for _, d := range df.frontDomains {
		if d.ID == domainID {
			return d.Healthy
		}
	}
	return false
}

func (df *DomainFronting) UpdateHealth(domainID string, healthy bool) {
	df.mu.Lock()
	defer df.mu.Unlock()

	for i, d := range df.frontDomains {
		if d.ID == domainID {
			df.frontDomains[i].Healthy = healthy
			df.frontDomains[i].LastCheck = time.Now()
			break
		}
	}
}

func (df *DomainFronting) GetDomains() []FrontDomain {
	df.mu.RLock()
	defer df.mu.RUnlock()

	domains := make([]FrontDomain, len(df.frontDomains))
	copy(domains, df.frontDomains)
	return domains
}

func (df *DomainFronting) GetHealthyDomains() []FrontDomain {
	df.mu.RLock()
	defer df.mu.RUnlock()

	var healthy []FrontDomain
	for _, d := range df.frontDomains {
		if d.Healthy {
			healthy = append(healthy, d)
		}
	}
	return healthy
}

func (df *DomainFronting) GetDomainCount() int {
	df.mu.RLock()
	defer df.mu.RUnlock()
	return len(df.frontDomains)
}

func generateFrontID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
