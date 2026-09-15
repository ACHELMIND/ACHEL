package malleable

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type ProfileApplier struct {
	mu          sync.RWMutex
	profiles    map[string]*AppliedProfile
	currentPro  string
}

type AppliedProfile struct {
	Name      string
	Profile   *Profile
	AppliedAt time.Duration
	Requests  int
	Errors    int
}

type ProfileApplyConfig struct {
	ProfileName string
	AutoApply   bool
	Fallback    string
}

func NewProfileApplier() *ProfileApplier {
	return &ProfileApplier{
		profiles: make(map[string]*AppliedProfile),
	}
}

func (pa *ProfileApplier) ApplyProfile(name string, profile *Profile) error {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	applied := &AppliedProfile{
		Name:      name,
		Profile:   profile,
		AppliedAt: time.Since(time.Now()),
		Requests:  0,
		Errors:    0,
	}

	pa.profiles[name] = applied
	pa.currentPro = name

	return nil
}

func (pa *ProfileApplier) RemoveProfile(name string) {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	delete(pa.profiles, name)

	if pa.currentPro == name {
		pa.currentPro = ""
	}
}

func (pa *ProfileApplier) SetCurrentProfile(name string) error {
	pa.mu.RLock()
	_, exists := pa.profiles[name]
	pa.mu.RUnlock()

	if !exists {
		return fmt.Errorf("profile not found: %s", name)
	}

	pa.mu.Lock()
	pa.currentPro = name
	pa.mu.Unlock()

	return nil
}

func (pa *ProfileApplier) GetCurrentProfile() *AppliedProfile {
	pa.mu.RLock()
	defer pa.mu.RUnlock()
	return pa.profiles[pa.currentPro]
}

func (pa *ProfileApplier) ApplyToRequest(req *http.Request, profile *Profile) {
	if profile == nil {
		return
	}

	for key, value := range profile.HTTPGet.Headers {
		req.Header.Set(key, value)
	}

	if len(profile.HTTPGet.URI) > 0 {
		req.URL.Path = profile.HTTPGet.URI[0]
	}
}

func (pa *ProfileApplier) ApplyToResponse(resp *http.Response, profile *Profile) {
	if profile == nil {
		return
	}

	if profile.HTTPGet.Headers != nil {
		for key, value := range profile.HTTPGet.Headers {
			resp.Header.Set(key, value)
		}
	}
}

func (pa *ProfileApplier) GenerateRequest(profile *Profile) *http.Request {
	if profile == nil {
		return nil
	}

	method := profile.HTTPGet.Method
	if method == "" {
		method = "GET"
	}

	uri := "/"
	if len(profile.HTTPGet.URI) > 0 {
		uri = profile.HTTPGet.URI[0]
	}

	req, _ := http.NewRequest(method, uri, nil)

	for key, value := range profile.HTTPGet.Headers {
		req.Header.Set(key, value)
	}

	return req
}

func (pa *ProfileApplier) GetProfiles() map[string]*AppliedProfile {
	pa.mu.RLock()
	defer pa.mu.RUnlock()

	profiles := make(map[string]*AppliedProfile)
	for k, v := range pa.profiles {
		profiles[k] = v
	}
	return profiles
}

func (pa *ProfileApplier) GetProfileCount() int {
	pa.mu.RLock()
	defer pa.mu.RUnlock()
	return len(pa.profiles)
}

func (pa *ProfileApplier) IncrementRequests(name string) {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	if profile, exists := pa.profiles[name]; exists {
		profile.Requests++
	}
}

func (pa *ProfileApplier) IncrementErrors(name string) {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	if profile, exists := pa.profiles[name]; exists {
		profile.Errors++
	}
}

func (pa *ProfileApplier) GetStats(name string) (int, int) {
	pa.mu.RLock()
	defer pa.mu.RUnlock()

	if profile, exists := pa.profiles[name]; exists {
		return profile.Requests, profile.Errors
	}
	return 0, 0
}

func generateMalleableURL(host string, path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return fmt.Sprintf("https://%s%s", host, path)
}
