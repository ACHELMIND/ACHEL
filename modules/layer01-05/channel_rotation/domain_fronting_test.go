package channel_rotation

import (
	"testing"
	"time"
)

func TestNewDomainFronting(t *testing.T) {
	df := NewDomainFronting()
	if df == nil {
		t.Fatal("NewDomainFronting returned nil")
	}
	if len(df.frontDomains) != 0 {
		t.Errorf("expected 0 domains, got %d", len(df.frontDomains))
	}
}

func TestDomainFronting_AddDomain(t *testing.T) {
	df := NewDomainFronting()
	df.AddDomain(FrontDomain{Domain: "cdn.example.com", CDNProvider: "cloudflare", IP: "1.2.3.4", Port: 443})

	if df.GetDomainCount() != 1 {
		t.Fatalf("expected 1 domain, got %d", df.GetDomainCount())
	}
	d := df.GetDomains()[0]
	if d.Domain != "cdn.example.com" {
		t.Errorf("expected cdn.example.com, got %s", d.Domain)
	}
	if !d.Healthy {
		t.Error("expected domain to be healthy by default")
	}
	if d.ID == "" {
		t.Error("expected auto-generated ID")
	}
}

func TestDomainFronting_AddDomain_WithID(t *testing.T) {
	df := NewDomainFronting()
	df.AddDomain(FrontDomain{ID: "custom-id", Domain: "cdn.example.com"})

	d := df.GetDomains()[0]
	if d.ID != "custom-id" {
		t.Errorf("expected custom-id, got %s", d.ID)
	}
}

func TestDomainFronting_RemoveDomain(t *testing.T) {
	df := NewDomainFronting()
	df.AddDomain(FrontDomain{ID: "d1", Domain: "a.com"})
	df.AddDomain(FrontDomain{ID: "d2", Domain: "b.com"})

	df.RemoveDomain("d1")

	if df.GetDomainCount() != 1 {
		t.Fatalf("expected 1 domain, got %d", df.GetDomainCount())
	}
	if df.GetDomains()[0].ID != "d2" {
		t.Errorf("expected d2, got %s", df.GetDomains()[0].ID)
	}
}

func TestDomainFronting_RemoveDomain_NotFound(t *testing.T) {
	df := NewDomainFronting()
	df.AddDomain(FrontDomain{ID: "d1", Domain: "a.com"})

	df.RemoveDomain("nonexistent")

	if df.GetDomainCount() != 1 {
		t.Errorf("expected 1 domain, got %d", df.GetDomainCount())
	}
}

func TestDomainFronting_GetNextDomain_Empty(t *testing.T) {
	df := NewDomainFronting()
	if d := df.GetNextDomain(); d != nil {
		t.Errorf("expected nil, got %v", d)
	}
}

func TestDomainFronting_GetNextDomain(t *testing.T) {
	df := NewDomainFronting()
	df.AddDomain(FrontDomain{ID: "d1", Domain: "a.com"})
	df.AddDomain(FrontDomain{ID: "d2", Domain: "b.com"})

	d1 := df.GetNextDomain()
	if d1 == nil || d1.ID != "d1" {
		t.Errorf("expected d1, got %v", d1)
	}

	d2 := df.GetNextDomain()
	if d2 == nil || d2.ID != "d2" {
		t.Errorf("expected d2, got %v", d2)
	}

	// Wrap around
	d3 := df.GetNextDomain()
	if d3 == nil || d3.ID != "d1" {
		t.Errorf("expected d1 (wrap), got %v", d3)
	}
}

func TestDomainFronting_GetNextDomain_SkipsUnhealthy(t *testing.T) {
	df := NewDomainFronting()
	df.AddDomain(FrontDomain{ID: "d1", Domain: "a.com"})
	df.AddDomain(FrontDomain{ID: "d2", Domain: "b.com"})
	df.UpdateHealth("d1", false)

	d := df.GetNextDomain()
	if d == nil || d.ID != "d2" {
		t.Errorf("expected d2 (skipping unhealthy d1), got %v", d)
	}
}

func TestDomainFronting_GetNextDomain_AllUnhealthy(t *testing.T) {
	df := NewDomainFronting()
	df.AddDomain(FrontDomain{ID: "d1", Domain: "a.com"})
	df.UpdateHealth("d1", false)

	if d := df.GetNextDomain(); d != nil {
		t.Errorf("expected nil when all unhealthy, got %v", d)
	}
}

func TestDomainFronting_CreateFrontedRequest(t *testing.T) {
	df := NewDomainFronting()
	df.AddDomain(FrontDomain{ID: "d1", Domain: "evil-cdn.com"})

	req, err := df.CreateFrontedRequest("https://target.com/api", "GET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Host != "evil-cdn.com" {
		t.Errorf("expected Host header evil-cdn.com, got %s", req.Host)
	}
	if req.Header.Get("Host") != "evil-cdn.com" {
		t.Errorf("expected Host header evil-cdn.com, got %s", req.Header.Get("Host"))
	}
}

func TestDomainFronting_CreateFrontedRequest_NoDomains(t *testing.T) {
	df := NewDomainFronting()
	_, err := df.CreateFrontedRequest("https://target.com", "GET")
	if err == nil {
		t.Error("expected error when no domains available")
	}
}

func TestDomainFronting_CheckHealth(t *testing.T) {
	df := NewDomainFronting()
	df.AddDomain(FrontDomain{ID: "d1", Domain: "a.com"})

	if !df.CheckHealth("d1") {
		t.Error("expected d1 to be healthy")
	}
	if df.CheckHealth("nonexistent") {
		t.Error("expected nonexistent to not be healthy")
	}
}

func TestDomainFronting_UpdateHealth(t *testing.T) {
	df := NewDomainFronting()
	df.AddDomain(FrontDomain{ID: "d1", Domain: "a.com"})

	df.UpdateHealth("d1", false)
	if df.CheckHealth("d1") {
		t.Error("expected d1 to be unhealthy")
	}

	df.UpdateHealth("d1", true)
	if !df.CheckHealth("d1") {
		t.Error("expected d1 to be healthy again")
	}
}

func TestDomainFronting_GetDomains(t *testing.T) {
	df := NewDomainFronting()
	df.AddDomain(FrontDomain{ID: "d1", Domain: "a.com"})
	df.AddDomain(FrontDomain{ID: "d2", Domain: "b.com"})

	domains := df.GetDomains()
	if len(domains) != 2 {
		t.Errorf("expected 2 domains, got %d", len(domains))
	}
}

func TestDomainFronting_GetHealthyDomains(t *testing.T) {
	df := NewDomainFronting()
	df.AddDomain(FrontDomain{ID: "d1", Domain: "a.com"})
	df.AddDomain(FrontDomain{ID: "d2", Domain: "b.com"})
	df.UpdateHealth("d1", false)

	healthy := df.GetHealthyDomains()
	if len(healthy) != 1 {
		t.Fatalf("expected 1 healthy domain, got %d", len(healthy))
	}
	if healthy[0].ID != "d2" {
		t.Errorf("expected d2, got %s", healthy[0].ID)
	}
}

func TestDomainFronting_GetDomainCount(t *testing.T) {
	df := NewDomainFronting()
	if df.GetDomainCount() != 0 {
		t.Errorf("expected 0, got %d", df.GetDomainCount())
	}

	df.AddDomain(FrontDomain{Domain: "a.com"})
	df.AddDomain(FrontDomain{Domain: "b.com"})
	if df.GetDomainCount() != 2 {
		t.Errorf("expected 2, got %d", df.GetDomainCount())
	}
}

func TestDomainFronting_LastCheckSet(t *testing.T) {
	df := NewDomainFronting()
	before := time.Now()
	df.AddDomain(FrontDomain{ID: "d1", Domain: "a.com"})
	after := time.Now()

	d := df.GetDomains()[0]
	if d.LastCheck.Before(before) || d.LastCheck.After(after) {
		t.Error("expected LastCheck to be set to approximately now")
	}
}
