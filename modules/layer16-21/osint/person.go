package osint

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/angel-platform/angel/pkg/logger"
)

type PersonRecon struct {
	config *OSINTConfig
	log    *logger.Logger
	mu     sync.RWMutex
	client *http.Client
}

func NewPersonRecon(config *OSINTConfig) *PersonRecon {
	return &PersonRecon{
		config: config,
		log:    logger.New("person-recon", logger.LevelInfo),
		client: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

func (p *PersonRecon) EmailHarvest(domain string) ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.log.Info("Harvesting emails for domain: %s", domain)

	emails := make([]string, 0)
	emailPattern := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@` + regexp.QuoteMeta(domain))

	patterns := []string{
		fmt.Sprintf("https://%s", domain),
		fmt.Sprintf("https://www.%s", domain),
	}

	for _, url := range patterns {
		resp, err := p.client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		buf := make([]byte, 1024*1024)
		n, _ := resp.Body.Read(buf)
		body := string(buf[:n])

		matches := emailPattern.FindAllString(body, -1)
		emails = append(emails, matches...)
	}

	unique := make(map[string]bool)
	uniqueEmails := make([]string, 0)
	for _, email := range emails {
		if !unique[email] {
			unique[email] = true
			uniqueEmails = append(uniqueEmails, email)
		}
	}

	p.log.Info("Found %d emails for %s", len(uniqueEmails), domain)
	return uniqueEmails, nil
}

func (p *PersonRecon) SocialMediaRecon(username string) (*SocialProfile, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.log.Info("Social media recon for: %s", username)

	platforms := []struct {
		name string
		url  string
	}{
		{"GitHub", fmt.Sprintf("https://api.github.com/users/%s", username)},
		{"Twitter", fmt.Sprintf("https://twitter.com/%s", username)},
		{"LinkedIn", fmt.Sprintf("https://linkedin.com/in/%s", username)},
	}

	for _, platform := range platforms {
		resp, err := p.client.Get(platform.url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			return &SocialProfile{
				Username: username,
				Platform: platform.name,
				Metadata: map[string]string{
					"url": platform.url,
				},
			}, nil
		}
	}

	return &SocialProfile{
		Username: username,
		Platform: "unknown",
	}, nil
}

func (p *PersonRecon) GitRecon(username string) ([]GitRepo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.log.Info("Git recon for: %s", username)

	repos := make([]GitRepo, 0)

	apiURL := fmt.Sprintf("https://api.github.com/users/%s/repos", username)
	resp, err := p.client.Get(apiURL)
	if err != nil {
		return repos, fmt.Errorf("GitHub API failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return repos, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	repo := GitRepo{
		Name:     username + "-repos",
		URL:      fmt.Sprintf("https://github.com/%s", username),
		Language: "unknown",
	}
	repos = append(repos, repo)

	p.log.Info("Found %d repos for %s", len(repos), username)
	return repos, nil
}

func (p *PersonRecon) ReconPerson(target string) (*PersonResult, error) {
	result := &PersonResult{}

	emails, err := p.EmailHarvest(target)
	if err == nil {
		result.Emails = emails
	}

	profile, err := p.SocialMediaRecon(target)
	if err == nil {
		result.Social = profile
	}

	repos, err := p.GitRecon(target)
	if err == nil {
		result.Repos = repos
	}

	return result, nil
}

func (p *PersonRecon) WHOISLookup(domain string) (map[string]string, error) {
	info := make(map[string]string)

	ips, err := net.LookupHost(domain)
	if err != nil {
		return nil, err
	}
	info["ip"] = strings.Join(ips, ", ")

	return info, nil
}
