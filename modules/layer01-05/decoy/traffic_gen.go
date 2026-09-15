package decoy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"sync"
	"time"
)

type TrafficGenerator struct {
	mu          sync.RWMutex
	config      TrafficConfig
	patterns    []TrafficPattern
	running     bool
	stopCh      chan struct{}
	totalSent   int64
	totalRecv   int64
}

type TrafficConfig struct {
	Rate        float64
	BurstSize   int
	Pattern     string
	Protocol    string
	TargetIP    string
	TargetPort  int
}

type TrafficPattern struct {
	Name      string
	Rate      float64
	Burst     bool
	Duration  time.Duration
	Variance  float64
}

type TrafficStats struct {
	TotalSent   int64
	TotalRecv   int64
	AvgRate     float64
	PeakRate    float64
	Timestamp   time.Time
}

func NewTrafficGenerator(config TrafficConfig) *TrafficGenerator {
	return &TrafficGenerator{
		config:   config,
		patterns: make([]TrafficPattern, 0),
		stopCh:   make(chan struct{}),
	}
}

func (tg *TrafficGenerator) AddPattern(pattern TrafficPattern) {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	tg.patterns = append(tg.patterns, pattern)
}

func (tg *TrafficGenerator) RemovePattern(name string) {
	tg.mu.Lock()
	defer tg.mu.Unlock()

	for i, p := range tg.patterns {
		if p.Name == name {
			tg.patterns = append(tg.patterns[:i], tg.patterns[i+1:]...)
			break
		}
	}
}

func (tg *TrafficGenerator) Start() {
	tg.mu.Lock()
	tg.running = true
	tg.mu.Unlock()

	go tg.generateLoop()
}

func (tg *TrafficGenerator) Stop() {
	tg.mu.Lock()
	tg.running = false
	tg.mu.Unlock()
	close(tg.stopCh)
}

func (tg *TrafficGenerator) generateLoop() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-tg.stopCh:
			return
		case <-ticker.C:
			tg.generate()
		}
	}
}

func (tg *TrafficGenerator) generate() {
	tg.mu.RLock()
	defer tg.mu.RUnlock()

	tg.totalSent += int64(tg.config.BurstSize)
	tg.totalRecv += int64(float64(tg.config.BurstSize) * 0.5)
}

func (tg *TrafficGenerator) GenerateRandomTraffic() []byte {
	size := 64 + randIntn(1024)
	data := make([]byte, size)
	rand.Read(data)
	return data
}

func (tg *TrafficGenerator) GenerateHTTPTraffic() string {
	paths := []string{"/", "/login", "/admin", "/api", "/images/logo.png", "/css/style.css"}
	path := paths[randIntn(len(paths))]

	return fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n",
		path, tg.config.TargetIP)
}

func (tg *TrafficGenerator) GenerateDNSTraffic() string {
	domains := []string{"example.com", "google.com", "github.com", "microsoft.com", "amazon.com"}
	domain := domains[randIntn(len(domains))]

	return fmt.Sprintf("DNS %s A IN", domain)
}

func (tg *TrafficGenerator) GenerateSMTPTraffic() string {
	return fmt.Sprintf("EHLO %s\r\nMAIL FROM:<%s>\r\nRCPT TO:<test@example.com>\r\nDATA\r\n.\r\nQUIT",
		tg.config.TargetIP, generateRandomEmail())
}

func (tg *TrafficGenerator) GenerateRandomData(size int) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}

func (tg *TrafficGenerator) GetStats() TrafficStats {
	tg.mu.RLock()
	defer tg.mu.RUnlock()

	return TrafficStats{
		TotalSent:  tg.totalSent,
		TotalRecv:  tg.totalRecv,
		AvgRate:    float64(tg.totalSent) / time.Since(time.Now()).Seconds(),
		PeakRate:   float64(tg.config.Rate) * 1.5,
		Timestamp:  time.Now(),
	}
}

func (tg *TrafficGenerator) GetPatterns() []TrafficPattern {
	tg.mu.RLock()
	defer tg.mu.RUnlock()

	patterns := make([]TrafficPattern, len(tg.patterns))
	copy(patterns, tg.patterns)
	return patterns
}

func (tg *TrafficGenerator) IsRunning() bool {
	tg.mu.RLock()
	defer tg.mu.RUnlock()
	return tg.running
}

func generateRandomEmail() string {
	names := []string{"john", "jane", "bob", "alice", "charlie"}
	domains := []string{"example.com", "test.com", "demo.com"}

	name := names[randIntn(len(names))]
	domain := domains[randIntn(len(domains))]

	return fmt.Sprintf("%s@%s", name, domain)
}

func randIntn(n int) int {
	if n <= 0 {
		return 0
	}
	b := make([]byte, 4)
	rand.Read(b)
	return int(b[0])%n + int(b[1])%n + int(b[2])%n + int(b[3])%n
}

func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return hex.EncodeToString(b)[:length]
}

func calculateVariance(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}

	var sum float64
	for _, d := range data {
		sum += d
	}
	mean := sum / float64(len(data))

	var variance float64
	for _, d := range data {
		variance += (d - mean) * (d - mean)
	}

	return variance / float64(len(data))
}

func calculateStdDev(data []float64) float64 {
	return math.Sqrt(calculateVariance(data))
}
