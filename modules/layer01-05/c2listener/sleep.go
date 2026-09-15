package c2listener

import (
	"sync"
	"time"
)

type SleepMasker struct {
	mu            sync.RWMutex
	jitter        float64
	minSleep      time.Duration
	maxSleep      time.Duration
	sleepMethod   string
	encrypted     bool
	masked        bool
	sleepHistory  []SleepEntry
}

type SleepEntry struct {
	StartTime time.Time
	Duration  time.Duration
	Method    string
	Masked    bool
}

type SleepConfig struct {
	Jitter      float64
	MinSleep    time.Duration
	MaxSleep    time.Duration
	SleepMethod string
	Encrypted   bool
}

func NewSleepMasker(config SleepConfig) *SleepMasker {
	if config.Jitter == 0 {
		config.Jitter = 0.25
	}
	if config.MinSleep == 0 {
		config.MinSleep = 5 * time.Second
	}
	if config.MaxSleep == 0 {
		config.MaxSleep = 60 * time.Second
	}
	if config.SleepMethod == "" {
		config.SleepMethod = "standard"
	}

	return &SleepMasker{
		jitter:      config.Jitter,
		minSleep:    config.MinSleep,
		maxSleep:    config.MaxSleep,
		sleepMethod: config.SleepMethod,
		encrypted:   config.Encrypted,
	}
}

func (s *SleepMasker) Sleep() time.Duration {
	duration := s.calculateSleepDuration()

	entry := SleepEntry{
		StartTime: time.Now(),
		Duration:  duration,
		Method:    s.sleepMethod,
		Masked:    s.masked,
	}

	s.mu.Lock()
	s.sleepHistory = append(s.sleepHistory, entry)
	s.mu.Unlock()

	time.Sleep(duration)

	return duration
}

func (s *SleepMasker) SleepWithJitter() time.Duration {
	duration := s.calculateSleepDuration()

	entry := SleepEntry{
		StartTime: time.Now(),
		Duration:  duration,
		Method:    "jitter",
		Masked:    s.masked,
	}

	s.mu.Lock()
	s.sleepHistory = append(s.sleepHistory, entry)
	s.mu.Unlock()

	time.Sleep(duration)

	return duration
}

func (s *SleepMasker) calculateSleepDuration() time.Duration {
	s.mu.RLock()
	jitter := s.jitter
	minSleep := s.minSleep
	maxSleep := s.maxSleep
	s.mu.RUnlock()

	base := minSleep + time.Duration(float64(maxSleep-minSleep)*0.5)

	jitterAmount := float64(base) * jitter
	if jitterAmount > 0 {
		jitterDuration := time.Duration(jitterAmount)
		base = base + jitterDuration
	}

	if base < minSleep {
		base = minSleep
	}
	if base > maxSleep {
		base = maxSleep
	}

	return base
}

func (s *SleepMasker) Mask() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.masked = true
}

func (s *SleepMasker) Unmask() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.masked = false
}

func (s *SleepMasker) IsMasked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.masked
}

func (s *SleepMasker) GetHistory() []SleepEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	history := make([]SleepEntry, len(s.sleepHistory))
	copy(history, s.sleepHistory)
	return history
}

func (s *SleepMasker) SetJitter(jitter float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jitter = jitter
}

func (s *SleepMasker) SetSleepMethod(method string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sleepMethod = method
}

func (s *SleepMasker) GetAvgSleepDuration() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.sleepHistory) == 0 {
		return 0
	}

	var total time.Duration
	for _, entry := range s.sleepHistory {
		total += entry.Duration
	}

	return total / time.Duration(len(s.sleepHistory))
}
