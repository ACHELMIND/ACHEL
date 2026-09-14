package orchestrator

import (
	"fmt"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
)

type StateManager struct {
	state  map[string]*StateEntry
	log    *logger.Logger
	mu     sync.RWMutex
}

func NewStateManager() *StateManager {
	return &StateManager{
		state: make(map[string]*StateEntry),
		log:   logger.New("state-manager", logger.LevelInfo),
	}
}

func (sm *StateManager) SaveState(key string, value interface{}) error {
	if key == "" {
		return fmt.Errorf("empty key")
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()

	if existing, ok := sm.state[key]; ok {
		existing.Value = value
		existing.UpdatedAt = now
		sm.log.Debug("Updated state: %s", key)
	} else {
		sm.state[key] = &StateEntry{
			Key:       key,
			Value:     value,
			CreatedAt: now,
			UpdatedAt: now,
		}
		sm.log.Debug("Saved state: %s", key)
	}

	return nil
}

func (sm *StateManager) LoadState(key string) (interface{}, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	entry, ok := sm.state[key]
	if !ok {
		return nil, fmt.Errorf("state not found: %s", key)
	}

	return entry.Value, nil
}

func (sm *StateManager) ListKeys(prefix string) []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	keys := make([]string, 0)
	for key := range sm.state {
		if prefix == "" || len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			keys = append(keys, key)
		}
	}
	return keys
}

func (sm *StateManager) DeleteState(key string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, ok := sm.state[key]; !ok {
		return fmt.Errorf("state not found: %s", key)
	}

	delete(sm.state, key)
	sm.log.Debug("Deleted state: %s", key)
	return nil
}

func (sm *StateManager) Clear() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.state = make(map[string]*StateEntry)
	sm.log.Info("State cleared")
}

func (sm *StateManager) GetEntry(key string) (*StateEntry, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	entry, ok := sm.state[key]
	if !ok {
		return nil, fmt.Errorf("state not found: %s", key)
	}
	return entry, nil
}

func (sm *StateManager) Count() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.state)
}
