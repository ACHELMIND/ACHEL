package resilience

import (
	"log"
	"sync"
	"time"
)

type RePersist struct {
	mu            sync.RWMutex
	persistenceMap map[string]PersistenceMethod
	running       bool
	stopCh        chan struct{}
	checkInterval time.Duration
}

type PersistenceMethod struct {
	ID          string
	Type        string
	Location    string
	Active      bool
	LastCheck   time.Time
	ReinstallFunc func() error
}

func NewRePersist(checkInterval time.Duration) *RePersist {
	return &RePersist{
		persistenceMap: make(map[string]PersistenceMethod),
		stopCh:        make(chan struct{}),
		checkInterval: checkInterval,
	}
}

func (r *RePersist) Start() {
	r.mu.Lock()
	r.running = true
	r.mu.Unlock()

	go r.monitorLoop()
}

func (r *RePersist) Stop() {
	r.mu.Lock()
	r.running = false
	r.mu.Unlock()
	close(r.stopCh)
}

func (r *RePersist) monitorLoop() {
	ticker := time.NewTicker(r.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.checkAll()
		}
	}
}

func (r *RePersist) checkAll() {
	r.mu.RLock()
	methods := make([]PersistenceMethod, 0, len(r.persistenceMap))
	for _, m := range r.persistenceMap {
		methods = append(methods, m)
	}
	r.mu.RUnlock()

	for _, method := range methods {
		if !method.Active {
			r.reinstall(method)
		}
	}
}

func (r *RePersist) reinstall(method PersistenceMethod) {
	log.Printf("Reinstalling persistence: %s", method.ID)

	if method.ReinstallFunc != nil {
		if err := method.ReinstallFunc(); err != nil {
			log.Printf("Failed to reinstall persistence %s: %v", method.ID, err)
			return
		}

		r.mu.Lock()
		m := r.persistenceMap[method.ID]
		m.Active = true
		m.LastCheck = time.Now()
		r.persistenceMap[method.ID] = m
		r.mu.Unlock()

		log.Printf("Successfully reinstalled persistence: %s", method.ID)
	}
}

func (r *RePersist) AddMethod(method PersistenceMethod) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.persistenceMap[method.ID] = method
}

func (r *RePersist) RemoveMethod(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.persistenceMap, id)
}

func (r *RePersist) MarkActive(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if method, exists := r.persistenceMap[id]; exists {
		method.Active = true
		method.LastCheck = time.Now()
		r.persistenceMap[id] = method
	}
}

func (r *RePersist) MarkInactive(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if method, exists := r.persistenceMap[id]; exists {
		method.Active = false
		r.persistenceMap[id] = method
	}
}

func (r *RePersist) GetMethods() []PersistenceMethod {
	r.mu.RLock()
	defer r.mu.RUnlock()

	methods := make([]PersistenceMethod, 0, len(r.persistenceMap))
	for _, m := range r.persistenceMap {
		methods = append(methods, m)
	}
	return methods
}

func (r *RePersist) GetActiveCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	count := 0
	for _, m := range r.persistenceMap {
		if m.Active {
			count++
		}
	}
	return count
}

func (r *RePersist) GetInactiveCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	count := 0
	for _, m := range r.persistenceMap {
		if !m.Active {
			count++
		}
	}
	return count
}
