package resilience

import (
	"log"
	"sync"
	"time"
)

type ReHarvest struct {
	mu            sync.RWMutex
	harvestTargets map[string]HarvestTarget
	running       bool
	stopCh        chan struct{}
	interval      time.Duration
}

type HarvestTarget struct {
	ID           string
	Type         string
	Location     string
	LastHarvest  time.Time
	HarvestFunc  func() ([]byte, error)
}

func NewReHarvest(interval time.Duration) *ReHarvest {
	return &ReHarvest{
		harvestTargets: make(map[string]HarvestTarget),
		stopCh:        make(chan struct{}),
		interval:      interval,
	}
}

func (rh *ReHarvest) Start() {
	rh.mu.Lock()
	rh.running = true
	rh.mu.Unlock()

	go rh.monitorLoop()
}

func (rh *ReHarvest) Stop() {
	rh.mu.Lock()
	rh.running = false
	rh.mu.Unlock()
	close(rh.stopCh)
}

func (rh *ReHarvest) monitorLoop() {
	ticker := time.NewTicker(rh.interval)
	defer ticker.Stop()

	for {
		select {
		case <-rh.stopCh:
			return
		case <-ticker.C:
			rh.harvestAll()
		}
	}
}

func (rh *ReHarvest) harvestAll() {
	rh.mu.RLock()
	targets := make([]HarvestTarget, 0, len(rh.harvestTargets))
	for _, t := range rh.harvestTargets {
		targets = append(targets, t)
	}
	rh.mu.RUnlock()

	for _, target := range targets {
		rh.harvest(target)
	}
}

func (rh *ReHarvest) harvest(target HarvestTarget) {
	if target.HarvestFunc == nil {
		return
	}

	data, err := target.HarvestFunc()
	if err != nil {
		log.Printf("Failed to harvest target %s: %v", target.ID, err)
		return
	}

	log.Printf("Harvested %d bytes from target %s", len(data), target.ID)

	rh.mu.Lock()
	t := rh.harvestTargets[target.ID]
	t.LastHarvest = time.Now()
	rh.harvestTargets[target.ID] = t
	rh.mu.Unlock()
}

func (rh *ReHarvest) AddTarget(target HarvestTarget) {
	rh.mu.Lock()
	defer rh.mu.Unlock()
	rh.harvestTargets[target.ID] = target
}

func (rh *ReHarvest) RemoveTarget(id string) {
	rh.mu.Lock()
	defer rh.mu.Unlock()
	delete(rh.harvestTargets, id)
}

func (rh *ReHarvest) GetTargets() []HarvestTarget {
	rh.mu.RLock()
	defer rh.mu.RUnlock()

	targets := make([]HarvestTarget, 0, len(rh.harvestTargets))
	for _, t := range rh.harvestTargets {
		targets = append(targets, t)
	}
	return targets
}

func (rh *ReHarvest) GetTarget(id string) *HarvestTarget {
	rh.mu.RLock()
	defer rh.mu.RUnlock()

	target, exists := rh.harvestTargets[id]
	if !exists {
		return nil
	}
	return &target
}

func (rh *ReHarvest) IsRunning() bool {
	rh.mu.RLock()
	defer rh.mu.RUnlock()
	return rh.running
}
