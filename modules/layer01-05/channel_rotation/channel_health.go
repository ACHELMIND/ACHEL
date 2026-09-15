package channel_rotation

import (
	"sync"
	"time"
)

type ChannelHealth struct {
	mu        sync.RWMutex
	channels  map[string]*HealthStatus
}

type HealthStatus struct {
	ChannelID   string
	Healthy     bool
	LastCheck   time.Time
	Latency     time.Duration
	ErrorCount  int
	SuccessRate float64
}

func NewChannelHealth() *ChannelHealth {
	return &ChannelHealth{
		channels: make(map[string]*HealthStatus),
	}
}

func (ch *ChannelHealth) Update(channelID string, healthy bool, latency time.Duration) {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	if status, exists := ch.channels[channelID]; exists {
		status.Healthy = healthy
		status.LastCheck = time.Now()
		status.Latency = latency

		if !healthy {
			status.ErrorCount++
		} else {
			status.ErrorCount = 0
		}

		totalChecks := float64(status.ErrorCount + 1)
		if healthy {
			status.SuccessRate = (status.SuccessRate * (totalChecks - 1) + 1) / totalChecks
		} else {
			status.SuccessRate = (status.SuccessRate * (totalChecks - 1)) / totalChecks
		}
	} else {
		ch.channels[channelID] = &HealthStatus{
			ChannelID:   channelID,
			Healthy:     healthy,
			LastCheck:   time.Now(),
			Latency:     latency,
			ErrorCount:  0,
			SuccessRate: 1.0,
		}
	}
}

func (ch *ChannelHealth) IsHealthy(channelID string) bool {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	if status, exists := ch.channels[channelID]; exists {
		return status.Healthy
	}
	return false
}

func (ch *ChannelHealth) GetStatus(channelID string) *HealthStatus {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	return ch.channels[channelID]
}

func (ch *ChannelHealth) GetAllStatuses() map[string]*HealthStatus {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	statuses := make(map[string]*HealthStatus)
	for id, status := range ch.channels {
		statuses[id] = status
	}
	return statuses
}

func (ch *ChannelHealth) GetBestChannel() string {
	ch.mu.RLock()
	defer ch.mu.RUnlock()

	var bestChannel string
	var bestScore float64

	for id, status := range ch.channels {
		if status.Healthy {
			score := status.SuccessRate * (1.0 / (1.0 + status.Latency.Seconds()))
			if score > bestScore {
				bestScore = score
				bestChannel = id
			}
		}
	}

	return bestChannel
}

func (ch *ChannelHealth) MarkUnhealthy(channelID string) {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	if status, exists := ch.channels[channelID]; exists {
		status.Healthy = false
		status.ErrorCount++
	}
}

func (ch *ChannelHealth) MarkHealthy(channelID string) {
	ch.mu.Lock()
	defer ch.mu.Unlock()

	if status, exists := ch.channels[channelID]; exists {
		status.Healthy = true
		status.ErrorCount = 0
	}
}
