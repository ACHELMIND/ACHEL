package channel_rotation

import (
	"log"
	"sync"
	"time"
)

type ChannelRotation struct {
	mu            sync.RWMutex
	channels      []Channel
	currentIndex  int
	failoverTimer *time.Timer
	healthChecks  map[string]bool
}

type Channel struct {
	ID       string
	Type     string
	Addr     string
	Port     int
	Status   string
	Priority int
}

func NewChannelRotation() *ChannelRotation {
	return &ChannelRotation{
		channels: make([]Channel, 0),
		healthChecks: make(map[string]bool),
	}
}

func (cr *ChannelRotation) AddChannel(channel Channel) {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	cr.channels = append(cr.channels, channel)
	cr.healthChecks[channel.ID] = true
}

func (cr *ChannelRotation) RemoveChannel(channelID string) {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	for i, ch := range cr.channels {
		if ch.ID == channelID {
			cr.channels = append(cr.channels[:i], cr.channels[i+1:]...)
			delete(cr.healthChecks, channelID)
			break
		}
	}
}

func (cr *ChannelRotation) GetCurrentChannel() *Channel {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	if len(cr.channels) == 0 {
		return nil
	}

	return &cr.channels[cr.currentIndex]
}

func (cr *ChannelRotation) Rotate() *Channel {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	if len(cr.channels) == 0 {
		return nil
	}

	cr.currentIndex = (cr.currentIndex + 1) % len(cr.channels)
	channel := &cr.channels[cr.currentIndex]

	log.Printf("Rotated to channel: %s (%s)", channel.ID, channel.Type)
	return channel
}

func (cr *ChannelRotation) Failover() *Channel {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	for i, ch := range cr.channels {
		if cr.healthChecks[ch.ID] {
			cr.currentIndex = i
			log.Printf("Failover to channel: %s (%s)", ch.ID, ch.Type)
			return &ch
		}
	}

	log.Println("No healthy channels available")
	return nil
}

func (cr *ChannelRotation) CheckHealth(channelID string) bool {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return cr.healthChecks[channelID]
}

func (cr *ChannelRotation) SetHealth(channelID string, healthy bool) {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	cr.healthChecks[channelID] = healthy
}

func (cr *ChannelRotation) GetHealthyChannels() []Channel {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	var healthy []Channel
	for _, ch := range cr.channels {
		if cr.healthChecks[ch.ID] {
			healthy = append(healthy, ch)
		}
	}
	return healthy
}

func (cr *ChannelRotation) StartHealthCheck(interval time.Duration) {
	cr.mu.Lock()
	cr.failoverTimer = time.NewTimer(interval)
	cr.mu.Unlock()

	go func() {
		for {
			select {
			case <-cr.failoverTimer.C:
				cr.performHealthCheck()
				cr.failoverTimer.Reset(interval)
			}
		}
	}()
}

func (cr *ChannelRotation) performHealthCheck() {
	cr.mu.RLock()
	channels := make([]Channel, len(cr.channels))
	copy(channels, cr.channels)
	cr.mu.RUnlock()

	for _, ch := range channels {
		healthy := cr.checkChannelHealth(ch)
		cr.SetHealth(ch.ID, healthy)
	}
}

func (cr *ChannelRotation) checkChannelHealth(ch Channel) bool {
	return true
}

func (cr *ChannelRotation) GetChannelCount() int {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return len(cr.channels)
}
