package channel_rotation

import (
	"log"
	"sync"
	"time"
)

type FailoverLogic struct {
	mu            sync.RWMutex
	channels      []FailoverChannel
	currentIndex  int
	healthCheck   *ChannelHealth
	failoverTimer *time.Timer
	autoFailover  bool
}

type FailoverChannel struct {
	ID       string
	Type     string
	Addr     string
	Port     int
	Priority int
}

func NewFailoverLogic() *FailoverLogic {
	return &FailoverLogic{
		channels:     make([]FailoverChannel, 0),
		healthCheck:  NewChannelHealth(),
		autoFailover: true,
	}
}

func (f *FailoverLogic) AddChannel(channel FailoverChannel) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.channels = append(f.channels, channel)
}

func (f *FailoverLogic) RemoveChannel(channelID string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for i, ch := range f.channels {
		if ch.ID == channelID {
			f.channels = append(f.channels[:i], f.channels[i+1:]...)
			break
		}
	}
}

func (f *FailoverLogic) GetCurrentChannel() *FailoverChannel {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if len(f.channels) == 0 {
		return nil
	}

	return &f.channels[f.currentIndex]
}

func (f *FailoverLogic) Failover() *FailoverChannel {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.channels) == 0 {
		return nil
	}

	for i, ch := range f.channels {
		if f.healthCheck.IsHealthy(ch.ID) {
			f.currentIndex = i
			log.Printf("Failover to channel: %s (%s)", ch.ID, ch.Type)
			return &ch
		}
	}

	log.Println("No healthy channels available for failover")
	return nil
}

func (f *FailoverLogic) CheckAndFailover() *FailoverChannel {
	if !f.autoFailover {
		return f.GetCurrentChannel()
	}

	current := f.GetCurrentChannel()
	if current != nil && f.healthCheck.IsHealthy(current.ID) {
		return current
	}

	return f.Failover()
}

func (f *FailoverLogic) StartAutoFailover(interval time.Duration) {
	f.mu.Lock()
	f.failoverTimer = time.NewTimer(interval)
	f.mu.Unlock()

	go func() {
		for {
			select {
			case <-f.failoverTimer.C:
				f.CheckAndFailover()
				f.failoverTimer.Reset(interval)
			}
		}
	}()
}

func (f *FailoverLogic) StopAutoFailover() {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.failoverTimer != nil {
		f.failoverTimer.Stop()
	}
}

func (f *FailoverLogic) GetHealthCheck() *ChannelHealth {
	return f.healthCheck
}

func (f *FailoverLogic) SetAutoFailover(enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.autoFailover = enabled
}

func (f *FailoverLogic) GetChannelCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.channels)
}

func (f *FailoverLogic) GetHealthyChannelCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()

	count := 0
	for _, ch := range f.channels {
		if f.healthCheck.IsHealthy(ch.ID) {
			count++
		}
	}
	return count
}
