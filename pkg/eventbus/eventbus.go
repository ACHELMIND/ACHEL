package eventbus

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Event struct {
	ID        string                 `json:"id"`
	Topic     string                 `json:"topic"`
	Timestamp string                 `json:"timestamp"`
	Source    string                 `json:"source"`
	Dest      string                 `json:"dest"`
	Type      string                 `json:"type"`
	Priority  int                    `json:"priority"`
	Data      map[string]interface{} `json:"data"`
	TraceID   string                 `json:"trace_id"`
	Signature string                 `json:"signature,omitempty"`
}

type Handler func(event Event) error

type Subscription struct {
	Topic     string
	Handler   Handler
	QueueSize int
}

type EventBus struct {
	mu           sync.RWMutex
	subscribers  map[string][]*Subscription
	hmacKey      []byte
	eventLog     []Event
	eventMu      sync.Mutex
	purger      *time.Ticker
	stopPurger   chan struct{}
}

func New(hmacKey string) *EventBus {
	eb := &EventBus{
		subscribers: make(map[string][]*Subscription),
		hmacKey:     []byte(hmacKey),
		stopPurger:  make(chan struct{}),
	}
	eb.purger = time.NewTicker(24 * time.Hour)
	go func() {
		for {
			select {
			case <-eb.purger.C:
				eb.purgeOldEvents()
			case <-eb.stopPurger:
				return
			}
		}
	}()
	return eb
}

func (eb *EventBus) Stop() {
	close(eb.stopPurger)
	eb.purger.Stop()
}

func (eb *EventBus) Publish(topic string, source string, eventType string, data map[string]interface{}) (*Event, error) {
	event := &Event{
		ID:        uuid.New().String(),
		Topic:     topic,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Source:    source,
		Dest:      "*",
		Type:      eventType,
		Priority:  50,
		Data:      data,
		TraceID:   uuid.New().String(),
	}

	sig, err := eb.signEvent(event)
	if err != nil {
		return nil, fmt.Errorf("sign event: %w", err)
	}
	event.Signature = sig

	eb.eventMu.Lock()
	eb.eventLog = append(eb.eventLog, *event)
	eb.eventMu.Unlock()

	eb.mu.RLock()
	defer eb.mu.RUnlock()

	for topicPattern, handlers := range eb.subscribers {
		if eb.matchTopic(topic, topicPattern) {
			for _, sub := range handlers {
				go func(h Handler, e Event) {
					_ = h(e)
				}(sub.Handler, *event)
			}
		}
	}

	return event, nil
}

func (eb *EventBus) Subscribe(topic string, handler Handler) *Subscription {
	sub := &Subscription{
		Topic:     topic,
		Handler:   handler,
		QueueSize: 100,
	}

	eb.mu.Lock()
	defer eb.mu.Unlock()
	eb.subscribers[topic] = append(eb.subscribers[topic], sub)
	return sub
}

func (eb *EventBus) matchTopic(actual, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if actual == pattern {
		return true
	}
	patternParts := splitTopic(pattern)
	actualParts := splitTopic(actual)
	if len(patternParts) > len(actualParts) {
		return false
	}
	for i, p := range patternParts {
		if p == "*" {
			return true
		}
		if p == actualParts[i] {
			continue
		}
		return false
	}
	return len(patternParts) == len(actualParts)
}

func splitTopic(topic string) []string {
	var parts []string
	current := ""
	for _, c := range topic {
		if c == '.' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	parts = append(parts, current)
	return parts
}

func (eb *EventBus) signEvent(event *Event) (string, error) {
	data, err := json.Marshal(map[string]string{
		"id":        event.ID,
		"topic":     event.Topic,
		"timestamp": event.Timestamp,
		"source":    event.Source,
		"type":      event.Type,
	})
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, eb.hmacKey)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (eb *EventBus) VerifySignature(event *Event) bool {
	expected, err := eb.signEvent(event)
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(event.Signature), []byte(expected))
}

func (eb *EventBus) purgeOldEvents() {
	eb.eventMu.Lock()
	defer eb.eventMu.Unlock()
	cutoff := time.Now().Add(-30 * 24 * time.Hour)
	var filtered []Event
	for _, e := range eb.eventLog {
		ts, err := time.Parse(time.RFC3339, e.Timestamp)
		if err != nil {
			continue
		}
		if ts.After(cutoff) {
			filtered = append(filtered, e)
		}
	}
	eb.eventLog = filtered
}

func (eb *EventBus) GetEventLog() []Event {
	eb.eventMu.Lock()
	defer eb.eventMu.Unlock()
	result := make([]Event, len(eb.eventLog))
	copy(result, eb.eventLog)
	return result
}

func (eb *EventBus) GetEventCount() int {
	eb.eventMu.Lock()
	defer eb.eventMu.Unlock()
	return len(eb.eventLog)
}
