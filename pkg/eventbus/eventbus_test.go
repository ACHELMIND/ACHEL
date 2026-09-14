package eventbus

import (
	"sync"
	"testing"
	"time"
)

func TestEventBusPublishSubscribe(t *testing.T) {
	eb := New("test-secret-key")
	defer eb.Stop()

	var received Event
	var wg sync.WaitGroup
	wg.Add(1)

	eb.Subscribe("c2.implant.registered.v1", func(event Event) error {
		received = event
		wg.Done()
		return nil
	})

	data := map[string]interface{}{
		"agent_id": "test-agent-1",
		"hostname": "target-host",
	}

	_, err := eb.Publish("c2.implant.registered.v1", "implant-1", "event", data)
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for event")
	}

	if received.ID == "" {
		t.Error("Expected event ID to be set")
	}
	if received.Source != "implant-1" {
		t.Errorf("Expected source 'implant-1', got '%s'", received.Source)
	}
	if received.Type != "event" {
		t.Errorf("Expected type 'event', got '%s'", received.Type)
	}
}

func TestEventBusWildcardSubscription(t *testing.T) {
	eb := New("test-secret-key")
	defer eb.Stop()

	var count int
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(3)

	eb.Subscribe("c2.*.*", func(event Event) error {
		mu.Lock()
		count++
		mu.Unlock()
		wg.Done()
		return nil
	})

	for i := 0; i < 3; i++ {
		eb.Publish("c2.implant.registered.v1", "test", "event", nil)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for events")
	}

	mu.Lock()
	defer mu.Unlock()
	if count != 3 {
		t.Errorf("Expected 3 events, got %d", count)
	}
}

func TestEventBusSignatureVerification(t *testing.T) {
	eb := New("test-secret-key")
	defer eb.Stop()

	event, err := eb.Publish("c2.implant.registered.v1", "test", "event", nil)
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	if !eb.VerifySignature(event) {
		t.Error("Expected valid signature")
	}

	event.Signature = "invalid"
	if eb.VerifySignature(event) {
		t.Error("Expected invalid signature")
	}
}

func TestEventBusMultipleHandlers(t *testing.T) {
	eb := New("test-secret-key")
	defer eb.Stop()

	var count int
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(2)

	eb.Subscribe("c2.implant.*", func(event Event) error {
		mu.Lock()
		count++
		mu.Unlock()
		wg.Done()
		return nil
	})

	eb.Subscribe("c2.implant.*", func(event Event) error {
		mu.Lock()
		count++
		mu.Unlock()
		wg.Done()
		return nil
	})

	eb.Publish("c2.implant.registered.v1", "test", "event", nil)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for events")
	}

	mu.Lock()
	defer mu.Unlock()
	if count != 2 {
		t.Errorf("Expected 2 handlers to fire, got %d", count)
	}
}

func TestEventBusEventLog(t *testing.T) {
	eb := New("test-secret-key")
	defer eb.Stop()

	for i := 0; i < 5; i++ {
		eb.Publish("c2.implant.registered.v1", "test", "event", nil)
	}

	if eb.GetEventCount() != 5 {
		t.Errorf("Expected 5 events in log, got %d", eb.GetEventCount())
	}

	log := eb.GetEventLog()
	if len(log) != 5 {
		t.Errorf("Expected 5 events in log, got %d", len(log))
	}
}

func TestEventBusTopicMatching(t *testing.T) {
	tests := []struct {
		actual  string
		pattern string
		want    bool
	}{
		{"c2.implant.registered.v1", "c2.implant.registered.v1", true},
		{"c2.implant.registered.v1", "c2.*.registered.v1", true},
		{"c2.implant.registered.v1", "c2.implant.*", true},
		{"c2.implant.registered.v1", "c2.*.*", true},
		{"c2.implant.registered.v1", "*", true},
		{"c2.implant.registered.v1", "c2.listener.*", false},
		{"exploit.sqli.result.v1", "c2.*.*", false},
	}

	eb := New("test")
	defer eb.Stop()

	for _, tt := range tests {
		got := eb.matchTopic(tt.actual, tt.pattern)
		if got != tt.want {
			t.Errorf("matchTopic(%q, %q) = %v, want %v", tt.actual, tt.pattern, got, tt.want)
		}
	}
}
