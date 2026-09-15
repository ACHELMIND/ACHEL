package rpg

import (
	"fmt"
	"log"
	"sync"
	"time"
)

type BroadcastManager struct {
	channels map[string]*Channel
	mu       sync.RWMutex
}

type Channel struct {
	ID       string
	Name     string
	Members  map[string]*Player
	Messages chan *Message
	mu       sync.RWMutex
}

type Player struct {
	ID       string
	Name     string
	Level    int
	Faction  string
	Channel  string
	LastSeen time.Time
}

type Message struct {
	ID        string    `json:"id"`
	ChannelID string    `json:"channel_id"`
	SenderID  string    `json:"sender_id"`
	Content   string    `json:"content"`
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
}

type BroadcastEvent struct {
	Type      string      `json:"type"`
	ChannelID string      `json:"channel_id"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

func NewBroadcastManager() *BroadcastManager {
	return &BroadcastManager{
		channels: make(map[string]*Channel),
	}
}

func (m *BroadcastManager) CreateChannel(id, name string) *Channel {
	m.mu.Lock()
	defer m.mu.Unlock()

	channel := &Channel{
		ID:       id,
		Name:     name,
		Members:  make(map[string]*Player),
		Messages: make(chan *Message, 100),
	}

	m.channels[id] = channel
	return channel
}

func (m *BroadcastManager) GetChannel(id string) (*Channel, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ch, exists := m.channels[id]
	return ch, exists
}

func (m *BroadcastManager) JoinChannel(channelID string, player *Player) error {
	m.mu.RLock()
	ch, exists := m.channels[channelID]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("channel not found: %s", channelID)
	}

	ch.mu.Lock()
	defer ch.mu.Unlock()

	ch.Members[player.ID] = player
	player.Channel = channelID

	log.Printf("Player %s joined channel %s", player.Name, ch.Name)
	return nil
}

func (m *BroadcastManager) LeaveChannel(channelID, playerID string) error {
	m.mu.RLock()
	ch, exists := m.channels[channelID]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("channel not found: %s", channelID)
	}

	ch.mu.Lock()
	defer ch.mu.Unlock()

	if player, ok := ch.Members[playerID]; ok {
		delete(ch.Members, playerID)
		player.Channel = ""
		log.Printf("Player %s left channel %s", player.Name, ch.Name)
	}

	return nil
}

func (m *BroadcastManager) Broadcast(channelID, senderID, content, msgType string) error {
	m.mu.RLock()
	ch, exists := m.channels[channelID]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("channel not found: %s", channelID)
	}

	msg := &Message{
		ID:        generateID(),
		ChannelID: channelID,
		SenderID:  senderID,
		Content:   content,
		Type:      msgType,
		Timestamp: time.Now(),
	}

	select {
	case ch.Messages <- msg:
		log.Printf("Broadcast sent to channel %s: %s", ch.Name, content)
		return nil
	default:
		return fmt.Errorf("message queue full for channel %s", channelID)
	}
}

func (m *BroadcastManager) GetPlayers(channelID string) []*Player {
	m.mu.RLock()
	ch, exists := m.channels[channelID]
	m.mu.RUnlock()

	if !exists {
		return nil
	}

	ch.mu.RLock()
	defer ch.mu.RUnlock()

	players := make([]*Player, 0, len(ch.Members))
	for _, p := range ch.Members {
		players = append(players, p)
	}

	return players
}

func (m *BroadcastManager) SendToPlayer(playerID, content string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, ch := range m.channels {
		ch.mu.RLock()
		if _, ok := ch.Members[playerID]; ok {
			ch.mu.RUnlock()
			return m.Broadcast(ch.ID, "SYSTEM", content, "direct")
		}
		ch.mu.RUnlock()
	}

	return fmt.Errorf("player not found in any channel")
}

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func (m *BroadcastManager) StartListening(channelID string, handler func(*Message)) {
	m.mu.RLock()
	ch, exists := m.channels[channelID]
	m.mu.RUnlock()

	if !exists {
		return
	}

	go func() {
		for msg := range ch.Messages {
			handler(msg)
		}
	}()
}

func (m *BroadcastManager) BroadcastToAll(content, msgType string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, ch := range m.channels {
		_ = m.Broadcast(ch.ID, "SYSTEM", content, msgType)
	}
}

type EventHandler func(event *BroadcastEvent)

type EventBroadcaster struct {
	subscribers map[string][]EventHandler
	mu          sync.RWMutex
}

func NewEventBroadcaster() *EventBroadcaster {
	return &EventBroadcaster{
		subscribers: make(map[string][]EventHandler),
	}
}

func (b *EventBroadcaster) Subscribe(eventType string, handler EventHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.subscribers[eventType] = append(b.subscribers[eventType], handler)
}

func (b *EventBroadcaster) Publish(event *BroadcastEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if handlers, ok := b.subscribers[event.Type]; ok {
		for _, handler := range handlers {
			go handler(event)
		}
	}
}

type GameState struct {
	Players    map[string]*Player
	Vehicles   map[string]*Vehicle
	Buildings  map[string]*Building
	Factions   map[string]*Faction
	mu         sync.RWMutex
}

type Vehicle struct {
	ID      string
	Model   int
	OwnerID string
	Pos     Position
}

type Building struct {
	ID      string
	Name    string
	Type    string
	OwnerID string
	Pos     Position
}

type Faction struct {
	ID      string
	Name    string
	Leader  string
	Members []string
}

type Position struct {
	X, Y, Z float64
}

func NewGameState() *GameState {
	return &GameState{
		Players:  make(map[string]*Player),
		Vehicles: make(map[string]*Vehicle),
		Buildings: make(map[string]*Building),
		Factions: make(map[string]*Faction),
	}
}

func (s *GameState) AddPlayer(player *Player) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Players[player.ID] = player
}

func (s *GameState) RemovePlayer(playerID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.Players, playerID)
}

func (s *GameState) GetPlayer(playerID string) (*Player, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.Players[playerID]
	return p, ok
}
