package smb_beacon

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type PeerToPeer struct {
	mu        sync.RWMutex
	id        string
	peers     map[string]*Peer
	messages  chan *P2PMessage
	running   bool
}

type Peer struct {
	ID        string
	Addr      string
	Port      int
	Connected bool
	LastSeen  time.Time
}

type P2PMessage struct {
	ID        string
	From      string
	To        string
	Type      string
	Payload   []byte
	Timestamp time.Time
}

func NewPeerToPeer() *PeerToPeer {
	return &PeerToPeer{
		id:       generateP2PID(),
		peers:    make(map[string]*Peer),
		messages: make(chan *P2PMessage, 100),
	}
}

func (p2p *PeerToPeer) Start() {
	p2p.mu.Lock()
	p2p.running = true
	p2p.mu.Unlock()

	go p2p.listen()
}

func (p2p *PeerToPeer) Stop() {
	p2p.mu.Lock()
	defer p2p.mu.Unlock()
	p2p.running = false
}

func (p2p *PeerToPeer) listen() {
	for {
		p2p.mu.RLock()
		running := p2p.running
		p2p.mu.RUnlock()

		if !running {
			return
		}

		time.Sleep(100 * time.Millisecond)
	}
}

func (p2p *PeerToPeer) Connect(addr string, port int) error {
	peerID := generateP2PID()

	peer := &Peer{
		ID:        peerID,
		Addr:      addr,
		Port:      port,
		Connected: true,
		LastSeen:  time.Now(),
	}

	p2p.mu.Lock()
	p2p.peers[peerID] = peer
	p2p.mu.Unlock()

	fmt.Printf("Connected to peer %s at %s:%d\n", peerID, addr, port)
	return nil
}

func (p2p *PeerToPeer) Disconnect(peerID string) {
	p2p.mu.Lock()
	defer p2p.mu.Unlock()

	if peer, exists := p2p.peers[peerID]; exists {
		peer.Connected = false
		delete(p2p.peers, peerID)
	}
}

func (p2p *PeerToPeer) SendMessage(to string, msgType string, payload []byte) error {
	p2p.mu.RLock()
	_, exists := p2p.peers[to]
	p2p.mu.RUnlock()

	if !exists {
		return fmt.Errorf("peer not found: %s", to)
	}

	msg := &P2PMessage{
		ID:        generateP2PID(),
		From:      p2p.id,
		To:        to,
		Type:      msgType,
		Payload:   payload,
		Timestamp: time.Now(),
	}

	select {
	case p2p.messages <- msg:
		return nil
	default:
		return fmt.Errorf("message queue full")
	}
}

func (p2p *PeerToPeer) ReceiveMessage() *P2PMessage {
	select {
	case msg := <-p2p.messages:
		return msg
	default:
		return nil
	}
}

func (p2p *PeerToPeer) GetPeers() []*Peer {
	p2p.mu.RLock()
	defer p2p.mu.RUnlock()

	peers := make([]*Peer, 0, len(p2p.peers))
	for _, peer := range p2p.peers {
		peers = append(peers, peer)
	}
	return peers
}

func (p2p *PeerToPeer) GetID() string {
	p2p.mu.RLock()
	defer p2p.mu.RUnlock()
	return p2p.id
}

func (p2p *PeerToPeer) IsRunning() bool {
	p2p.mu.RLock()
	defer p2p.mu.RUnlock()
	return p2p.running
}

func generateP2PID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
