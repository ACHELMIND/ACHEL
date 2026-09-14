package evidence

import (
	"time"
)

type EvidenceEntry struct {
	ID        string    `json:"id"`
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
	Timestamp time.Time `json:"timestamp"`
	Data      []byte    `json:"data"`
	Signature []byte    `json:"signature"`
}

type EvidenceCapture struct {
	ID        string            `json:"id"`
	Type      string            `json:"type"`
	Timestamp time.Time         `json:"timestamp"`
	Data      []byte            `json:"data"`
	Metadata  map[string]string `json:"metadata"`
	Hash      string            `json:"hash"`
}

type RedactPattern struct {
	Name    string
	Pattern string
	Replace string
}
