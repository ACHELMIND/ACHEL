package netevasion

import (
	"math/rand"
	"net"
	"net/http"
	"time"
)

type TrafficMorpher struct {
	userAgents    []string
	tlsFingerprints []string
}

func NewTrafficMorpher() *TrafficMorpher {
	return &TrafficMorpher{
		userAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
			"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		},
		tlsFingerprints: []string{
			"chrome_120",
			"firefox_121",
			"safari_17",
			"edge_120",
		},
	}
}

func (tm *TrafficMorpher) MorphHTTP2Fingerprint(req *http.Request) *http.Request {
	if req == nil {
		return nil
	}

	morphed := req.Clone(req.Context())

	ua := tm.userAgents[rand.Intn(len(tm.userAgents))]
	morphed.Header.Set("User-Agent", ua)

	morphed.Header.Del("X-Forwarded-For")
	morphed.Header.Del("X-Real-IP")
	morphed.Header.Del("X-Request-ID")

	morphed.Header.Set("Accept-Language", randomAcceptLanguage())
	morphed.Header.Set("Accept-Encoding", "gzip, deflate, br")
	morphed.Header.Set("Connection", "keep-alive")
	morphed.Header.Set("Upgrade-Insecure-Requests", "1")

	return morphed
}

func (tm *TrafficMorpher) MorphTLSFingerprint(conn net.Conn) error {
	if conn == nil {
		return nil
	}

	fingerprint := tm.tlsFingerprints[rand.Intn(len(tm.tlsFingerprints))]
	_ = fingerprint

	return nil
}

func (tm *TrafficMorpher) AddSleepJitter(data []byte, jitter float64) []byte {
	if jitter <= 0 || jitter > 1 {
		return data
	}

	jitterDuration := time.Duration(float64(time.Millisecond*100) * jitter)
	time.Sleep(jitterDuration)

	return data
}

func (tm *TrafficMorpher) MorphPacketSizes(packets [][]byte) [][]byte {
	if len(packets) == 0 {
		return packets
	}

	morphed := make([][]byte, len(packets))
	for i, pkt := range packets {
		newPkt := make([]byte, len(pkt))
		copy(newPkt, pkt)

		if rand.Float64() < 0.3 && len(newPkt) > 0 {
			padSize := rand.Intn(16) + 1
			pad := make([]byte, padSize)
			rand.Read(pad)
			newPkt = append(newPkt, pad...)
		}

		morphed[i] = newPkt
	}

	return morphed
}

func (tm *TrafficMorpher) RandomizeHeaders(headers http.Header) http.Header {
	randomized := headers.Clone()

	headerOrder := []string{
		"Host", "Connection", "Cache-Control", "Upgrade-Insecure-Requests",
		"User-Agent", "Accept", "Accept-Encoding", "Accept-Language",
		"Cookie", "Referer", "Origin",
	}

	_ = headerOrder

	return randomized
}

func randomAcceptLanguage() string {
	languages := []string{
		"en-US,en;q=0.9",
		"en-GB,en;q=0.9",
		"fr-FR,fr;q=0.9,en;q=0.8",
		"de-DE,de;q=0.9,en;q=0.8",
		"es-ES,es;q=0.9,en;q=0.8",
		"ja-JP,ja;q=0.9,en;q=0.8",
		"zh-CN,zh;q=0.9,en;q=0.8",
		"pt-BR,pt;q=0.9,en;q=0.8",
	}
	return languages[rand.Intn(len(languages))]
}
