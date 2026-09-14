package osint

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
)

type PortScanner struct {
	config *OSINTConfig
	log    *logger.Logger
	mu     sync.RWMutex
}

func NewPortScanner(config *OSINTConfig) *PortScanner {
	return &PortScanner{
		config: config,
		log:    logger.New("port-scanner", logger.LevelInfo),
	}
}

func (p *PortScanner) TCPScan(host string, ports []int) ([]OpenPort, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.log.Info("Starting TCP scan on %s (%d ports)", host, len(ports))

	openPorts := make([]OpenPort, 0)

	if net.ParseIP(host) == nil {
		ips, err := net.LookupHost(host)
		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed: %w", err)
		}
		if len(ips) > 0 {
			host = ips[0]
		}
	}

	concurrency := p.config.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 50
	}

	portCh := make(chan int, concurrency)
	resultCh := make(chan OpenPort, len(ports))

	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portCh {
				addr := fmt.Sprintf("%s:%d", host, port)
				conn, err := net.DialTimeout("tcp", addr, p.config.Timeout)
				if err == nil {
					conn.Close()
					service := guessService(port)
					resultCh <- OpenPort{
						Port:    port,
						State:   "open",
						Service: service,
					}
				}
			}
		}()
	}

	for _, port := range ports {
		portCh <- port
	}
	close(portCh)

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	for result := range resultCh {
		openPorts = append(openPorts, result)
	}

	p.log.Info("Found %d open ports on %s", len(openPorts), host)
	return openPorts, nil
}

func (p *PortScanner) ServiceFingerprint(host string, port int) (*ServiceInfo, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", addr, p.config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	service := guessService(port)
	version := ""

	return &ServiceInfo{
		Port:    port,
		Service: service,
		Version: version,
	}, nil
}

func (p *PortScanner) BannerGrab(host string, port int) (string, error) {
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", addr, p.config.Timeout)
	if err != nil {
		return "", fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(p.config.Timeout))

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("read failed: %w", err)
	}

	banner := strings.TrimSpace(string(buffer[:n]))
	return banner, nil
}

func (p *PortScanner) ScanRange(host string, startPort, endPort int) ([]OpenPort, error) {
	ports := make([]int, 0, endPort-startPort+1)
	for i := startPort; i <= endPort; i++ {
		ports = append(ports, i)
	}
	return p.TCPScan(host, ports)
}

func (p *PortScanner) IsPortOpen(host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func guessService(port int) string {
	services := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
		53: "dns", 80: "http", 110: "pop3", 111: "rpc",
		135: "msrpc", 139: "netbios", 143: "imap",
		443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
		1433: "mssql", 1521: "oracle", 2049: "nfs",
		3306: "mysql", 3389: "rdp", 5432: "postgresql",
		5900: "vnc", 6379: "redis", 8080: "http-proxy",
		8443: "https-alt", 8888: "http-alt",
		9200: "elasticsearch", 9300: "elasticsearch",
		27017: "mongodb",
	}
	if svc, ok := services[port]; ok {
		return svc
	}
	return "unknown"
}
