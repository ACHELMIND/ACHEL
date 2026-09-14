package osint

import (
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
)

type OSINTEngine struct {
	config    *OSINTConfig
	log       *logger.Logger
	mu        sync.RWMutex
	dnsRecon  *DNSRecon
	portScan  *PortScanner
	webRecon  *WebRecon
	personRecon *PersonRecon
	cloudRecon  *CloudRecon
}

func NewOSINTEngine(config *OSINTConfig) *OSINTEngine {
	if config == nil {
		config = DefaultOSINTConfig()
	}

	e := &OSINTEngine{
		config:      config,
		log:         logger.New("osint-engine", logger.LevelInfo),
		dnsRecon:    NewDNSRecon(config),
		portScan:    NewPortScanner(config),
		webRecon:    NewWebRecon(config),
		personRecon: NewPersonRecon(config),
		cloudRecon:  NewCloudRecon(config),
	}

	return e
}

func (e *OSINTEngine) Recon(target string) (*ReconResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.log.Info("Starting recon for target: %s", target)
	start := time.Now()

	result := &ReconResult{
		Target:    target,
		Timestamp: start,
	}

	dnsResult, err := e.dnsRecon.FullDNSRecon(target)
	if err != nil {
		e.log.Warn("DNS recon failed: %v", err)
	} else {
		result.DNS = dnsResult
	}

	openPorts, err := e.portScan.TCPScan(target, e.config.Ports)
	if err != nil {
		e.log.Warn("Port scan failed: %v", err)
	} else {
		result.Ports = openPorts
	}

	webResult, err := e.webRecon.ReconWeb(target)
	if err != nil {
		e.log.Warn("Web recon failed: %v", err)
	} else {
		result.Web = webResult
	}

	e.log.Info("Recon completed for %s in %v", target, time.Since(start))
	return result, nil
}

func (e *OSINTEngine) FullRecon(target string) (*FullReconResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.log.Info("Starting full recon for target: %s", target)
	start := time.Now()

	result := &FullReconResult{
		Target:    target,
		Timestamp: start,
	}

	dnsResult, err := e.dnsRecon.FullDNSRecon(target)
	if err != nil {
		e.log.Warn("DNS recon failed: %v", err)
	} else {
		result.DNS = dnsResult
	}

	openPorts, err := e.portScan.TCPScan(target, e.config.Ports)
	if err != nil {
		e.log.Warn("Port scan failed: %v", err)
	} else {
		result.Ports = openPorts
	}

	services := make([]ServiceInfo, 0)
	for _, port := range openPorts {
		info, err := e.portScan.ServiceFingerprint(target, port.Port)
		if err == nil {
			services = append(services, *info)
		}
	}
	result.Services = services

	webResult, err := e.webRecon.ReconWeb(target)
	if err != nil {
		e.log.Warn("Web recon failed: %v", err)
	} else {
		result.Web = webResult
	}

	personResult, err := e.personRecon.ReconPerson(target)
	if err != nil {
		e.log.Warn("Person recon failed: %v", err)
	} else {
		result.Person = personResult
	}

	cloudResult, err := e.cloudRecon.ReconCloud(target)
	if err != nil {
		e.log.Warn("Cloud recon failed: %v", err)
	} else {
		result.Cloud = cloudResult
	}

	e.log.Info("Full recon completed for %s in %v", target, time.Since(start))
	return result, nil
}

func (e *OSINTEngine) SetLoggerLevel(level logger.Level) {
	e.log.SetLevel(level)
}

func (e *OSINTEngine) GetStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return map[string]interface{}{
		"target":          e.config.Target,
		"timeout":         e.config.Timeout,
		"max_concurrency": e.config.MaxConcurrency,
		"ports_count":     len(e.config.Ports),
	}
}
