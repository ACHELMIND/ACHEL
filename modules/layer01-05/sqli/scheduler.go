package sqli

import (
	"sort"
	"sync"
	"time"
)

type Scheduler struct {
	engine    *SQLiEngine
	techniqueQueue []*Technique
	mu        sync.RWMutex
}

func NewScheduler(engine *SQLiEngine) *Scheduler {
	return &Scheduler{
		engine:         engine,
		techniqueQueue: make([]*Technique, 0),
	}
}

func (s *Scheduler) ScheduleTechniques(target string) []*Technique {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.techniqueQueue = make([]*Technique, 0)

	priorities := map[InjectionType]int{
		InjectionErrorBased:   1,
		InjectionUnionBased:   2,
		InjectionBooleanBlind: 3,
		InjectionTimeBased:    4,
		InjectionStacked:      5,
		InjectionOOBDNS:      6,
		InjectionOOBHTTP:     7,
		InjectionOOBICMP:     8,
	}

	enabled := make(map[InjectionType]bool)
	for _, t := range s.engine.config.Techniques {
		enabled[t] = true
	}

	if len(enabled) == 0 {
		for _, t := range []InjectionType{
			InjectionErrorBased,
			InjectionUnionBased,
			InjectionBooleanBlind,
			InjectionTimeBased,
			InjectionStacked,
			InjectionOOBDNS,
			InjectionOOBHTTP,
			InjectionOOBICMP,
		} {
			enabled[t] = true
		}
	}

	for itype, priority := range priorities {
		if !enabled[itype] {
			continue
		}
		tech := &Technique{
			Name:     string(itype),
			Type:     itype,
			Priority: priority,
			Status:   TechniqueStatusPending,
		}
		s.techniqueQueue = append(s.techniqueQueue, tech)
	}

	sort.Slice(s.techniqueQueue, func(i, j int) bool {
		return s.techniqueQueue[i].Priority < s.techniqueQueue[j].Priority
	})

	return s.techniqueQueue
}

func (s *Scheduler) RunWithFallback(target string) (*ScanResult, error) {
	s.engine.logger.Info("Running detection with fallback on target: %s", target)

	result := &ScanResult{
		Target:    target,
		StartTime: time.Now(),
	}

	techniques := s.ScheduleTechniques(target)
	if len(techniques) == 0 {
		s.engine.logger.Warn("No techniques scheduled")
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		return result, nil
	}

	params := s.engine.config.Params
	if len(params) == 0 {
		params = s.engine.detectParameters(target)
	}

	foundInjection := false

	for _, tech := range techniques {
		if foundInjection && tech.Priority > 4 {
			tech.Status = TechniqueStatusSkipped
			result.AddTechnique(tech)
			continue
		}

		detector, ok := s.engine.detectors[tech.Type]
		if !ok {
			tech.Status = TechniqueStatusSkipped
			result.AddTechnique(tech)
			continue
		}

		tech.Status = TechniqueStatusRunning
		start := time.Now()

		detectionResult, err := detector.Detect(target, params)
		tech.Duration = time.Since(start)

		if err != nil {
			tech.Status = TechniqueStatusFailed
			tech.Error = err.Error()
			s.engine.logger.Error("Technique %s failed: %v", tech.Name, err)
			result.AddTechnique(tech)
			continue
		}

		if detectionResult.Found {
			tech.Status = TechniqueStatusCompleted
			tech.Result = detectionResult
			result.AddTechnique(tech)

			dbms := s.engine.fingerprintDBMS(target, params[0], detectionResult)
			pt := &InjectionPoint{
				URL:           target,
				Parameter:     params[0],
				Location:      ParamQuery,
				InjectionType: detectionResult.Type,
				DBMS:          dbms,
				Payload:       detectionResult.Payload,
				Evidence:      detectionResult.Evidence,
				Confidence:    detectionResult.Confidence,
				Severity:      detectionResult.Severity,
				Details:       detectionResult.Details,
			}
			result.AddInjectionPoint(pt)
			result.DBMS = dbms
			foundInjection = true

			s.engine.logger.Info("Technique %s found injection (confidence: %.2f)",
				tech.Name, detectionResult.Confidence)
		} else {
			tech.Status = TechniqueStatusCompleted
			tech.Result = detectionResult
			result.AddTechnique(tech)
		}
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	s.engine.logger.Info("Scan completed in %v, found %d injection points",
		result.Duration, len(result.InjectionPoints))

	return result, nil
}

func (s *Scheduler) GetQueue() []*Technique {
	s.mu.RLock()
	defer s.mu.RUnlock()
	queue := make([]*Technique, len(s.techniqueQueue))
	copy(queue, s.techniqueQueue)
	return queue
}

func (s *Scheduler) ClearQueue() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.techniqueQueue = make([]*Technique, 0)
}
