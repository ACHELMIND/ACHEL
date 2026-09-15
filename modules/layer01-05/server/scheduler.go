package server

import (
	"sync"
	"time"
)

type Scheduler struct {
	mu        sync.RWMutex
	tasks     map[string]*ScheduledTask
	running   bool
	interval  time.Duration
	stopCh    chan struct{}
}

type ScheduledTask struct {
	ID        string
	Task      *QueuedTask
	Schedule  string
	Interval  time.Duration
	NextRun   time.Time
	LastRun   time.Time
	Enabled   bool
}

type SchedulerConfig struct {
	Interval time.Duration
}

func NewScheduler(config SchedulerConfig) *Scheduler {
	if config.Interval == 0 {
		config.Interval = 1 * time.Minute
	}

	return &Scheduler{
		tasks:    make(map[string]*ScheduledTask),
		interval: config.Interval,
		stopCh:   make(chan struct{}),
	}
}

func (s *Scheduler) Start() {
	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	go s.runLoop()
}

func (s *Scheduler) Stop() {
	s.mu.Lock()
	s.running = false
	s.mu.Unlock()
	close(s.stopCh)
}

func (s *Scheduler) runLoop() {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.checkAndRun()
		}
	}
}

func (s *Scheduler) checkAndRun() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	for _, task := range s.tasks {
		if task.Enabled && now.After(task.NextRun) {
			go s.executeTask(task)
		}
	}
}

func (s *Scheduler) executeTask(task *ScheduledTask) {
	s.mu.Lock()
	task.LastRun = time.Now()
	task.NextRun = time.Now().Add(task.Interval)
	s.mu.Unlock()
}

func (s *Scheduler) AddTask(task *ScheduledTask) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if task.NextRun.IsZero() {
		task.NextRun = time.Now().Add(task.Interval)
	}
	task.Enabled = true

	s.tasks[task.ID] = task
}

func (s *Scheduler) RemoveTask(taskID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tasks, taskID)
}

func (s *Scheduler) EnableTask(taskID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if task, exists := s.tasks[taskID]; exists {
		task.Enabled = true
	}
}

func (s *Scheduler) DisableTask(taskID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if task, exists := s.tasks[taskID]; exists {
		task.Enabled = false
	}
}

func (s *Scheduler) GetTask(taskID string) *ScheduledTask {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tasks[taskID]
}

func (s *Scheduler) GetTasks() []*ScheduledTask {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tasks := make([]*ScheduledTask, 0, len(s.tasks))
	for _, task := range s.tasks {
		tasks = append(tasks, task)
	}
	return tasks
}

func (s *Scheduler) GetEnabledTasks() []*ScheduledTask {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tasks := make([]*ScheduledTask, 0)
	for _, task := range s.tasks {
		if task.Enabled {
			tasks = append(tasks, task)
		}
	}
	return tasks
}

func (s *Scheduler) GetTaskCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tasks)
}

func (s *Scheduler) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

func (s *Scheduler) SetInterval(interval time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.interval = interval
}

func (s *Scheduler) GetInterval() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.interval
}
