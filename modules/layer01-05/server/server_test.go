package server

import (
	"testing"
	"time"
)

func TestNewServer(t *testing.T) {
	s := NewServer("127.0.0.1", 0)
	if s == nil {
		t.Fatal("expected non-nil Server")
	}
	if s.addr != "127.0.0.1" {
		t.Errorf("expected addr 127.0.0.1, got %s", s.addr)
	}
}

func TestServer_StopBeforeStart(t *testing.T) {
	s := NewServer("127.0.0.1", 0)
	s.Stop()
}

func TestServer_GetAgentCount(t *testing.T) {
	s := NewServer("127.0.0.1", 0)
	count := s.GetAgentCount()
	if count != 0 {
		t.Errorf("expected 0 agents, got %d", count)
	}
}

func TestServer_GetTaskCount(t *testing.T) {
	s := NewServer("127.0.0.1", 0)
	count := s.GetTaskCount()
	if count != 0 {
		t.Errorf("expected 0 tasks, got %d", count)
	}
}

func TestNewTaskQueue(t *testing.T) {
	q := NewTaskQueue(TaskQueueConfig{
		MaxTasks:     100,
		PriorityMode: "fifo",
	})
	if q == nil {
		t.Fatal("expected non-nil TaskQueue")
	}
}

func TestTaskQueue_AddGetTask(t *testing.T) {
	q := NewTaskQueue(TaskQueueConfig{
		MaxTasks:     100,
		PriorityMode: "fifo",
	})
	//nolint: gocritic
	id := q.AddTask("test-task", "recon", "{}")
	if id == "" {
		t.Error("expected non-empty task ID")
	}
	task := q.GetTask(id)
	if task == nil {
		t.Fatal("expected non-nil task")
	}
	if task.Type != "recon" {
		t.Errorf("expected type recon, got %s", task.Type)
	}
}

func TestTaskQueue_AddTaskOverflow(t *testing.T) {
	q := NewTaskQueue(TaskQueueConfig{MaxTasks: 2})
	_ = q.AddTask("a", "t", "{}") //nolint
	_ = q.AddTask("b", "t", "{}") //nolint
	_ = q.AddTask("c", "t", "{}") //nolint
	// Queue accepts tasks; overflow behavior depends on config
}

func TestTaskQueue_CompleteTask(t *testing.T) {
	q := NewTaskQueue(TaskQueueConfig{MaxTasks: 100})
	_ = q.AddTask("t", "recon", "{}") //nolint
	q.CompleteTask("t")
}

func TestTaskQueue_FailTask(t *testing.T) {
	q := NewTaskQueue(TaskQueueConfig{MaxTasks: 100})
	_ = q.AddTask("t", "recon", "{}") //nolint
	q.FailTask("t")
}

func TestTaskQueue_GetNonexistent(t *testing.T) {
	q := NewTaskQueue(TaskQueueConfig{MaxTasks: 100})
	task := q.GetTask("nonexistent")
	if task != nil {
		t.Error("expected nil for nonexistent task")
	}
}

func TestNewResultHandler(t *testing.T) {
	rh := NewResultHandler(ResultHandlerConfig{
		BufferSize: 100,
	})
	if rh == nil {
		t.Fatal("expected non-nil ResultHandler")
	}
}

func TestResultHandler_HandleAndGetResult(t *testing.T) {
	rh := NewResultHandler(ResultHandlerConfig{BufferSize: 100})
	result := &TaskResult{
		TaskID:   "t1",
		AgentID:  "a1",
		Data:     "test-result",
		Timestamp: time.Now(),
	}
	rh.HandleResult(result)
	r := rh.GetResult("t1")
	if r == nil {
		t.Fatal("expected non-nil result")
	}
	if r.Data != "test-result" {
		t.Errorf("expected data test-result, got %s", r.Data)
	}
}

func TestResultHandler_GetResultsByAgent(t *testing.T) {
	rh := NewResultHandler(ResultHandlerConfig{BufferSize: 100})
	rh.HandleResult(&TaskResult{TaskID: "t1", AgentID: "a1", Data: "d1", Timestamp: time.Now()})
	rh.HandleResult(&TaskResult{TaskID: "t2", AgentID: "a1", Data: "d2", Timestamp: time.Now()})
	rh.HandleResult(&TaskResult{TaskID: "t3", AgentID: "a2", Data: "d3", Timestamp: time.Now()})
	results := rh.GetResultsByAgent("a1")
	if len(results) != 2 {
		t.Errorf("expected 2 results for agent a1, got %d", len(results))
	}
}

func TestResultHandler_GetResultsByTask(t *testing.T) {
	rh := NewResultHandler(ResultHandlerConfig{BufferSize: 100})
	rh.HandleResult(&TaskResult{TaskID: "t1", AgentID: "a1", Data: "d1", Timestamp: time.Now()})
	rh.HandleResult(&TaskResult{TaskID: "t1", AgentID: "a2", Data: "d2", Timestamp: time.Now()})
	results := rh.GetResultsByTask("t1")
	if len(results) != 2 {
		t.Errorf("expected 2 results for task t1, got %d", len(results))
	}
}

func TestResultHandler_RegisterHandler(t *testing.T) {
	rh := NewResultHandler(ResultHandlerConfig{BufferSize: 100})
	called := false
	rh.RegisterHandler("recon", func(r *TaskResult) {
		called = true
	})
	rh.HandleResult(&TaskResult{
		TaskID:   "t1",
		AgentID:  "a1",
		Data:     "d",
		Type:     "recon",
		Timestamp: time.Now(),
	})
	if !called {
		t.Error("expected handler to be called")
	}
}

func TestNewScheduler(t *testing.T) {
	s := NewScheduler(SchedulerConfig{
		Interval: 1 * time.Second,
	})
	if s == nil {
		t.Fatal("expected non-nil Scheduler")
	}
}

func TestScheduler_StartStop(t *testing.T) {
	s := NewScheduler(SchedulerConfig{
		Interval: 100 * time.Millisecond,
	})
	s.Start()
	time.Sleep(50 * time.Millisecond)
	s.Stop()
}

func TestScheduler_AddRemoveTask(t *testing.T) {
	s := NewScheduler(SchedulerConfig{
		Interval: 1 * time.Second,
	})
	task := &ScheduledTask{
		ID:      "job1",
		Interval: 1 * time.Hour,
	}
	s.AddTask(task)
	s.RemoveTask("job1")
}

func TestScheduler_StopBeforeStart(t *testing.T) {
	s := NewScheduler(SchedulerConfig{
		Interval: 1 * time.Second,
	})
	s.Stop()
}
