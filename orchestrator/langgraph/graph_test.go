package langgraph

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewGraph(t *testing.T) {
	g := NewGraph()
	if g == nil {
		t.Fatal("expected non-nil graph")
	}
	if len(g.nodes) != 0 {
		t.Error("expected empty nodes")
	}
	if len(g.edges) != 0 {
		t.Error("expected empty edges")
	}
}

func TestAddNode(t *testing.T) {
	g := NewGraph()
	g.AddNode("start", "Start Node", NodeTypeStart, nil)
	if len(g.nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(g.nodes))
	}
	node := g.nodes["start"]
	if node.Name != "Start Node" {
		t.Errorf("expected name 'Start Node', got %q", node.Name)
	}
	if node.Type != NodeTypeStart {
		t.Errorf("expected type NodeTypeStart, got %s", node.Type)
	}
}

func TestAddEdge(t *testing.T) {
	g := NewGraph()
	g.AddNode("a", "A", NodeTypeAction, nil)
	g.AddNode("b", "B", NodeTypeAction, nil)
	g.AddEdge("a", "b")

	if len(g.edges["a"]) != 1 {
		t.Errorf("expected 1 edge from a, got %d", len(g.edges["a"]))
	}
	if g.edges["a"][0] != "b" {
		t.Errorf("expected edge a->b, got a->%s", g.edges["a"][0])
	}
}

func TestSetState_GetState(t *testing.T) {
	g := NewGraph()
	g.SetState("key1", "value1")
	g.SetState("key2", 42)

	if v := g.GetState("key1"); v != "value1" {
		t.Errorf("expected 'value1', got %v", v)
	}
	if v := g.GetState("key2"); v != 42 {
		t.Errorf("expected 42, got %v", v)
	}
	if v := g.GetState("nonexistent"); v != nil {
		t.Errorf("expected nil for nonexistent key, got %v", v)
	}
}

func TestRun_SimpleLinear(t *testing.T) {
	g := NewGraph()
	execOrder := []string{}

	g.AddNode("start", "Start", NodeTypeStart, func(state map[string]interface{}) (map[string]interface{}, error) {
		execOrder = append(execOrder, "start")
		return map[string]interface{}{"start_done": true}, nil
	})
	g.AddNode("process", "Process", NodeTypeAction, func(state map[string]interface{}) (map[string]interface{}, error) {
		execOrder = append(execOrder, "process")
		return map[string]interface{}{"process_done": true}, nil
	})
	g.AddNode("end", "End", NodeTypeEnd, func(state map[string]interface{}) (map[string]interface{}, error) {
		execOrder = append(execOrder, "end")
		return map[string]interface{}{"end_done": true}, nil
	})

	g.AddEdge("start", "process")
	g.AddEdge("process", "end")

	err := g.Run("start")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(execOrder) != 3 {
		t.Fatalf("expected 3 executions, got %d", len(execOrder))
	}
	expected := []string{"start", "process", "end"}
	for i, e := range expected {
		if execOrder[i] != e {
			t.Errorf("expected execution %d to be %s, got %s", i, e, execOrder[i])
		}
	}

	// Check state was accumulated
	if v := g.GetState("start_done"); v != true {
		t.Error("expected start_done in state")
	}
	if v := g.GetState("process_done"); v != true {
		t.Error("expected process_done in state")
	}
	if v := g.GetState("end_done"); v != true {
		t.Error("expected end_done in state")
	}
}

func TestRun_NoEdges(t *testing.T) {
	g := NewGraph()
	g.AddNode("single", "Single", NodeTypeAction, func(state map[string]interface{}) (map[string]interface{}, error) {
		return map[string]interface{}{"done": true}, nil
	})

	err := g.Run("single")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_NodeNotFound(t *testing.T) {
	g := NewGraph()
	err := g.Run("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent node")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got %q", err.Error())
	}
}

func TestRun_CycleDetection(t *testing.T) {
	g := NewGraph()
	g.AddNode("a", "A", NodeTypeAction, nil)
	g.AddNode("b", "B", NodeTypeAction, nil)
	g.AddEdge("a", "b")
	g.AddEdge("b", "a")

	err := g.Run("a")
	if err == nil {
		t.Fatal("expected cycle detection error")
	}
	if !strings.Contains(err.Error(), "cycle detected") {
		t.Errorf("expected 'cycle detected' in error, got %q", err.Error())
	}
}

func TestRun_NodeExecutionError(t *testing.T) {
	g := NewGraph()
	g.AddNode("start", "Start", NodeTypeStart, func(state map[string]interface{}) (map[string]interface{}, error) {
		return nil, errors.New("execution failed")
	})
	g.AddNode("next", "Next", NodeTypeAction, nil)
	g.AddEdge("start", "next")

	err := g.Run("start")
	if err == nil {
		t.Fatal("expected execution error")
	}
	if !strings.Contains(err.Error(), "execution failed") {
		t.Errorf("expected 'execution failed' in error, got %q", err.Error())
	}
}

func TestRun_NilExecuteFunction(t *testing.T) {
	g := NewGraph()
	g.AddNode("start", "Start", NodeTypeStart, nil)
	g.AddNode("end", "End", NodeTypeEnd, nil)
	g.AddEdge("start", "end")

	err := g.Run("start")
	if err != nil {
		t.Fatalf("nil Execute should be skipped, got error: %v", err)
	}
}

func TestRun_ParallelBranches(t *testing.T) {
	g := NewGraph()

	g.AddNode("start", "Start", NodeTypeStart, func(state map[string]interface{}) (map[string]interface{}, error) {
		return map[string]interface{}{"started": true}, nil
	})
	g.AddNode("branch_a", "Branch A", NodeTypeAction, func(state map[string]interface{}) (map[string]interface{}, error) {
		return map[string]interface{}{"a_done": true}, nil
	})
	g.AddNode("branch_b", "Branch B", NodeTypeAction, func(state map[string]interface{}) (map[string]interface{}, error) {
		return map[string]interface{}{"b_done": true}, nil
	})

	g.AddEdge("start", "branch_a")
	g.AddEdge("start", "branch_b")

	err := g.Run("start")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if v := g.GetState("a_done"); v != true {
		t.Error("expected a_done in state")
	}
	if v := g.GetState("b_done"); v != true {
		t.Error("expected b_done in state")
	}
}

func TestReset(t *testing.T) {
	g := NewGraph()
	g.SetState("key", "value")
	g.Reset()

	if v := g.GetState("key"); v != nil {
		t.Errorf("expected nil after reset, got %v", v)
	}
	if g.running {
		t.Error("expected not running after reset")
	}
}

func TestIsRunning(t *testing.T) {
	g := NewGraph()
	if g.IsRunning() {
		t.Error("expected not running initially")
	}
}

func TestGetStateSnapshot(t *testing.T) {
	g := NewGraph()
	g.SetState("a", 1)
	g.SetState("b", "two")

	snap := g.GetStateSnapshot()
	if snap["a"] != 1 {
		t.Errorf("expected a=1, got %v", snap["a"])
	}
	if snap["b"] != "two" {
		t.Errorf("expected b=two, got %v", snap["b"])
	}

	// Modify snapshot should not affect graph state
	snap["a"] = 999
	if g.GetState("a") != 1 {
		t.Error("snapshot modification affected graph state")
	}
}

func TestExecuteWithTimeout_FinishesInTime(t *testing.T) {
	g := NewGraph()
	g.AddNode("fast", "Fast", NodeTypeAction, func(state map[string]interface{}) (map[string]interface{}, error) {
		return nil, nil
	})

	err := ExecuteWithTimeout(g, "fast", 5*time.Second)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestExecuteWithTimeout_Timeout(t *testing.T) {
	g := NewGraph()
	g.AddNode("slow", "Slow", NodeTypeAction, func(state map[string]interface{}) (map[string]interface{}, error) {
		time.Sleep(2 * time.Second)
		return nil, nil
	})

	err := ExecuteWithTimeout(g, "slow", 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected 'timed out' in error, got %q", err.Error())
	}
}

func TestNodeType_Constants(t *testing.T) {
	types := map[NodeType]bool{
		NodeTypeAction:    false,
		NodeTypeCondition: false,
		NodeTypeRouter:    false,
		NodeTypeParallel:  false,
		NodeTypeStart:     false,
		NodeTypeEnd:       false,
	}
	for nt := range types {
		if types[nt] {
			t.Errorf("duplicate NodeType: %s", nt)
		}
		types[nt] = true
	}
}

func TestGraph_NodeMetadata(t *testing.T) {
	g := NewGraph()
	g.AddNode("n", "Node", NodeTypeAction, nil)

	node := g.nodes["n"]
	if node.Metadata == nil {
		t.Error("expected non-nil metadata map")
	}
}
