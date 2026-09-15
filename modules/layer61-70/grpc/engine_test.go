package grpc

import "testing"

func TestServiceEnumerate(t *testing.T) {
	config := GRPCConfig{
		TargetHost: "target",
		TargetPort: 50051,
		Reflection: true,
	}
	engine := NewEngine(config)
	result := engine.ServiceEnumerate()
	if result.Reflection == nil {
		t.Error("expected non-nil reflection")
	}
	if len(result.Services) == 0 {
		t.Error("expected non-empty services")
	}
}

func TestMethodDiscover(t *testing.T) {
	config := GRPCConfig{
		TargetHost: "target",
		TargetPort: 50051,
	}
	engine := NewEngine(config)
	result := engine.MethodDiscover()
	if !result.Enumerated {
		t.Error("expected enumerated result")
	}
}

func TestAuthBypass(t *testing.T) {
	config := GRPCConfig{
		TargetHost: "target",
		TargetPort: 50051,
	}
	engine := NewEngine(config)
	result := engine.AuthBypass()
	if !result.Enumerated {
		t.Error("expected enumerated result")
	}
}

func TestProtoLeak(t *testing.T) {
	config := GRPCConfig{
		TargetHost: "target",
		TargetPort: 50051,
	}
	engine := NewEngine(config)
	result := engine.ProtoLeak()
	if !result.ProtoLeak {
		t.Error("expected proto leak detected")
	}
}
