package graphql

import "testing"

func TestDeepNestedQuery(t *testing.T) {
	config := GraphQLConfig{
		TargetURL: "http://target:4000/graphql",
		MaxDepth:  10,
	}
	engine := NewEngine(config)
	result := engine.DeepNestedQuery()
	if result.Attack != GraphQLAttackDeepNesting {
		t.Errorf("expected DeepNesting attack, got %d", result.Attack)
	}
	if result.MaxDepth <= 0 {
		t.Error("expected positive max depth")
	}
	if len(result.Queries) == 0 {
		t.Error("expected non-empty queries")
	}
}

func TestBatchQueryAbuse(t *testing.T) {
	config := GraphQLConfig{
		TargetURL: "http://target:4000/graphql",
		BatchSize: 50,
	}
	engine := NewEngine(config)
	result := engine.BatchQueryAbuse()
	if result.Attack != GraphQLAttackBatchAbuse {
		t.Errorf("expected BatchAbuse attack, got %d", result.Attack)
	}
	if result.ResponseSize <= 0 {
		t.Error("expected positive response size")
	}
}

func TestSchemaLeak(t *testing.T) {
	config := GraphQLConfig{
		TargetURL: "http://target:4000/graphql",
	}
	engine := NewEngine(config)
	result := engine.SchemaLeak()
	if result.Attack != GraphQLAttackSchemaLeak {
		t.Errorf("expected SchemaLeak, got %d", result.Attack)
	}
	if result.Schema == nil {
		t.Error("expected non-nil schema")
	}
	if result.Schema != nil && len(result.Schema.Types) == 0 {
		t.Error("expected non-empty types")
	}
}

func TestFieldSuggestion(t *testing.T) {
	config := GraphQLConfig{
		TargetURL: "http://target:4000/graphql",
	}
	engine := NewEngine(config)
	result := engine.FieldSuggestion()
	if result.Attack != GraphQLAttackFieldSuggestion {
		t.Errorf("expected FieldSuggestion, got %d", result.Attack)
	}
	if !result.Vulnerable {
		t.Error("expected vulnerable result")
	}
}
