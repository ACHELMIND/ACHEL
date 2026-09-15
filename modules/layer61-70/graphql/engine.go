package graphql

import (
	"fmt"
	"strings"
)

type Engine struct {
	config GraphQLConfig
}

func NewEngine(config GraphQLConfig) *Engine {
	return &Engine{config: config}
}

func (e *Engine) DeepNestedQuery() GraphQLResult {
	maxDepth := e.config.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 10
	}

	queries := make([]string, 0)
	deepestReached := 0

	for depth := 1; depth <= maxDepth; depth++ {
		query := buildNestedQuery(depth)
		queries = append(queries, query)
		deepestReached = depth
	}

	vulnerable := deepestReached > 5

	detail := fmt.Sprintf("Deep nested query: max depth %d, queries generated: %d, vulnerable: %v",
		deepestReached, len(queries), vulnerable)

	return GraphQLResult{
		Attack:     GraphQLAttackDeepNesting,
		Vulnerable: vulnerable,
		MaxDepth:   deepestReached,
		Details:    detail,
		Queries:    queries,
	}
}

func (e *Engine) BatchQueryAbuse() GraphQLResult {
	batchSize := e.config.BatchSize
	if batchSize <= 0 {
		batchSize = 50
	}

	queries := make([]string, 0)
	for i := 0; i < batchSize; i++ {
		q := fmt.Sprintf(`{"query":"{ user(id:%d) { name email } }"}`, i)
		queries = append(queries, q)
	}

	vulnerable := batchSize > 10
	totalPayloadSize := len(strings.Join(queries, ","))

	detail := fmt.Sprintf("Batch query abuse: %d queries, total payload: %d bytes, vulnerable: %v",
		batchSize, totalPayloadSize, vulnerable)

	return GraphQLResult{
		Attack:       GraphQLAttackBatchAbuse,
		Vulnerable:   vulnerable,
		ResponseSize: totalPayloadSize,
		Details:      detail,
		Queries:      queries[:min(5, len(queries))],
	}
}

func (e *Engine) SchemaLeak() GraphQLResult {
	introspectionQuery := `{"query":"{ __schema { types { name kind fields { name type { name kind } } } } }"}`

	schema := &IntrospectionResult{
		SchemaAvailable: true,
		Types: []SchemaType{
			{Name: "User", Kind: "OBJECT", Fields: []SchemaField{
				{Name: "id", Type: "ID", Nullable: false},
				{Name: "email", Type: "String", Nullable: false},
				{Name: "name", Type: "String", Nullable: true},
				{Name: "password", Type: "String", Nullable: true},
				{Name: "role", Type: "Role", Nullable: true},
			}},
			{Name: "Query", Kind: "OBJECT", Fields: []SchemaField{
				{Name: "user", Type: "User", Args: []string{"id"}},
				{Name: "users", Type: "[User]", Args: []string{"limit", "offset"}},
			}},
			{Name: "Mutation", Kind: "OBJECT", Fields: []SchemaField{
				{Name: "login", Type: "AuthPayload", Args: []string{"email", "password"}},
				{Name: "createUser", Type: "User", Args: []string{"input"}},
			}},
		},
		QueryDepth:    3,
		MutationAvail: true,
		TotalFields:   9,
	}

	vulnerable := schema.SchemaAvailable
	detail := fmt.Sprintf("Schema leak: %d types, %d fields, mutations: %v",
		len(schema.Types), schema.TotalFields, schema.MutationAvail)

	return GraphQLResult{
		Attack:     GraphQLAttackSchemaLeak,
		Vulnerable: vulnerable,
		Schema:     schema,
		Details:    detail,
		Queries:    []string{introspectionQuery},
	}
}

func (e *Engine) FieldSuggestion() GraphQLResult {
	queries := []string{
		`{"query":"{ __type(name:\"User\") { inputFields { name type { name } } } }"}`,
		`{"query":"{ __type(name:\"User\") { enumValues { name } } }"}`,
		`{"query":"{ __schema { queryType { fields { name args { name type { name } } } } } }"}`,
	}

	vulnerable := true
	detail := fmt.Sprintf("Field suggestion: %d queries generated for field enumeration", len(queries))

	return GraphQLResult{
		Attack:     GraphQLAttackFieldSuggestion,
		Vulnerable: vulnerable,
		Details:    detail,
		Queries:    queries,
	}
}

func buildNestedQuery(depth int) string {
	var b strings.Builder
	b.WriteString("{ ")
	for i := 0; i < depth; i++ {
		b.WriteString(fmt.Sprintf("user_%d: user(id:%d) { name ", i, i))
	}
	b.WriteString("}")
	for i := depth - 1; i >= 0; i-- {
		b.WriteString(" ")
		b.WriteString("}")
	}
	return b.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
