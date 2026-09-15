package graphql

type GraphQLAttack int

const (
	GraphQLAttackIntrospection GraphQLAttack = iota
	GraphQLAttackDeepNesting
	GraphQLAttackBatchAbuse
	GraphQLAttackSchemaLeak
	GraphQLAttackFieldSuggestion
	GraphQLAttackDoS
)

func (a GraphQLAttack) String() string {
	return [...]string{
		"Introspection", "DeepNesting", "BatchAbuse",
		"SchemaLeak", "FieldSuggestion", "DoS",
	}[a]
}

type IntrospectionResult struct {
	SchemaAvailable bool          `json:"schema_available"`
	Types           []SchemaType  `json:"types"`
	QueryDepth      int           `json:"query_depth"`
	MutationAvail   bool          `json:"mutation_available"`
	TotalFields     int           `json:"total_fields"`
}

type SchemaType struct {
	Name       string       `json:"name"`
	Kind       string       `json:"kind"`
	Fields     []SchemaField `json:"fields"`
	IsInput    bool         `json:"is_input"`
}

type SchemaField struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Nullable   bool   `json:"nullable"`
	Args       []string `json:"args"`
}

type GraphQLConfig struct {
	TargetURL    string            `json:"target_url"`
	Headers      map[string]string `json:"headers"`
	MaxDepth     int               `json:"max_depth"`
	BatchSize    int               `json:"batch_size"`
	Query        string            `json:"query"`
	Variables    map[string]string `json:"variables"`
}

type GraphQLResult struct {
	Attack       GraphQLAttack      `json:"attack"`
	Vulnerable   bool               `json:"vulnerable"`
	MaxDepth     int                `json:"max_depth_found"`
	Schema       *IntrospectionResult `json:"schema,omitempty"`
	ResponseSize int                `json:"response_size"`
	Details      string             `json:"details"`
	Queries      []string           `json:"queries_generated"`
}

type QueryTemplate struct {
	Name     string `json:"name"`
	Depth    int    `json:"depth"`
	Payload  string `json:"payload"`
	Attack   GraphQLAttack `json:"attack"`
}
