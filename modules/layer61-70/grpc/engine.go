package grpc

import (
	"fmt"
	"strings"
)

type Engine struct {
	config GRPCConfig
}

func NewEngine(config GRPCConfig) *Engine {
	return &Engine{config: config}
}

func (e *Engine) ServiceEnumerate() GRPCResult {
	services := discoverServices(e.config)

	totalMethods := 0
	for _, svc := range services {
		totalMethods += len(svc.Methods)
	}

	reflection := &ReflectionResult{
		Services:      services,
		TotalMethods:  totalMethods,
		AuthService:   "grpc.health.v1.Health",
		ServerVersion: "v1.50.0",
	}

	detail := fmt.Sprintf("Service enumeration: %d services, %d methods discovered",
		len(services), totalMethods)

	return GRPCResult{
		Reflection: reflection,
		Enumerated: len(services) > 0,
		Details:    detail,
		Services:   services,
		RiskScore:  0.6,
	}
}

func (e *Engine) MethodDiscover() GRPCResult {
	services := discoverServices(e.config)

	methods := make([]string, 0)
	for _, svc := range services {
		for _, m := range svc.Methods {
			access := "public"
			if m.Auth != "" {
				access = "authenticated"
			}
			methods = append(methods, fmt.Sprintf("%s/%s (%s, %s)",
				svc.Name, m.Name, access, streamType(m.Streaming)))
		}
	}

	detail := fmt.Sprintf("Method discovery: %d methods across %d services: %s",
		len(methods), len(services), strings.Join(methods[:min(len(methods), 5)], "; "))

	return GRPCResult{
		Enumerated: len(methods) > 0,
		Details:    detail,
		Services:   services,
		RiskScore:  0.5,
	}
}

func (e *Engine) AuthBypass() GRPCResult {
	services := discoverServices(e.config)

	unprotectedMethods := make([]string, 0)
	for _, svc := range services {
		for _, m := range svc.Methods {
			if m.Auth == "" {
				unprotectedMethods = append(unprotectedMethods, fmt.Sprintf("%s/%s", svc.Name, m.Name))
			}
		}
	}

	authBypass := len(unprotectedMethods) > 0
	detail := fmt.Sprintf("Auth bypass: %d unprotected methods found: %s",
		len(unprotectedMethods), strings.Join(unprotectedMethods[:min(len(unprotectedMethods), 3)], ", "))

	return GRPCResult{
		Enumerated: true,
		AuthBypass: authBypass,
		Details:    detail,
		Services:   services,
		RiskScore:  0.8,
	}
}

func (e *Engine) ProtoLeak() GRPCResult {
	protoFiles := []ProtoFile{
		{
			Name:     "user.proto",
			Messages: []string{"User", "GetUserRequest", "GetUserResponse", "ListUsersRequest"},
			Services: []GRPCService{
				{Name: "UserService", Methods: []GRPCMethod{
					{Name: "GetUser", InputType: "GetUserRequest", OutputType: "User"},
					{Name: "ListUsers", InputType: "ListUsersRequest", OutputType: "ListUsersResponse", Streaming: true},
				}},
			},
		},
		{
			Name:     "auth.proto",
			Messages: []string{"LoginRequest", "LoginResponse", "Token"},
			Services: []GRPCService{
				{Name: "AuthService", Methods: []GRPCMethod{
					{Name: "Login", InputType: "LoginRequest", OutputType: "LoginResponse"},
					{Name: "RefreshToken", InputType: "Token", OutputType: "LoginResponse"},
				}},
			},
		},
	}

	totalMessages := 0
	for _, pf := range protoFiles {
		totalMessages += len(pf.Messages)
	}

	detail := fmt.Sprintf("Proto leak: %d proto files, %d messages, services: %s",
		len(protoFiles), totalMessages, summarizeProtoServices(protoFiles))

	return GRPCResult{
		Enumerated: true,
		ProtoLeak:  true,
		Details:    detail,
		RiskScore:  0.7,
	}
}

func discoverServices(config GRPCConfig) []GRPCService {
	services := []GRPCService{
		{
			Name:    "UserService",
			Package: "app.v1",
			Methods: []GRPCMethod{
				{Name: "GetUser", InputType: "GetUserRequest", OutputType: "User", Auth: "bearer"},
				{Name: "CreateUser", InputType: "CreateUserRequest", OutputType: "User", Auth: "bearer"},
				{Name: "ListUsers", InputType: "ListUsersRequest", OutputType: "ListUsersResponse", Streaming: true},
				{Name: "DeleteUser", InputType: "DeleteUserRequest", OutputType: "Empty", Auth: "admin"},
			},
		},
		{
			Name:    "PaymentService",
			Package: "payment.v1",
			Methods: []GRPCMethod{
				{Name: "ProcessPayment", InputType: "PaymentRequest", OutputType: "PaymentResponse", Auth: "bearer"},
				{Name: "Refund", InputType: "RefundRequest", OutputType: "RefundResponse", Auth: "admin"},
			},
		},
		{
			Name:    "HealthService",
			Package: "grpc.health.v1",
			Methods: []GRPCMethod{
				{Name: "Check", InputType: "HealthCheckRequest", OutputType: "HealthCheckResponse"},
				{Name: "Watch", InputType: "HealthCheckRequest", OutputType: "HealthCheckResponse", Streaming: true},
			},
		},
	}

	if config.ServiceName != "" {
		for _, svc := range services {
			if strings.Contains(svc.Name, config.ServiceName) {
				return []GRPCService{svc}
			}
		}
	}

	return services
}

func streamType(streaming bool) string {
	if streaming {
		return "streaming"
	}
	return "unary"
}

func summarizeProtoServices(files []ProtoFile) string {
	names := make([]string, 0)
	for _, f := range files {
		names = append(names, f.Name)
	}
	return strings.Join(names, ", ")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
