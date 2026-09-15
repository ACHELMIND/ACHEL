# ANGEL Platform Documentation

## Overview

ANGEL (Advanced Next-Generation Offensive Security Framework) is a comprehensive red team platform built with Go. It provides 70 layers of offensive security modules, from core C2 infrastructure to advanced exploitation techniques.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    ANGEL Platform Architecture                   │
├─────────────────────────────────────────────────────────────────┤
│  TIER 5: Frontend (Angular)                                     │
│  - Dashboard, Agent Console, Report Viewer                      │
├─────────────────────────────────────────────────────────────────┤
│  TIER 4: API Gateway (.NET 10)                                  │
│  - Auth, RBAC, Rate Limiting                                    │
├─────────────────────────────────────────────────────────────────┤
│  TIER 3: Orchestrator (Go)                                      │
│  - LangGraph Orchestration, Intent Classifier, Brain            │
├─────────────────────────────────────────────────────────────────┤
│  TIER 2: C2 Framework (Go)                                      │
│  - Implant, Teamserver, Listeners, SMB Beacon                   │
├─────────────────────────────────────────────────────────────────┤
│  TIER 1: Infrastructure (Terraform/Ansible)                     │
│  - VPS, WireGuard, Firewall                                     │
└─────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
ANGEL/
├── cmd/                    # Binary entry points
│   ├── teamserver/         # Main C2 teamserver
│   ├── console/            # Operator console
│   └── rules-loader/       # Rules loading utility
├── modules/                # Offensive modules (70 layers)
│   ├── layer01-05/         # C2 core, decoy, SQLi, NoSQL, DB post-exploit
│   ├── layer06-10/         # Evasion, Kerberos, Lateral, Persistence, Rootkit
│   ├── layer11-15/         # Brain, Collector, Credential, Destruction, Orchestrator
│   ├── layer16-21/         # Cleanup, Evidence, Exploit, Infra, OSINT, Report
│   ├── layer22-25/         # Auth bypass, Destruction chain, Implant gen, Net evasion
│   ├── layer26-40/         # Container, Cloud, SE, Wireless, Supply chain, API, Mobile, etc.
│   ├── layer41-60/         # Cache smuggling, Cert forgery, CSRF, DNSSEC, IoT, etc.
│   └── layer61-70/         # ARP/DHCP, Biz logic, Crypto, Deser, GraphQL, gRPC, etc.
├── pkg/                    # Shared packages
│   ├── supabase/           # Supabase client
│   ├── eventbus/           # Event bus system
│   ├── crypto/             # Cryptographic utilities
│   ├── logger/             # Logging system
│   ├── types/              # Common types
│   ├── purchase/           # Payment processing (iOS/Web)
│   └── rpg/                # RPG game system
├── scripts/                # Automation scripts
├── tests/                  # Test scenarios
├── docs/                   # Documentation
├── infra/                  # Infrastructure (Terraform/Ansible)
├── frontend/               # Frontend (Angular)
├── Makefile                # Build automation
└── STRUKTUR_ANGEL.md       # Full blueprint
```

## Quick Start

### Prerequisites

- Go 1.27+
- Node.js 18+ (for frontend)
- Terraform (for infrastructure)
- Ansible (for configuration management)

### Installation

```bash
# Clone repository
git clone https://github.com/ACHELMIND/ACHEL.git
cd ACHEL

# Install dependencies
go mod tidy

# Build
make build

# Run tests
make test
```

### Configuration

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

### Running

```bash
# Start teamserver
./bin/angel

# Start console
./bin/angel-console

# Load rules
./bin/angel-rules
```

## Module Layers

### Layer 1-5: Core C2
- **C2 Implant**: Core implant with sleep masking, encryption
- **C2 Server**: Teamserver with task queue, agent management
- **SQL Injection**: Automated SQL injection engine
- **NoSQL Injection**: MongoDB, Redis, CouchDB injection
- **Database Post-Exploit**: MSSQL, MySQL, PostgreSQL, Oracle

### Layer 6-10: Advanced Evasion
- **Evasion**: Syscall, sleep, AMSI, ETW bypass
- **Kerberos**: Kerberoasting, Golden/Silver ticket
- **Lateral Movement**: SMB, WMI, PSExec, DCOM
- **Persistence**: Registry, scheduled tasks, services
- **Rootkit**: Kernel, userland, UEFI rootkits

### Layer 11-15: Intelligence
- **Brain**: Autonomous decision engine
- **Collector**: Data collection and exfiltration
- **Credential**: LSASS, browser, SAM dump
- **Destruction**: Wiper, ransomware
- **Orchestrator**: LangGraph-based orchestration

### Layer 16-21: Infrastructure
- **Cleanup**: Log clearing, trace removal
- **Evidence**: Chain of custody, forensics
- **Exploit**: LFI, SSRF, RCE, deserialization
- **Infra**: Terraform, Ansible automation
- **OSINT**: Subdomain, email, social recon

### Layer 22-25: Additional
- **Auth Bypass**: JWT, credential stuffing
- **Destruction Chain**: Multi-stage destruction
- **Implant Gen**: Polymorphic implant generation
- **Net Evasion**: Network traffic manipulation

### Layer 26-40: Extended
- **Container**: Docker, Kubernetes escape
- **Cloud**: AWS, Azure, GCP attacks
- **Social Engineering**: Phishing, vishing
- **Wireless**: WiFi, Bluetooth, RFID
- **Supply Chain**: Dependency confusion, CI/CD
- **API Security**: OAuth, JWT, rate limiting
- **Mobile**: iOS/Android attacks
- **Physical**: USB drops, badge cloning
- **Purple Team**: Detection validation
- **Threat Intel**: IOC generation, MITRE mapping
- **IR**: Incident response simulation
- **Zero Trust**: MFA bypass, lateral movement
- **Web3**: Smart contract vulnerabilities
- **Malware**: Static/dynamic analysis
- **AI/ML**: Prompt injection, model stealing

### Layer 41-60: Advanced Web
- **Cache Smuggling**: Request smuggling, cache poisoning
- **Certificate Forgery**: Self-signed, Let's Encrypt abuse
- **CSRF**: Token bypass, SameSite bypass
- **DNSSEC**: NSEC walking, zone walking
- **IoT**: Device exploitation
- **IPv6**: SLAAC, NDP attacks
- **LDAP**: Injection, enumeration
- **mDNS**: Multicast DNS attacks
- **Methodology**: Attack patterns
- **Multi-Cloud**: Cross-cloud attacks
- **OPSEC**: Operational security
- **Redirect**: Open redirect, SSRF
- **SAML**: XML signature wrapping
- **SCADA**: ICS/SCADA exploitation
- **TLS 1.3**: Protocol attacks
- **Upload**: File upload vulnerabilities
- **Web Misc**: Miscellaneous web attacks

### Layer 61-70: Network & Crypto
- **ARP/DHCP**: Spoofing, starvation
- **Business Logic**: Price manipulation, workflow abuse
- **Crypto**: Padding oracle, ECB leak, hash length extension
- **Deserialization**: Java, PHP, Python, .NET
- **GraphQL**: Introspection, depth abuse
- **gRPC**: Reflection, service exploitation
- **Memory Corruption**: Buffer overflow, use-after-free
- **Password Reset**: Token prediction, enumeration
- **Race Condition**: TOCTOU, double spending
- **VLAN**: Hopping, trunking attacks

## API Reference

### Teamserver API

```
POST   /api/v1/agents          - Register agent
GET    /api/v1/agents          - List agents
GET    /api/v1/agents/{id}     - Get agent
POST   /api/v1/tasks           - Create task
GET    /api/v1/tasks           - List tasks
POST   /api/v1/results         - Submit result
GET    /api/v1/health          - Health check
```

### Event Bus Topics

```
c2.implant.registered.v1       - Agent registration
c2.implant.checkin.v1          - Agent check-in
c2.task.created.v1             - Task created
c2.task.completed.v1           - Task completed
exploit.*.result.v1            - Exploit results
orchestrator.decision.sent.v1  - Orchestrator decisions
```

## Development

### Adding a New Module

1. Create directory: `modules/layerXX-YY/modulename/`
2. Create files: `types.go`, `engine.go`, `engine_test.go`
3. Implement the `Engine` struct with methods
4. Add tests
5. Register in event bus

### Code Style

- Follow Go conventions
- Use `gofmt` and `goimports`
- Write tests for all public functions
- Document exported functions

## Testing

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run specific test
go test -v ./modules/layer01-05/sqli/
```

## Deployment

### Local

```bash
make build
./bin/angel
```

### Docker

```bash
make docker
docker run -p 8080:8080 angel:latest
```

### Production

1. Provision infrastructure with Terraform
2. Configure with Ansible
3. Deploy binaries
4. Start services

## Security Notes

- Always use in authorized environments only
- Keep credentials in `.env` (never commit)
- Use VPN for operational security
- Enable encryption for all communications
- Rotate keys regularly

## License

Private - Authorized use only
