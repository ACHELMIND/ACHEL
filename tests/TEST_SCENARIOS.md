# Test Scenarios - TC-001 to TC-1346

## Overview

This document contains test scenarios for all 70 layers of the ANGEL platform.
Each test case follows the format: TC-XXX - [Description]

## Layer 1-5: Core C2 (TC-001 to TC-100)

### C2 Framework
- TC-001: Agent registration success
- TC-002: Agent registration failure - retry with backoff
- TC-003: Agent registration failure - alternate listener
- TC-004: Teamserver crash recovery
- TC-005: Listener port blocked - rotate port
- TC-006: Listener port blocked - domain fronting
- TC-007: Implant detected - self-destruct
- TC-008: Implant detected - re-deploy
- TC-009: Channel blocked - rotate channel
- TC-010: Channel blocked - use fallback
- TC-011: Encryption key mismatch - regenerate
- TC-012: Encryption key mismatch - re-establish
- TC-013: Database corruption - restore backup
- TC-014: Database corruption - rebuild
- TC-015: Sleep masking success
- TC-016: Syscall execution success
- TC-017: Channel rotation - HTTPS to DNS
- TC-018: Channel rotation - DNS to WebSocket
- TC-019: Domain fronting - Cloudflare
- TC-020: Domain fronting - CloudFront

### SMB Beacon
- TC-021: SMB Beacon connection
- TC-022: SMB Beacon execution
- TC-023: SMB Beacon disconnect
- TC-024: SMB Beacon reconnect
- TC-025: SMB Beacon key rotation

### Environment Detection
- TC-026: VM detection - VMware
- TC-027: VM detection - VirtualBox
- TC-028: VM detection - Hyper-V
- TC-029: Sandbox detection - Cuckoo
- TC-030: Sandbox detection - Joe Sandbox
- TC-031: EDR detection - CrowdStrike
- TC-032: EDR detection - SentinelOne
- TC-033: EDR detection - Carbon Black
- TC-034: Debugger detection - OllyDbg
- TC-035: Debugger detection - x64dbg
- TC-036: Network monitoring detection

### Resilience
- TC-037: Dead man's switch trigger
- TC-038: Self-destruct execution
- TC-039: Re-persistence success
- TC-040: Re-harvest credentials
- TC-041: Recovery from crash

### Channel Rotation
- TC-042: Channel health check
- TC-043: Failover to backup channel
- TC-044: Domain fronting rotation

### Decoy
- TC-045: Decoy server deployment
- TC-046: Honeypot credential capture
- TC-047: Visitor logging
- TC-048: Traffic generation

### Malleable C2
- TC-049: Profile application
- TC-050: Profile validation
- TC-051: Profile rotation

### Server
- TC-052: Task queue management
- TC-053: Task scheduling
- TC-054: Result handling

## Layer 6-10: Advanced Evasion (TC-101 to TC-200)

### Evasion
- TC-101: Syscall evasion - NtCreateFile
- TC-102: Syscall evasion - NtWriteVirtualMemory
- TC-103: Sleep masking - standard
- TC-104: Sleep masking - jitter
- TC-105: AMSI bypass - patching
- TC-106: AMSI bypass - reflection
- TC-107: ETW bypass - patching
- TC-108: ETW bypass - provider manipulation
- TC-109: Sysmon bypass - driver loading
- TC-110: Sysmon bypass - configuration manipulation

### Kerberos
- TC-111: Kerberoasting - standard
- TC-112: Kerberoasting - AES
- TC-113: AS-REP Roasting
- TC-114: Golden Ticket creation
- TC-115: Golden Ticket injection
- TC-116: Silver Ticket creation
- TC-117: Diamond Ticket creation
- TC-118: Pass-the-Ticket
- TC-119: Overpass-the-Hash
- TC-120: Kerberos delegation abuse

### Lateral Movement
- TC-121: SMB lateral movement
- TC-122: WMI lateral movement
- TC-123: PSExec lateral movement
- TC-124: DCOM lateral movement
- TC-125: WinRM lateral movement
- TC-126: SSH lateral movement
- TC-127: RDP lateral movement
- TC-128: Pass-the-Hash
- TC-129: Pass-the-Password
- TC-130: Overpass-the-Hash

### Persistence
- TC-131: Registry persistence - Run keys
- TC-132: Registry persistence - Services
- TC-133: Scheduled Task persistence
- TC-134: Service persistence
- TC-135: Startup folder persistence
- TC-136: WMI event subscription
- TC-137: COM object hijacking
- TC-138: DLL search order hijacking
- TC-139: AppInit DLLs
- TC-140: Image File Execution Options

### Rootkit
- TC-141: Userland rootkit - IAT hooking
- TC-142: Userland rootkit - inline hooking
- TC-143: Kernel rootkit - driver loading
- TC-144: Kernel rootkit - DKOM
- TC-145: Bootkit - MBR infection
- TC-146: Bootkit - UEFI infection

## Layer 11-15: Intelligence (TC-201 to TC-300)

### Brain
- TC-201: Autonomous decision making
- TC-202: Risk assessment
- TC-203: Behavior learning
- TC-204: Timing control

### Collector
- TC-205: Screenshot capture
- TC-206: Keylogger capture
- TC-207: Clipboard capture
- TC-208: Audio capture
- TC-209: Video capture
- TC-210: Browser data collection

### Credential
- TC-211: LSASS dump - mimikatz
- TC-212: LSASS dump - direct syscalls
- TC-213: SAM dump
- TC-214: Browser credential extraction
- TC-215: WiFi credential extraction
- TC-216: DPAPI credential extraction

### Destruction
- TC-217: Wiper - file encryption
- TC-218: Wiper - MBR overwrite
- TC-219: Ransomware - file encryption
- TC-220: Ransomware - note deployment

### Orchestrator
- TC-221: Intent classification
- TC-222: Decision execution
- TC-223: Workflow management

## Layer 16-21: Infrastructure (TC-301 to TC-400)

### Cleanup
- TC-301: Log clearing - Windows
- TC-302: Log clearing - Linux
- TC-303: Timeline manipulation
- TC-304: Artifact removal

### Evidence
- TC-305: Evidence collection
- TC-306: Chain of custody
- TC-307: Forensic imaging

### Exploit
- TC-308: LFI exploitation
- TC-309: SSRF exploitation
- TC-310: RCE exploitation
- TC-311: Deserialization exploitation
- TC-312: SQL injection exploitation
- TC-313: NoSQL injection exploitation

### Infra
- TC-314: Terraform provisioning
- TC-315: Ansible configuration
- TC-316: VPS deployment
- TC-317: WireGuard setup

### OSINT
- TC-318: Subdomain enumeration
- TC-319: Email harvesting
- TC-320: Social media reconnaissance
- TC-321: Breach data analysis

## Layer 22-25: Additional (TC-401 to TC-500)

### Auth Bypass
- TC-401: JWT bypass - none algorithm
- TC-402: JWT bypass - weak secret
- TC-403: JWT bypass - key confusion
- TC-404: Credential stuffing
- TC-405: Password spraying

### Destruction Chain
- TC-406: Multi-stage destruction
- TC-407: Staged data exfiltration
- TC-408: Coordinated destruction

### Implant Gen
- TC-409: Polymorphic implant generation
- TC-410: Metamorphic implant generation
- TC-411: Encryption-based evasion

### Net Evasion
- TC-412: Traffic manipulation
- TC-413: Protocol tunneling
- TC-414: DNS tunneling
- TC-415: ICMP tunneling

## Layer 26-40: Extended (TC-501 to TC-700)

### Container
- TC-501: Docker socket mount escape
- TC-502: Privileged container escape
- TC-503: K8s API access
- TC-504: K8s secret extraction
- TC-505: Containerd escape

### Cloud
- TC-506: AWS IAM privesc
- TC-507: Azure AD privesc
- TC-508: GCP IAM privesc
- TC-509: AWS metadata service
- TC-510: Azure managed identity

### Social Engineering
- TC-511: Email phishing
- TC-512: Spear phishing
- TC-513: Vishing
- TC-514: Smishing
- TC-515: QR phishing

### Wireless
- TC-516: WiFi deauth attack
- TC-517: WiFi handshake capture
- TC-518: Evil twin deployment
- TC-519: Bluetooth sniffing
- TC-520: RFID cloning

### Supply Chain
- TC-521: Dependency confusion
- TC-522: Typosquatting
- TC-523: CI/CD pipeline compromise
- TC-524: Package registry abuse

### API Security
- TC-525: OAuth redirect URI manipulation
- TC-526: JWT algorithm bypass
- TC-527: Rate limit bypass
- TC-528: IDOR exploitation
- TC-529: GraphQL introspection

### Mobile
- TC-530: iOS keychain dump
- TC-531: iOS jailbreak detection bypass
- TC-532: Android root detection bypass
- TC-533: SSL pinning bypass

### Physical
- TC-534: USB HID attack
- TC-535: Badge cloning
- TC-536: Lock picking
- TC-537: Social engineering physical

### Purple Team
- TC-538: Alert validation
- TC-539: Detection rule testing
- TC-540: MITRE mapping
- TC-541: Coverage analysis

### Threat Intel
- TC-542: IOC generation
- TC-543: MITRE ATT&CK mapping
- TC-544: Threat actor profiling
- TC-545: Campaign tracking

### IR
- TC-546: Breach simulation
- TC-547: Playbook execution
- TC-548: Incident response

### Zero Trust
- TC-549: MFA bypass - SIM swap
- TC-550: MFA bypass - push fatigue
- TC-551: Identity attack
- TC-552: Network segmentation bypass

### Web3
- TC-553: Reentrancy detection
- TC-554: Flash loan attack
- TC-555: Privilege escalation
- TC-556: Governance manipulation

### Malware
- TC-557: PE analysis
- TC-558: YARA scanning
- TC-559: String extraction
- TC-560: Import analysis

### AI/ML
- TC-561: Prompt injection
- TC-562: Model stealing
- TC-563: Adversarial examples
- TC-564: Jailbreak

## Layer 41-60: Advanced Web (TC-701 to TC-1000)

### Cache Smuggling
- TC-701: Request smuggling
- TC-702: Cache poisoning
- TC-703: CDN abuse

### Certificate Forgery
- TC-704: Self-signed certificate
- TC-705: Let's Encrypt abuse
- TC-706: Certificate transparency

### CSRF
- TC-707: Token bypass
- TC-708: SameSite bypass
- TC-709: JSON CSRF
- TC-710: Admin hijack

### DNSSEC
- TC-711: NSEC walking
- TC-712: Zone walking
- TC-713: Key signing

### IoT
- TC-714: Device enumeration
- TC-715: Firmware extraction
- TC-716: Default credentials
- TC-717: Protocol analysis

### IPv6
- TC-718: SLAAC attack
- TC-719: NDP poisoning
- TC-720: IPv6 tunneling

### LDAP
- TC-721: LDAP injection
- TC-722: LDAP enumeration
- TC-723: AD exploration

### mDNS
- TC-724: mDNS enumeration
- TC-725: mDNS poisoning

### Methodology
- TC-726: Attack patterns
- TC-727: Testing procedures
- TC-728: Documentation

### Multi-Cloud
- TC-729: Cross-cloud attacks
- TC-730: Cloud-to-cloud movement

### OPSEC
- TC-731: Operational security
- TC-732: Anti-forensics
- TC-733: Evasion techniques

### Redirect
- TC-734: Open redirect
- TC-735: SSRF via redirect

### SAML
- TC-736: XML signature wrapping
- TC-737: SAML bypass
- TC-738: Token manipulation

### SCADA
- TC-739: ICS enumeration
- TC-740: Protocol exploitation
- TC-741: PLC manipulation

### TLS 1.3
- TC-742: Protocol analysis
- TC-743: Cipher suite weakness
- TC-744: Certificate validation

### Upload
- TC-745: File upload bypass
- TC-746: Web shell upload
- TC-747: Path traversal

### Web Misc
- TC-748: XSS injection
- TC-749: XXE injection
- TC-750: SSTI injection

## Layer 61-70: Network & Crypto (TC-1001 to TC-1346)

### ARP/DHCP
- TC-1001: ARP spoofing
- TC-1002: ARP poisoning
- TC-1003: DHCP starvation
- TC-1004: DHCP spoofing

### Business Logic
- TC-1005: Price manipulation
- TC-1006: Quantity manipulation
- TC-1007: Workflow abuse
- TC-1008: Race condition

### Crypto
- TC-1009: Padding oracle
- TC-1010: ECB leak
- TC-1011: Hash length extension
- TC-1012: Weak key detection

### Deserialization
- TC-1013: Java deserialization
- TC-1014: PHP deserialization
- TC-1015: Python pickle
- TC-1016: .NET deserialization

### GraphQL
- TC-1017: Introspection
- TC-1018: Depth abuse
- TC-1019: Batch attacks

### gRPC
- TC-1020: Reflection
- TC-1021: Service enumeration
- TC-1022: Method exploitation

### Memory Corruption
- TC-1023: Buffer overflow
- TC-1024: Use-after-free
- TC-1025: Heap spray
- TC-1026: Return-oriented programming

### Password Reset
- TC-1027: Token prediction
- TC-1028: Token enumeration
- TC-1029: Reset flow bypass

### Race Condition
- TC-1030: TOCTOU
- TC-1031: Double spending
- TC-1032: Concurrent request abuse

### VLAN
- TC-1033: VLAN hopping
- TC-1034: Double tagging
- TC-1035: Trunk port abuse

---

## Test Execution Notes

### Prerequisites
- Authorized testing environment only
- Proper credentials and access
- VPN connection for remote testing
- Logging enabled for evidence collection

### Documentation Requirements
- Screenshots for each finding
- Command output logs
- Timeline of events
- Evidence preservation

### Reporting Requirements
- Critical findings: Immediate notification
- High findings: 24-hour notification
- All findings: Detailed report within 5 business days
