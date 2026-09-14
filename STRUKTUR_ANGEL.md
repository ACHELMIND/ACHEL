STRUKTUR ANGEL


```markdown
# ANGEL — BLUEPRINT FINAL (LAYER 1-25)


> **Status:** FINAL & EXECUTABLE
> **Tujuan:** Platform offensive security (red team / blackhat) untuk engagement resmi.
> **Standar:** P0/P1, Hard/Expert, Full Attack, No Demo, No Placeholder.
> **Prinsip:** "No copy-paste" — tiap baris ditulis sendiri, bukan clone.
> **Legalitas:** Hanya digunakan pada sistem yang telah diizinkan (kontrak, izin polisi, persetujuan founder).


---


## 1. PENDAHULUAN


### 1.1 Latar Belakang
ANGEL adalah platform offensive security yang dirancang untuk menguji ketahanan infrastruktur dan sistem informasi perusahaan. Platform ini digunakan dalam engagement resmi yang memiliki izin tertulis.


### 1.2 Tujuan
- Mengidentifikasi celah keamanan P0/P1.
- Mendemonstrasikan dampak nyata (RCE, data exfiltration, database compromise).
- Menghasilkan laporan teknis dan eksekutif yang dapat ditindaklanjuti.


### 1.3 Ruang Lingkup
- Target: Infrastruktur, aplikasi web, database, endpoint.
- Metode: Offensive security testing (red team).
- Hasil: Laporan P0/P1 dengan bukti reproduksi.


### 1.4 Legalitas
- Seluruh aktivitas hanya pada sistem yang telah diizinkan.
- Kontrak, izin polisi, dan persetujuan founder telah ditandatangani.


---


## 2. ARSITEKTUR


### 2.1 Prinsip Desain
> **"Parallel separation beats serial depth"**


- Setiap komponen terpisah secara fungsional.
- Semua komunikasi antar modul menggunakan event-driven architecture.
- Jika tim blue team menangkap satu node, mereka tidak tahu node lain.


### 2.2 Diagram 6-Layer


```


┌─────────────────────────────────────────────────────────────────────┐
│              LAYER 5: FRONTEND (Angular)                           │
│ - Dashboard (operator monitoring)                              │
│ - Agent console (task submission, real-time logs)                      │
│ - Report viewer (evidence, chain-of-custody)                           │
└─────────────────────────────────────────────────────────────────────┘
│
┌─────────────────────────────────────────────────────────────────────┐
│              LAYER 4: API GATEWAY (.NET 10)                        │
│ - REST API + WebSocket untuk frontend                                  │
│ - Authentication + RBAC                                │
│ - Rate limiting + request validation                       │
└─────────────────────────────────────────────────────────────────────┘
│
┌─────────────────────────────────────────────────────────────────────┐
│              LAYER 3: ORCHESTRATOR (LangGraph)                                 │
│ - Intent classifier → route ke agent                       │
│ - Multi-agent parallelism (Fireteam mode)                          │
│ - State management (SQLite/PostgreSQL)                                     │
│ - Autonomous Decision-Making (Brain)                               │
└─────────────────────────────────────────────────────────────────────┘
│
┌─────────────────────────────────────────────────────────────────────┐
│              LAYER 2: C2 FRAMEWORK (Go/Rust)                               │
│ - Implant (Windows/Linux/macOS/Android)                                    │
│ - Teamserver (HTTP/HTTPS/WebSocket/DNS/SMB listeners)                                  │
│ - Malleable C2 Profile (Teams/Office365/Google mimicry)                        │
│ - SMB Beacon (lateral movement tanpa internet)                             │
│ - The Decoy (deception layer)                              │
└─────────────────────────────────────────────────────────────────────┘
│
┌─────────────────────────────────────────────────────────────────────┐
│              LAYER 1: INFRASTRUCTURE (Terraform/Ansible)                           │
│ - VPS provisioning + WireGuard + firewall                          │
│ - Functional Separation (4 VPC nodes)                              │
│ - Nginx redirector (URI routing, decoy)                        │
└─────────────────────────────────────────────────────────────────────┘


```


---


## 3. MODUL INTI (LAYER 1–5)

### 3.1 C2 Framework (98+ Agents + Malleable Profile + SMB Beacon)


#### Struktur File


```text
ANGEL-C2/
├── implant/
│ ├── windows/
│ │ ├── implant_main.go             # Entry point implant Windows
│ │ ├── implant_config.go           # Konfigurasi (server, key, interval)
│ │ ├── implant_register.go         # Register ke C2 (POST /api/v1/register)
│ │ ├── implant_task.go            # Ambil task (GET /api/v1/task)
│ │ ├── implant_result.go          # Kirim hasil (POST /api/v1/result)
│ │ ├── implant_crypto.go           # ECDH + AES-256-GCM
│ │ ├── implant_sleep.go            # Sleep jitter + masking
│ │ ├── implant_inject.go          # Process injection (APC, CreateRemoteThread)
│ │ └── implant_persistence.go # Registry, service, scheduled task
│ ├── linux/
│ │ ├── implant_main.go
│ │ ├── implant_config.go
│ │ ├── implant_register.go
│ │ ├── implant_task.go
│ │ ├── implant_result.go
│ │ ├── implant_crypto.go
│ │ └── implant_persistence.go # Cron, systemd, rc.local
│ ├── darwin/
│ │ ├── implant_main.go
│ │ ├── implant_config.go
│ │ ├── implant_register.go
│ │ ├── implant_task.go
│ │ ├── implant_result.go
│ │ ├── implant_crypto.go
│ │ └── implant_persistence.go # LaunchDaemons, LaunchAgents
│ └── android/
│     ├── implant_main.go
│     ├── implant_config.go
│     ├── implant_register.go
│     ├── implant_task.go
│     ├── implant_result.go
│     ├── implant_crypto.go
│     └── implant_persistence.go # Magisk, BOOT_COMPLETED
│
├── malleable/
│ ├── profile_loader.go           # Load & parse YAML profile
│ ├── profiles/
│ │ ├── teams.yaml                # Mimic Microsoft Teams traffic
│ │ ├── office.yaml              # Mimic Office365 traffic
│ │ ├── google.yaml               # Mimic Google traffic
│ │ └── custom.yaml               # Custom profile
│ ├── http_get.go               # Konfigurasi URI, headers, User-Agent
│ ├── http_post.go               # Konfigurasi URI, headers, body
│ ├── metadata.go                 # Encoding/decoding metadata agent
│ └── tls.go                  # Custom TLS certificate (JA3 spoofing)
│
├── server/
│ ├── listener/
│ │ ├── http.go                # Listener HTTP (port 80/8080)
│ │ ├── https.go                # Listener HTTPS (port 443)
│ │ ├── websocket.go               # Listener WebSocket (real-time)
│ │ ├── dns.go                  # Listener DNS (backup)
│ │ ├── smb.go                  # Listener SMB (untuk SMB Beacon)
│ │ └── tor.go                 # Listener Tor (anonymity)
│ ├── task/
│ │ ├── queue.go                 # Task queue (in-memory + SQLite)
│ │ ├── scheduler.go              # Scheduler (time-based, event-based)
│ │ └── result.go               # Result store (in-memory + SQLite)
│ ├── crypto/
│ │ ├── ecdh.go                 # ECDH key exchange (secp256r1)
│ │ ├── aes.go                  # AES-256-GCM per message
│ │ ├── hmac.go                  # HMAC-SHA256 integrity
│ │ └── cert.go                # Certificate generation & validation
│ ├── database/
│ │ ├── sqlite.go               # SQLite connection
│ │ ├── models.go                # Models: Agent, Task, Result
│ │ └── migrations.go             # Database migrations
│ └── api/
│     ├── routes.go             # Route definitions
│     ├── handlers.go            # HTTP handlers (register, task, result)
│     └── middleware.go           # Auth middleware, logging, rate limiting
│
├── smb_beacon/
│ ├── smb_beacon.go                 # SMB beacon via named pipe
│ ├── named_pipe.go                # Named pipe handler (Windows)
│ └── peer_to_peer.go              # P2P communication antar beacon
│
├── brain/
│ ├── autonomous_decision.go           # Autonomous decision engine
│ ├── risk_assessment.go             # Risk analysis

│ ├── behavior_learning.go           # Learn from past decisions
│ └── timing_control.go            # Adaptive timing
│
└── console/
├── terminal/
│ ├── main.go                 # Terminal entry point
│ ├── commands.go                # Command definitions
│ └── autocomplete.go            # Autocomplete
├── dashboard/
│ ├── main.go                 # Dashboard entry point
│ ├── agents.go               # Agent list UI
│ └── reports.go              # Report viewer UI
└── api/
├── client.go            # API client untuk dashboard
└── auth.go              # Authentication untuk dashboard
```


Penjelasan Teknis


Komponen Fungsi Input Process Output Evidence
Implant Agent di target Server URL, AES key, sleep interval Register → Task → Result loop Status, output Hash chain + timestamp
Malleable Profile Menyamar sebagai traffic Teams/Office YAML config Load, parse, apply ke HTTP client Traffic pattern Screenshot traffic
Teamserver Listener multi-protokol HTTP request Parse request, validate, route ke handler Response Log request/response
SMB Beacon Komunikasi internal tanpa outbound Named pipe Read/write pipe, relay ke HTTP beacon Task/result Log named pipe
Crypto Enkripsi & integrity Plaintext + key ECDH → AES-GCM → HMAC Ciphertext + MAC Hash chain
Database Persistence Agent/Task/Result SQL insert/select Data Query log
Brain Autonomous decision Environment + history Analyze → risk → decide Action Decision log


Flowchart Pengerjaan (Layer 1)


```text
[START]
│
▼
[1] Buat folder struktur C2
│
▼
[2] Implementasi server listener (HTTP/HTTPS/WebSocket/DNS/SMB)
│
▼
[3] Implementasi crypto (ECDH + AES + HMAC)
│
▼
[4] Implementasi database (SQLite + models + migrations)
│
▼
[5] Implementasi API (routes + handlers + middleware)
│
▼
[6] Implementasi implant (Windows/Linux/macOS/Android)
│
▼
[7] Implementasi malleable profile (teams/office/google)
│
▼
[8] Implementasi SMB beacon (named pipe + P2P)
│
▼
[9] Implementasi brain (autonomous decision + risk + learning)
│
▼
[10] Implementasi console (terminal + dashboard + API client)
│
▼
[END]
```


---


3.2 The Decoy / Deception Layer


Struktur File


```text
ANGEL-C2/
└── server/
├── decoy/
│ ├── decoy_page.go              # Decoy HTML page (NexaCloud style)
│ ├── decoy_routes.go            # Routes yang menampilkan decoy
│ └── decoy_headers.go             # Spoofed headers (Server: nginx/1.24.0)
└── gateway/
├── header_validation.go       # Validasi X-Operator-Key
└── route_selector.go         # Route berdasarkan visitor type
```


Penjelasan Teknis


Visitor Type Header Route Yang Dilihat
Agent X-Beacon-Token /api/v1/* Beacon endpoints

Operator X-Operator-Key /admin/* Dashboard
Analyst/scanner Tanpa header /* Decoy site (NexaCloud)
Siapa pun Tanpa header /login 404 Not Found


Flowchart Pengerjaan (Layer 2)


```text
[START]
│
▼
[1] Implementasi decoy_page.go (HTML + CSS)
│
▼
[2] Implementasi decoy_routes.go (route handler)
│
▼
[3] Implementasi decoy_headers.go (spoofed headers)
│
▼
[4] Implementasi header_validation.go (token check)
│
▼
[5] Implementasi route_selector.go (route logic)
│
▼
[END]
```


---


3.3 SQL Injection Engine (Full Coverage)


Struktur File


```text
ANGEL-SQLI/
├── detectors/
│ ├── boolean_blind.go             # Boolean-based blind inference
│ ├── time_based.go               # Time-based (SLEEP/BENCHMARK)
│ ├── error_based.go              # Error-based (extract via error message)
│ ├── union_based.go               # UNION-based (append SELECT)
│ ├── stacked_query.go             # Stacked queries (multiple statements)
│ ├── oob_dns.go                 # Out-of-band via DNS
│ ├── oob_http.go                # Out-of-band via HTTP
│ └── oob_icmp.go                # Out-of-band via ICMP
│
├── exploits/
│ ├── mysql/
│ │ ├── file_read.go             # LOAD_FILE()
│ │ ├── file_write.go           # INTO OUTFILE
│ │ ├── os_command.go                # sys_exec(), sys_eval()
│ │ ├── udf_inject.go            # UDF injection
│ │ ├── user_extract.go           # mysql.user
│ │ └── database_extract.go          # information_schema
│ ├── postgresql/
│ │ ├── file_read.go             # pg_read_file()
│ │ ├── file_write.go           # COPY TO/FROM
│ │ ├── os_command.go                # COPY TO PROGRAM
│ │ ├── user_extract.go           # pg_shadow
│ │ └── database_extract.go          # pg_database
│ ├── mssql/
│ │ ├── file_read.go             # OPENROWSET
│ │ ├── file_write.go           # xp_cmdshell
│ │ ├── os_command.go                # xp_cmdshell
│ │ ├── clr_assembly.go            # CLR assembly
│ │ ├── user_extract.go           # sys.sql_logins
│ │ └── database_extract.go          # sys.databases
│ ├── oracle/
│ │ ├── file_read.go             # UTL_FILE
│ │ ├── file_write.go           # UTL_FILE
│ │ ├── os_command.go                # Java stored procedures
│ │ ├── user_extract.go           # DBA_USERS
│ │ └── database_extract.go          # ALL_TABLES
│ └── sqlite/
│     ├── file_read.go         # load_extension()
│     ├── file_write.go        # ATTACH DATABASE
│     └── database_extract.go       # sqlite_master
│
├── waf_bypass/
│ ├── hex_encoding.go              # 0x55534552
│ ├── char_function.go            # CHAR(85,83,69,82)
│ ├── unicode_encoding.go            # %u0055
│ ├── double_url_encoding.go          # %2527
│ ├── case_variation.go            # SeLeCt
│ ├── comment_insertion.go           # /*!50000*/
│ ├── whitespace_variation.go        # %09, %0a, %0b
│ ├── json_body.go               # JSON body injection
│ ├── graphql_parameter.go           # GraphQL parameter injection
│ ├── xml_parameter.go              # XML parameter injection

│ ├── multipart_form.go            # Multipart form injection
│ └── user_agent_rotation.go         # Rotate UA per request
│
├── targets/
│ ├── url_parser.go              # Parse URL parameter
│ ├── form_parser.go              # Parse form parameter
│ ├── api_parser.go              # Parse API parameter
│ ├── graphql_parser.go            # Parse GraphQL query
│ └── websocket_parser.go            # Parse WebSocket message
│
└── reports/
├── evidence_collector.go        # Capture request/response + screenshot
├── report_generator.go         # Generate report
└── redaction_filter.go       # Redact PII/secret
```


Penjelasan Teknis


Sub-Modul Fungsi Teknologi
Detectors Boolean-blind (bit-by-bit inference), Time-based (force sleep + threshold), Error-based (parse error messages), UNION-based (append SELECT), Stacked (multiple statements), OOB (DNS/HTTP/ICMP exfil) Go
Exploits Per-DBMS: MySQL (file read/write, UDF, sys_exec), PostgreSQL (COPY TO PROGRAM), MSSQL (xp_cmdshell, CLR), Oracle (Java stored procedures), SQLite (load_extension) Go
WAF Bypass 12+ evasion modules: Hex encoding, CHAR(), unicode, double URL encoding, JSON/GraphQL/XML injection, user-agent rotation Go


Flowchart Pengerjaan (Layer 3)


```text
[START]
│
▼
[1] Implementasi detectors (boolean, time, error, union, stacked, OOB)
│
▼
[2] Implementasi exploits per DBMS (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
│
▼
[3] Implementasi WAF bypass (12+ modules)
│
▼
[4] Implementasi target parsers (URL, form, API, GraphQL, WebSocket)
│
▼
[5] Implementasi report generators (evidence + report + redaction)
│
▼
[END]
```


---


3.4 NoSQL Injection Engine


Struktur File


```text
ANGEL-NOSQLI/
├── mongodb/
│ ├── auth_bypass.go               # $ne, $gt injection
│ ├── boolean_blind.go             # Boolean-based blind
│ ├── time_based.go               # Time-based (sleep)
│ ├── js_injection.go            # JavaScript injection
│ ├── $lookup_exfil.go            # Aggregation pipeline exfil
│ └── error_based.go              # Error-based injection
├── elasticsearch/
│ ├── query_injection.go           # Query injection
│ ├── aggregation_exfil.go         # Aggregation exfil
│ └── script_injection.go         # Lucene script injection
├── couchdb/
│ ├── auth_bypass.go               # Auth bypass
│ └── js_injection.go            # JavaScript injection
├── redis/
│ ├── command_injection.go            # Command injection
│ └── key_dump.go                 # Dump keys
└── cassandra/
├── cql_injection.go         # CQL injection
└── user_extract.go           # Extract user data
```


Penjelasan Teknis


Sub-Modul Fungsi Teknologi
MongoDB Auth bypass ($ne, $gt), Boolean blind, Time-based, JS injection, $lookup exfil Go
Elasticsearch Query injection, Aggregation exfil, Lucene script injection Go
Redis Command injection, Key dump Go


Flowchart Pengerjaan (Layer 4)


```text
[START]
│

▼
[1] Implementasi MongoDB (auth bypass, boolean, time, js, lookup, error)
│
▼
[2] Implementasi Elasticsearch (query, aggregation, script)
│
▼
[3] Implementasi CouchDB (auth bypass, js injection)
│
▼
[4] Implementasi Redis (command injection, key dump)
│
▼
[5] Implementasi Cassandra (CQL injection, user extract)
│
▼
[END]
```


---


3.5 Database Post-Exploitation (khunt-style)


Struktur File


```text
ANGEL-DB-POST/
├── oracle/
│ ├── java_object_inject.go        # CREATE JAVA SOURCE
│ ├── java_object_compile.go         # Compile Java object
│ ├── java_object_exec.go           # KhuntCmd (OS command via cmd.exe)
│ ├── hash_extract.go             # KhuntHash (extract password hashes)
│ ├── file_system.go             # KhuntFS (file system enumeration)
│ ├── archive_extract.go          # KhuntUnzip (unzip archive)
│ └── registry_dump.go             # Dump registry
├── mysql/
│ ├── udf_install.go            # Install UDF
│ ├── os_command.go                 # sys_exec, sys_eval
│ ├── user_extract.go            # mysql.user
│ ├── file_system.go             # File system access
│ └── registry_dump.go             # Dump registry
├── postgresql/
│ ├── copy_program.go              # COPY TO PROGRAM
│ ├── user_extract.go            # pg_shadow
│ ├── file_system.go             # File system access
│ └── os_command.go                 # OS command
├── mssql/
│ ├── xp_cmdshell.go              # xp_cmdshell
│ ├── clr_assembly_load.go          # CLR assembly
│ ├── user_extract.go            # sys.sql_logins
│ ├── file_system.go             # File system access
│ └── registry_dump.go             # Dump registry
└── common/
├── backup_mechanisms.go            # Find backup mechanisms
├── vault_credentials.go       # Extract vault credentials
└── persistence_admin.go         # Create admin persistence
```


Penjelasan Teknis


Sub-Modul Fungsi Teknologi
Oracle Java object injection, KhuntCmd (OS command via cmd.exe dengan SYSTEM), KhuntHash (extract hash), KhuntFS (file system) Java/Go
MySQL UDF install (sys_exec, sys_eval), File system, User extract Go
PostgreSQL COPY TO PROGRAM (OS command), User extract (pg_shadow) Go
MSSQL xp_cmdshell, CLR assembly, User extract (sys.sql_logins) Go


Flowchart Pengerjaan (Layer 5)


```text
[START]
│
▼
[1] Implementasi Oracle (Java object inject, compile, exec, hash, fs)
│
▼
[2] Implementasi MySQL (UDF, os_command, user_extract, fs)
│
▼
[3] Implementasi PostgreSQL (COPY TO PROGRAM, user_extract, fs)
│
▼
[4] Implementasi MSSQL (xp_cmdshell, CLR, user_extract, fs)
│
▼
[5] Implementasi common (backup, vault, persistence)
│
▼
[END]
```

---


4. MODUL LANJUTAN (LAYER 6–10)


4.1 C2 Evasion & Stealth


Struktur File


```text
ANGEL-EVASION/
├── syscall/
│ ├── hells_gate.go              # PEB walk, SSN resolution
│ ├── syscall_ret_gadget.go         # syscall;ret
│ ├── indirect_syscall.go         # Indirect syscall
│ ├── nt_function.go             # NtCreateProcessEx, dll
│ └── unhook_ntdll.go             # Restore ntdll .text
├── sleep_masking/
│ ├── virtualprotect.go          # PAGE_NOACCESS + RC4
│ ├── thread_spoof.go             # Thread Stack Spoofing
│ ├── exception_handler.go          # Exception handler approach
│ ├── guard_page_removal.go            # Guard page removal
│ ├── stomping.go                # Module stomping
│ ├── callback.go               # Callback-based masking
│ └── encrypt_fragments.go           # Encrypt fragments
├── amsi_etw/
│ ├── hardware_breakpoint.go          # Patchless bypass
│ ├── inprocess_patch.go            # AMSI/ETW in-process
│ ├── registry_disable.go         # Registry disable
│ └── session_hijack.go            # Session hijack
├── anti_analysis/
│ ├── anti_debug/
│ │ ├── isdebuggerpresent.go         # IsDebuggerPresent
│ │ ├── ntglobalflag.go           # NtGlobalFlag
│ │ ├── peb_beingdebugged.go           # PEB BeingDebugged
│ │ ├── hardware_bp_check.go           # Hardware breakpoint check
│ │ └── timing_checks.go            # Timing checks
│ ├── anti_vm/
│ │ ├── hypervisor_detect.go         # Hypervisor detect
│ │ ├── cpuid_check.go             # CPUID check
│ │ ├── device_check.go             # Device check
│ │ ├── process_check.go            # Process check
│ │ └── mac_check.go               # MAC check
│ └── anti_sandbox/
│     ├── uptime_check.go          # Uptime check
│     ├── mouse_check.go            # Mouse check
│     ├── disk_size_check.go        # Disk size check
│     ├── core_count_check.go        # Core count check
│     └── memory_check.go           # Memory check
├── process_injection/
│ ├── crt_injection.go           # CreateRemoteThread
│ ├── apc_injection.go            # APC injection
│ ├── process_hollowing.go           # Process hollowing
│ ├── thread_hijacking.go          # Thread hijacking
│ ├── module_stomping.go             # Module stomping
│ ├── reflective_dll.go          # Reflective DLL
│ └── section_mapping.go            # Section mapping
├── log_cleanup/
│ ├── wevtutil_clear.go          # Clear event logs
│ ├── audit_clear.go             # Clear audit logs
│ ├── usn_journal_clear.go          # Clear USN journal
│ ├── prefetch_clear.go           # Clear prefetch
│ ├── shell_history_clear.go       # Clear shell history
│ └── forensic_artifact_clear.go # Clear forensic artifacts
└── network_evasion/
├── ip_rotation.go           # Rotate IP
├── proxy_chain.go            # Proxy chain
├── user_agent_rotation.go        # Rotate User-Agent
├── tls_fingerprint_rotation.go # Rotate TLS fingerprint
├── dns_rotation.go           # Rotate DNS
└── vpn_integration.go         # VPN integration
```


Penjelasan Teknis


Komponen Fungsi Teknologi
Syscall Hell's Gate (PEB walk, SSN resolution), Indirect syscall (hindari EDR hooks), Unhook ntdll Go/ASM
Sleep Masking 7 methods: VirtualProtect (PAGE_NOACCESS + RC4), Thread Stack Spoofing, Exception handler, Stomping, Guard page removal, Callback, Encrypt fragments Go/ASM
AMSI/ETW Hardware breakpoint (patchless), In-process patch, Registry disable, Session hijack Go/ASM
Anti Analysis Anti-debug (IsDebuggerPresent, PEB BeingDebugged), Anti-VM (CPUID, hypervisor), Anti-sandbox (uptime, mouse, disk) Go
Process Injection 7 methods: CRT, APC, Hollowing, Thread hijacking, Module stomping, Reflective DLL, Section mapping Go
Log Cleanup wevtutil.exe, Audit clear, USN journal clear, Prefetch clear, Shell history Go
Network Evasion IP rotation, Proxy chain, User-Agent rotation, TLS fingerprint rotation, DNS rotation, VPN Go


Flowchart Pengerjaan (Layer 6)


```text
[START]
│

▼
[1] Implementasi syscall (Hell's Gate, indirect, unhook)
│
▼
[2] Implementasi sleep masking (7 methods)
│
▼
[3] Implementasi AMSI/ETW bypass (hardware bp, in-process, registry)
│
▼
[4] Implementasi anti-analysis (debug, VM, sandbox)
│
▼
[5] Implementasi process injection (7 methods)
│
▼
[6] Implementasi log cleanup (wevtutil, audit, USN, prefetch)
│
▼
[7] Implementasi network evasion (IP, proxy, UA, TLS, DNS, VPN)
│
▼
[END]
```


---


4.2 Kerberos & Active Directory Attack


Struktur File


```text
ANGEL-AD/
├── kerberos/
│ ├── golden_ticket.go            # KRBTGT hash → domain-wide
│ ├── silver_ticket.go          # Service account hash
│ ├── shadow_credentials.go           # Alternative key credential
│ ├── skeleton_key.go             # Universal password
│ ├── kerberoast.go              # TGS request → hashcat
│ ├── asrep_roast.go              # NO credentials needed
│ ├── ticket_inject.go          # Pass-the-Ticket
│ ├── ticket_dump.go              # Extract tickets
│ ├── ptt_rdp.go               # RDP via injected ticket
│ └── ptt_psexec.go              # PsExec via injected ticket
├── ad_recon/
│ ├── domain_enum.go                # Domain enumeration
│ ├── user_enum.go                # User enumeration
│ ├── group_enum.go                # Group enumeration
│ ├── spn_enum.go                 # SPN enumeration
│ ├── gpo_enum.go                 # GPO enumeration
│ ├── ous_enum.go                 # OU enumeration
│ ├── trust_enum.go               # Trust enumeration
│ └── site_enum.go               # Site enumeration
├── ad_exploit/
│ ├── admin_sd_holder.go             # AdminSDHolder abuse
│ ├── dcsync.go                 # DCSync (NTDS extraction)
│ ├── delegation_abuse.go            # Delegation abuse
│ ├── constrained_delegation.go       # Constrained delegation
│ ├── unconstrained_delegation.go # Unconstrained delegation
│ ├── resource_based_delegation.go # Resource-based delegation
│ └── adcs/
│     ├── esc1.go              # ESC1
│     ├── esc2.go              # ESC2
│     ├── esc3.go              # ESC3
│     ├── esc4.go              # ESC4
│     ├── esc5.go              # ESC5
│     ├── esc6.go              # ESC6
│     ├── esc7.go              # ESC7
│     ├── esc8.go              # ESC8
│     ├── esc9.go              # ESC9
│     ├── esc10.go              # ESC10
│     ├── esc11.go             # ESC11
│     ├── esc12.go              # ESC12
│     ├── esc13.go              # ESC13
│     ├── esc14.go              # ESC14
│     ├── esc15.go              # ESC15
│     └── esc16.go              # ESC16
│ └── zero_logon.go               # ZeroLogon
├── ad_persistence/
│ ├── golden_ticket_persist.go       # Golden ticket persist
│ ├── shadow_cred_persist.go          # Shadow cred persist
│ ├── admin_sd_holder_persist.go # AdminSDHolder persist
│ └── dcsync_persist.go            # DCSync persist
```


Penjelasan Teknis


Komponen Fungsi Teknologi
Kerberos Golden Ticket (KRBTGT hash), Silver Ticket (service hash), Shadow Credentials, Kerberoast, AS-REP Roast, Pass-the-Ticket Go

AD Recon Domain enum, User enum, Group enum, SPN enum, GPO enum, OU enum, Trust enum, Site enum Go
AD Exploit DCSync (NTDS), Delegation abuse, ADCS (ESC1-16), ZeroLogon Go
AD Persistence Golden ticket persist, Shadow cred persist, DCSync persist Go


Flowchart Pengerjaan (Layer 7)


```text
[START]
│
▼
[1] Implementasi kerberos (golden, silver, shadow, kerberoast, AS-REP)
│
▼
[2] Implementasi ad_recon (domain, user, group, SPN, GPO, OU)
│
▼
[3] Implementasi ad_exploit (DCSync, delegation, ADCS ESC1-16, ZeroLogon)
│
▼
[4] Implementasi ad_persistence (golden, shadow, admin, dcsync)
│
▼
[END]
```


---


4.3 Lateral Movement


Struktur File


```text
ANGEL-LATERAL/
├── smb/
│ ├── smb_enum.go                  # SMB enumeration
│ ├── smb_auth.go                # SMB authentication
│ ├── smb_exec.go                 # PsExec-style
│ ├── smb_copy.go                 # File copy
│ └── smb_passthrough.go             # Pass-the-Hash
├── smb_beacon/
│ ├── smb_beacon.go                # SMB beacon via named pipe
│ ├── named_pipe.go                # Named pipe handler
│ └── peer_to_peer.go             # Peer-to-peer communication
├── wmi/
│ ├── wmi_enum.go                 # WMI enumeration
│ ├── wmi_auth.go                # WMI authentication
│ ├── wmi_exec.go                 # WMI execution
│ └── wmi_persist.go              # WMI persistence
├── winrm/
│ ├── winrm_auth.go               # WinRM authentication
│ ├── winrm_exec.go               # WinRM execution
│ └── winrm_shell.go              # WinRM shell
├── dcom/
│ ├── dcom_exec.go                # DCOM execution
│ └── dcom_persist.go             # DCOM persistence
├── rdp/
│ ├── rdp_auth.go                # RDP authentication
│ ├── rdp_connect.go              # RDP connection
│ └── rdp_tunnel.go              # RDP tunnel
├── ssh/
│ ├── ssh_auth.go                # SSH authentication
│ ├── ssh_exec.go                # SSH execution
│ └── ssh_tunnel.go              # SSH tunnel
├── powershell_remoting/
│ ├── ps_session.go               # PowerShell session
│ ├── ps_exec.go                 # PowerShell execution
│ └── ps_scriptblock.go           # PowerShell scriptblock
└── pivoting/
├── socks5_proxy.go           # SOCKS5 proxy
├── port_forward.go          # Port forwarding
├── tcp_tunnel.go           # TCP tunnel
├── dns_tunnel.go           # DNS tunnel
└── icmp_tunnel.go           # ICMP tunnel
```


Penjelasan Teknis


Komponen Fungsi Teknologi
SMB Enumeration, Authentication, PsExec-style, File copy, Pass-the-Hash Go
SMB Beacon SMB beacon via named pipe, Peer-to-peer Go
WMI Enumeration, Authentication, Execution, Persistence Go
WinRM Authentication, Execution, Shell Go
Pivoting SOCKS5, Port forwarding, TCP/DNS/ICMP tunnel Go


Flowchart Pengerjaan (Layer 8)


```text
[START]
│

▼
[1] Implementasi SMB (enum, auth, exec, copy, pass-the-hash)
│
▼
[2] Implementasi SMB Beacon (named pipe, P2P)
│
▼
[3] Implementasi WMI (enum, auth, exec, persist)
│
▼
[4] Implementasi WinRM (auth, exec, shell)
│
▼
[5] Implementasi DCOM (exec, persist)
│
▼
[6] Implementasi RDP (auth, connect, tunnel)
│
▼
[7] Implementasi SSH (auth, exec, tunnel)
│
▼
[8] Implementasi PowerShell Remoting (session, exec, scriptblock)
│
▼
[9] Implementasi pivoting (SOCKS5, port forward, TCP/DNS/ICMP tunnel)
│
▼
[END]
```


---


4.4 Persistence


Struktur File


```text
ANGEL-PERSIST/
├── windows/
│ ├── registry.go            # Registry operations
│ ├── scheduled_task.go            # Scheduled task
│ ├── service.go              # Service creation
│ ├── wmi.go                 # WMI subscription
│ ├── startup_folder.go          # Startup folder
│ ├── ads.go                 # Alternate Data Streams
│ ├── dll_sideload.go            # DLL sideloading
│ └── uefi/
│     ├── dxe_inject.go          # UEFI DXE injection
│     ├── boot_chain_hook.go        # Boot chain hook
│     └── secureboot_bypass.go        # Secure Boot bypass
├── linux/
│ ├── cron.go                # Cron job
│ ├── systemd.go                 # Systemd service + timer
│ ├── rc_local.go             # rc.local
│ ├── profile.go             # Profile injection
│ ├── bashrc.go               # bashrc injection
│ ├── ssh_authorized_keys.go          # SSH authorized keys
│ ├── pam_inject.go              # PAM injection
│ └── udev.go                # Udev rule
├── darwin/
│ ├── launchdaemons.go              # LaunchDaemons
│ ├── launchagents.go             # LaunchAgents
│ ├── cron.go                # Cron
│ └── ssh_authorized_keys.go          # SSH authorized keys
└── android/
├── magisk_module.go             # Magisk module
├── boot_completed.go            # BOOT_COMPLETED
├── foreground_service.go        # Foreground service
└── device_admin.go           # Device admin
```


Penjelasan Teknis


OS Metode Teknologi
Windows Registry, Scheduled Task, Service, WMI, Startup Folder, ADS, DLL Sideload, UEFI Go
Linux Cron, Systemd, rc.local, Profile, bashrc, SSH keys, PAM, Udev Go
macOS LaunchDaemons, LaunchAgents, Cron, SSH keys Go
Android Magisk, BOOT_COMPLETED, Foreground service, Device admin Go


Flowchart Pengerjaan (Layer 9)


```text
[START]
│
▼
[1] Implementasi Windows persistence (registry, task, service, WMI, startup, ADS, DLL, UEFI)
│
▼

[2] Implementasi Linux persistence (cron, systemd, rc.local, profile, bashrc, SSH, PAM, udev)
│
▼
[3] Implementasi macOS persistence (launchdaemons, launchagents, cron, SSH)
│
▼
[4] Implementasi Android persistence (magisk, boot_completed, service, device_admin)
│
▼
[END]
```


---


4.5 Hardware Rootkit


Struktur File


```text
ANGEL-ROOTKIT/
├── uefi/
│ ├── dxe_driver.go             # UEFI DXE driver injection
│ ├── boot_hook.go                # Hook bootmgfw.efi → winload.efi
│ ├── osl_hook.go               # Hook OslArchTransferToKernel
│ ├── cm_hook.go                  # Hook CmGetSystemDriverList
│ ├── secureboot_bypass.go           # Secure Boot bypass
│ ├── mok_enroll.go               # Enroll malicious MOK
│ ├── self_reinstall.go        # SMM self-reinstall
│ ├── persistence_esp.go            # Persistence di EFI System Partition
│ └── clean_shim_exploit.go         # Vulnerable shim exploit
├── smm/
│ ├── handler_inject.go           # SMM handler injection
│ ├── smram_exploit.go             # SMRAM exploit
│ ├── rop_chain.go              # SMM ROP/JOP chains
│ ├── interrupt_hook.go           # Hook hardware interrupts
│ └── self_reinstall.go        # Reinstall if UEFI removed
└── firmware/
├── spi_flash_read.go         # SPI flash read
├── spi_flash_write.go        # SPI flash write
├── jtag_debug.go            # JTAG debug
├── uart_console.go           # UART console
└── firmware_emulation.go         # Firmware emulation
```


Penjelasan Teknis


Komponen Fungsi Teknologi
UEFI DXE driver injection, Boot chain hook, OSL hook, Secure Boot bypass, MOK enroll, Self-reinstall UEFI C/ASM
SMM SMM handler injection, SMRAM exploit, ROP/JOP chains, Interrupt hooks, Self-reinstall UEFI C/ASM
Firmware SPI Flash read/write, JTAG debug, UART console, Firmware emulation Python/C


Flowchart Pengerjaan (Layer 10)


```text
[START]
│
▼
[1] Implementasi UEFI (DXE, boot hook, OSL hook, Secure Boot bypass, MOK)
│
▼
[2] Implementasi SMM (handler inject, SMRAM, ROP, interrupt hook)
│
▼
[3] Implementasi firmware (SPI, JTAG, UART, emulation)
│
▼
[END]
```


---


5. MODUL OFENSIF (LAYER 11–15)


5.1 Credential Theft


Struktur File


```text
ANGEL-CRED/
├── windows/
│ ├── lsass/
│ │ ├── fork_dump.go              # Fork dump (NtCreateProcessEx)
│ │ ├── minidump.go               # Minidump
│ │ ├── procdump.go               # Procdump
│ │ └── nanodump.go                # Nanodump
│ ├── sam/
│ │ ├── registry_dump.go            # Registry dump
│ │ └── hive_extract.go           # Hive extraction
│ ├── security/

│ │ └── registry_dump.go              # Registry dump
│ ├── browser/
│ │ ├── chrome.go                # Chrome password extraction
│ │ ├── firefox.go             # Firefox password extraction
│ │ ├── edge.go                # Edge password extraction
│ │ └── opera.go                # Opera password extraction
│ ├── dpapi/
│ │ └── decrypt.go              # DPAPI decryption
│ └── clipboard/
│     └── capture.go           # Clipboard capture
├── linux/
│ ├── shadow/
│ │ └── extract.go             # Shadow extraction
│ ├── history/
│ │ ├── bash_history.go              # Bash history
│ │ └── zsh_history.go            # Zsh history
│ ├── ssh/
│ │ └── private_key.go            # SSH private keys
│ └── browser/
│     ├── chrome.go             # Chrome password extraction
│     └── firefox.go          # Firefox password extraction
├── macos/
│ ├── keychain_dump.go                # Keychain dump
│ └── browser.go                # Browser password extraction
└── cloud/
├── aws/
│ ├── credentials.go          # ~/.aws/credentials
│ └── metadata.go             # EC2 metadata
├── azure/
│ ├── msal_cache.go            # Azure MSAL cache
│ └── azure_cli.go           # Azure CLI
└── gcp/
├── adc.go              # Google Application Default Credentials
└── gcloud_cli.go         # GCloud CLI
```


Penjelasan Teknis


Komponen Fungsi Teknologi
Windows LSASS dump (fork, minidump, procdump, nanodump), SAM, Browser (Chrome/Firefox/Edge/Opera), DPAPI, Clipboard Go
Linux Shadow extract, bash/zsh history, SSH keys, Browser Go
Cloud AWS credentials, Azure MSAL cache, GCP ADC Go


Flowchart Pengerjaan (Layer 11)


```text
[START]
│
▼
[1] Implementasi Windows credential theft (LSASS, SAM, browser, DPAPI, clipboard)
│
▼
[2] Implementasi Linux credential theft (shadow, history, SSH, browser)
│
▼
[3] Implementasi macOS credential theft (keychain, browser)
│
▼
[4] Implementasi cloud credential theft (AWS, Azure, GCP)
│
▼
[END]
```


---


5.2 Collector / InfoStealer Module


Struktur File


```text
ANGEL-COLLECT/
├── browser/
│ ├── chrome.go                 # Chrome password recovery
│ ├── firefox.go              # Firefox password recovery
│ ├── edge.go                  # Edge password recovery
│ └── opera.go                 # Opera password recovery
├── screen/
│ ├── capture.go               # Screen capture
│ └── record.go                # Screen recording
├── keylog/
│ └── keylogger.go              # Keylogger
├── wifi/
│ └── wifi_password.go               # WiFi password recovery
├── webcam/
│ └── capture.go               # Webcam capture
└── clipboard/
└── capture.go              # Clipboard capture
```

Penjelasan Teknis


Komponen Fungsi Teknologi
Browser Password recovery dari Chrome, Firefox, Edge, Opera Go
Screen Screen capture, Screen recording Go
Keylog Keylogger untuk capture keystrokes Go
WiFi WiFi password recovery Go
Webcam Webcam capture Go
Clipboard Clipboard capture Go


Flowchart Pengerjaan (Layer 12)


```text
[START]
│
▼
[1] Implementasi browser (Chrome, Firefox, Edge, Opera)
│
▼
[2] Implementasi screen (capture, record)
│
▼
[3] Implementasi keylog (keylogger)
│
▼
[4] Implementasi wifi (password recovery)
│
▼
[5] Implementasi webcam (capture)
│
▼
[6] Implementasi clipboard (capture)
│
▼
[END]
```


---


5.3 Destruction & Impact


Struktur File


```text
ANGEL-DESTRUCT/
├── database/
│ ├── drop_schemas.go               # DROP TABLE / DROP SCHEMA
│ ├── drop_foreign_keys.go             # DROP FOREIGN KEYS
│ ├── encrypt_records.go           # JADEPUFFER-style AES_ENCRYPT
│ ├── corrupt_data.go             # MAD-CAT-style gibberish
│ ├── delete_backup.go             # Delete backup/restore points
│ └── disable_recovery.go          # Disable recovery
├── ransomware/
│ ├── encrypt_files.go           # Encrypt files
│ ├── encrypt_database.go              # Encrypt database
│ ├── ransom_note.go               # Ransom note
│ └── key_destroy.go              # Generate random key, TIDAK DISIMPAN
├── wiper/
│ ├── zero_overwrite.go           # Lotus Wiper-style
│ ├── random_overwrite.go              # PathWiper-style
│ ├── mbr_destroy.go              # Overwrite MBR
│ ├── mft_destroy.go             # Overwrite $MFT
│ ├── volume_dismount.go               # Volume dismount
│ ├── restore_point_delete.go          # Restore point delete
│ └── usn_journal_clear.go         # USN journal clear
├── availability/
│ ├── service_stop.go             # Service stop
│ ├── process_kill.go            # Process kill
│ └── network_flood.go            # Network flood
└── impact_measurement/
├── blast_radius.go          # Blast radius
├── recovery_time.go          # Recovery time
├── business_impact.go           # Business impact
└── severity_calc.go         # P0/P1 scoring
```


Penjelasan Teknis


Komponen Fungsi Teknologi
Database DROP SCHEMA, DROP TABLE, AES_ENCRYPT (JADEPUFFER-style), MAD-CAT-style corruption, Delete backups Go
Ransomware Encrypt files, Encrypt database, Ransom note, Random key NOT stored Go
Wiper Lotus Wiper (zero overwrite), PathWiper (random overwrite), MBR/$MFT destruction, USN journal clear Go
Impact Measurement Blast radius, Recovery time, Business impact, P0/P1 scoring Go


Flowchart Pengerjaan (Layer 13)


```text
[START]

│
▼
[1] Implementasi database destruction (drop, encrypt, corrupt, backup)
│
▼
[2] Implementasi ransomware (encrypt files, encrypt DB, ransom note)
│
▼
[3] Implementasi wiper (zero overwrite, random overwrite, MBR, MFT)
│
▼
[4] Implementasi availability (service stop, process kill, network flood)
│
▼
[5] Implementasi impact measurement (blast radius, recovery, business, severity)
│
▼
[END]
```


---


5.4 Orchestrator (Autonomous AI + MCP + Fireteam)


Struktur File


```text
ANGEL-ORCHESTRATOR/
├── core/
│ ├── orchestrator_main.go            # Orchestrator main
│ ├── orchestrator_config.go          # Orchestrator config
│ └── orchestrator_state.go          # Orchestrator state
├── router/
│ ├── intent_classifier.go         # Classify request → agent
│ ├── action_selector.go            # Pilih agent berdasarkan intent
│ └── task_dispatcher.go            # Dispatch task ke agent
├── agents/
│ ├── recon_agent.go                # Recon agent
│ ├── exploit_agent.go             # Exploit agent
│ ├── post_exploit_agent.go           # Post-exploit agent
│ ├── lateral_agent.go             # Lateral agent
│ └── destruction_agent.go           # Destruction agent
├── fireteam/
│ └── parallel_exec.go             # Multiple sub-agents in parallel
├── graph/
│ ├── neo4j.go                  # Attack surface mapping
│ ├── attack_path.go               # Path generator
│ └── blast_radius.go              # Impact mapper
├── mcp/
│ ├── metasploit.go               # MCP server for Metasploit
│ ├── hydra.go                  # MCP server for Hydra
│ ├── playwright.go               # MCP server for browser automation
│ ├── kali_shell.go              # MCP server for Kali shell
│ ├── nmap.go                    # MCP server for Nmap
│ ├── nuclei.go                 # MCP server for Nuclei
│ └── ffuf.go                 # MCP server for FFuf
└── ai/
├── langgraph.go               # Autonomous decision-making
├── react_pattern.go            # Reasoning + Acting
├── hypothesis_generator.go         # Attack path hypothesis
└── empirical_validation.go       # 100% verification via PoC
```


Penjelasan Teknis


Komponen Fungsi Teknologi
Intent Router Classify user request → route ke agent spesifik LangGraph
Agents ReconAgent (Subfinder, Nmap), SQLiAgent (boolean-blind, time-based), PostAgent (khunt-style), LateralAgent (Pass-the-Hash), DestroyAgent (encrypt, drop) Go
Fireteam Root agent fan-out ke multiple sub-agents in parallel Go
MCP Tool servers: Metasploit, Hydra, Playwright, Kali shell, Nmap, Nuclei, FFuf Go
AI LangGraph, ReAct pattern, Hypothesis generation, Empirical validation Go


Flowchart Pengerjaan (Layer 14)


```text
[START]
│
▼
[1] Implementasi core (main, config, state)
│
▼
[2] Implementasi router (intent classifier, action selector, dispatcher)
│
▼
[3] Implementasi agents (recon, exploit, post-exploit, lateral, destruction)
│
▼
[4] Implementasi fireteam (parallel exec)
│

▼
[5] Implementasi graph (neo4j, attack path, blast radius)
│
▼
[6] Implementasi MCP (metasploit, hydra, playwright, kali shell, nmap, nuclei, ffuf)
│
▼
[7] Implementasi AI (langgraph, react, hypothesis, validation)
│
▼
[END]
```


---


5.5 Autonomous Decision-Making (Brain)


Struktur File


```text
ANGEL-C2/
└── brain/
├── autonomous_decision.go           # Autonomous decision-making engine
├── risk_assessment.go           # Risk analysis
├── behavior_learning.go         # Learn from past decisions
└── timing_control.go          # Adaptive timing
```


Penjelasan Teknis


Komponen Fungsi Teknologi
Autonomous Decision Analyze environment and system state, decide next action Go
Risk Assessment Manage risk assessment for each action, decide "safe" vs "risky" Go
Behavior Learning Learn from past decisions, self-learning dari history Go
Timing Control Adaptive timing — jika environment suspicious, sleep longer Go


Flowchart Pengerjaan (Layer 15)


```text
[START]
│
▼
[1] Implementasi autonomous_decision.go
│
▼
[2] Implementasi risk_assessment.go
│
▼
[3] Implementasi behavior_learning.go
│
▼
[4] Implementasi timing_control.go
│
▼
[END]
```


---


6. INFRASTRUKTUR & PELAPORAN (LAYER 16–21)


6.1 Infrastructure (Terraform + Ansible + Functional Separation)


Struktur File


```text
ANGEL-INFRA/
├── terraform/
│ ├── main.tf                 # VPS provisioning
│ ├── variables.tf             # Variables
│ ├── outputs.tf               # Outputs
│ ├── modules/
│ │ ├── vpc_recon/                # VPC for recon
│ │ ├── vpc_phishing/              # VPC for phishing
│ │ ├── vpc_c2_https/              # VPC for HTTPS C2
│ │ └── vpc_c2_dns/                # VPC for DNS C2
│ └── environments/
│     ├── dev/                # Dev environment
│     ├── staging/             # Staging environment
│     └── production/           # Production environment
├── ansible/
│ ├── playbooks/
│ │ ├── site.yml               # Main playbook
│ │ ├── redirector.yml            # Redirector playbook
│ │ ├── teamserver.yml               # Teamserver playbook
│ │ ├── opsec.yml                # OPSEC playbook
│ │ └── logging.yml              # Logging playbook
│ ├── roles/
│ │ ├── recon_node/                # Recon node role

│ │ ├── phishing_node/              # Phishing node role
│ │ ├── c2_https_node/              # C2 HTTPS node role
│ │ ├── c2_dns_node/                # C2 DNS node role
│ │ ├── wireguard/                # WireGuard role
│ │ ├── nginx/                  # Nginx role
│ │ └── firewall/              # Firewall role
│ └── inventories/
│     ├── production/            # Production inventory
│     └── staging/              # Staging inventory
├── redirector/
│ ├── nginx.conf                 # Nginx config
│ ├── ssl_cert.go                # SSL certificate
│ ├── route.go                  # Route logic
│ ├── decoy_page.go                 # Decoy page
│ ├── header_validation.go           # Header validation
│ └── rate_limit.go              # Rate limiting
├── vpn/
│ ├── wireguard.go                # WireGuard
│ ├── openvpn.go                  # OpenVPN
│ └── ipsec.go                  # IPsec
└── rotation/
├── ip_rotation.go            # Ganti IP setiap detik
├── proxy_chain.go              # Proxy chain
├── user_agent_rotation.go         # User-Agent rotation
└── tls_fingerprint_rotation.go # TLS fingerprint rotation
```


Penjelasan Teknis


Komponen Fungsi Teknologi
Functional Separation 4 VPC nodes: VPC #1 (Recon & scanning), VPC #2 (Phishing), VPC #3 (HTTPS C2), VPC #4 (DNS C2) HCL
Terraform One-command provision VPS, modular architecture, Environment separation HCL
Ansible Configuration management (WireGuard, firewall, tooling), Idempotent deployment YAML
Nginx URI-based routing (/c2/* → Teamserver, /admin/* → Orchestrator, /* → decoy), SSL termination nginx.conf
Rotation Ganti IP setiap 3-5 detik, Proxy chain, User-Agent rotation, TLS fingerprint rotation Go


Flowchart Pengerjaan (Layer 16)


```text
[START]
│
▼
[1] Implementasi Terraform (main, variables, outputs, modules, environments)
│
▼
[2] Implementasi Ansible (playbooks, roles, inventories)
│
▼
[3] Implementasi Nginx redirector (config, ssl, route, decoy, header, rate limit)
│
▼
[4] Implementasi VPN (wireguard, openvpn, ipsec)
│
▼
[5] Implementasi rotation (IP, proxy, UA, TLS)
│
▼
[END]
```


---


6.2 OSINT & Reconnaissance


Struktur File


```text
ANGEL-OSINT/
├── dns/
│ ├── subdomain_enum.go                # Passive + active
│ ├── dns_reverse.go               # Reverse DNS
│ ├── dns_zone_transfer.go            # Zone transfer
│ ├── dns_bruteforce.go             # DNS brute force
│ └── dns_history.go              # DNS history
├── port/
│ ├── port_scan.go                # TCP/UDP scan
│ ├── service_fingerprint.go        # Service fingerprint
│ ├── banner_grab.go               # Banner grab
│ └── network_map.go                # Network map
├── web/
│ ├── tech_fingerprint.go          # Wappalyzer-style
│ ├── waf_detect.go               # WAF detect
│ ├── cms_detect.go                # CMS detect
│ ├── framework_detect.go             # Framework detect
│ ├── ssl_cert.go               # SSL certificate
│ └── robots_parse.go              # Robots.txt parse
├── person/
│ ├── email_harvest.go             # Email harvest
│ ├── social_media.go              # Social media

│ ├── git_recon.go               # Git recon
│ ├── linkedin_parser.go           # LinkedIn parser
│ └── breach_data.go               # Breach data
├── company/
│ ├── asn_lookup.go               # ASN lookup
│ ├── netblock_lookup.go            # Netblock lookup
│ ├── cert_transparency.go           # Certificate transparency
│ ├── crt_sh.go                # crt.sh
│ └── shodan.go                  # Shodan
└── cloud/
├── aws_bucket_enum.go             # AWS bucket enumeration
├── azure_blob_enum.go             # Azure blob enumeration
├── gcp_bucket_enum.go             # GCP bucket enumeration
└── public_s3.go             # Public S3
```


Penjelasan Teknis


Komponen Fungsi Teknologi
DNS Subdomain enumeration, Reverse DNS, Zone transfer, DNS history Go
Port TCP/UDP scanning, Service fingerprinting, Banner grabbing Go
Web Technology fingerprinting, WAF detection, CMS/framework detection Go
Person Email harvesting, Social media, Git recon, LinkedIn parser Go
Company ASN lookup, Netblock lookup, Certificate transparency, Shodan Go


Flowchart Pengerjaan (Layer 17)


```text
[START]
│
▼
[1] Implementasi DNS (subdomain, reverse, zone transfer, brute, history)
│
▼
[2] Implementasi Port (scan, fingerprint, banner, network map)
│
▼
[3] Implementasi Web (tech, WAF, CMS, framework, SSL, robots)
│
▼
[4] Implementasi Person (email, social, git, linkedin, breach)
│
▼
[5] Implementasi Company (ASN, netblock, cert, crt.sh, shodan)
│
▼
[6] Implementasi Cloud (AWS, Azure, GCP, S3)
│
▼
[END]
```


---


6.3 Exploitation


Struktur File


```text
ANGEL-EXPLOIT/
├── sql_injection/
│ ├── detectors/               # SQLi detectors
│ ├── exploits/               # SQLi exploits
│ └── waf_bypass/                # WAF bypass
├── nosql_injection/
│ ├── mongodb/                   # MongoDB injection
│ ├── elasticsearch/             # Elasticsearch injection
│ └── redis/                 # Redis injection
├── xss/
│ ├── reflected_xss.go            # Reflected XSS
│ ├── stored_xss.go               # Stored XSS
│ ├── dom_xss.go                  # DOM XSS
│ ├── blind_xss.go               # Blind XSS
│ ├── polyglot_payload.go           # Polyglot payload
│ └── cookie_steal.go             # Cookie steal
├── ssrf/
│ ├── internal_scan.go            # Internal scan
│ ├── cloud_metadata.go              # Cloud metadata
│ ├── file_read.go              # File read
│ └── port_scan.go               # Port scan
├── rce/
│ ├── command_injection.go            # Command injection
│ ├── code_injection.go            # Code injection
│ ├── deserialization.go          # Deserialization
│ └── template_injection.go         # Template injection
├── lfi_rfi/
│ ├── file_read.go              # File read
│ ├── file_write.go             # File write
│ └── remote_include.go             # Remote include

├── graphql/
│ ├── introspection.go             # Introspection
│ ├── nested_query.go               # Nested query
│ └── injection.go              # Injection
├── api/
│ ├── parameter_injection.go           # Parameter injection
│ ├── json_injection.go            # JSON injection
│ └── xml_injection.go             # XML injection
└── cve/
├── cve_scanner.go              # CVE scanner
├── cve_exploiter.go           # CVE exploiter
└── exploit_db.go             # Exploit DB
```


Penjelasan Teknis


Komponen Fungsi Teknologi
XSS Reflected, Stored, DOM, Blind, Polyglot payload, Cookie stealing Go
SSRF Internal port scan, Cloud metadata, File read Go
RCE Command injection, Code injection, Deserialization, Template injection Go
CVE Scanner, Exploiter, Exploit DB integration Go


Flowchart Pengerjaan (Layer 18)


```text
[START]
│
▼
[1] Implementasi SQL injection (detectors, exploits, WAF bypass)
│
▼
[2] Implementasi NoSQL injection (MongoDB, Elasticsearch, Redis)
│
▼
[3] Implementasi XSS (reflected, stored, DOM, blind, polyglot, cookie)
│
▼
[4] Implementasi SSRF (internal scan, cloud metadata, file read)
│
▼
[5] Implementasi RCE (command, code, deserialization, template)
│
▼
[6] Implementasi LFI/RFI (file read, file write, remote include)
│
▼
[7] Implementasi GraphQL (introspection, nested query, injection)
│
▼
[8] Implementasi API (parameter, JSON, XML injection)
│
▼
[9] Implementasi CVE (scanner, exploiter, exploit DB)
│
▼
[END]
```


---


6.4 Forensic Evidence


Struktur File


```text
ANGEL-EVIDENCE/
├── ledger/
│ ├── hash_chain.go                # Chain-of-custody
│ ├── timestamp.go                 # Timestamp
│ ├── sequence.go                  # Monotonic sequence
│ ├── parent_child.go              # Parent-child reference
│ └── signature.go               # Digital signature
├── collector/
│ ├── request_capture.go             # Request capture
│ ├── response_capture.go              # Response capture
│ ├── screenshot.go                # Screenshot
│ ├── diff_capture.go             # Before/after state
│ └── telemetry_reference.go           # SIEM correlation
├── redaction/
│ ├── pii_filter.go            # PII filter
│ ├── secret_filter.go           # Secret filter
│ ├── token_filter.go            # Token filter
│ └── cert_filter.go            # Certificate filter
├── storage/
│ ├── local_store.go              # Local storage
│ ├── encrypted_store.go             # Encrypted storage
│ └── s3_upload.go                 # S3 upload
└── verification/
├── independent_verify.go         # Independent verifier

├── replay_verify.go             # Replay verification
└── integrity_check.go            # Integrity check
```


Penjelasan Teknis


Komponen Fungsi Teknologi
Ledger Hash chain (setiap evidence ter-hash dan ter-link ke parent), Timestamp (UTC), Monotonic sequence, Digital signature Go
Collector Request/response capture, Screenshot, Before/after state diff, Telemetry reference Go
Redaction PII filter, Secret filter, Token filter, Certificate filter Go
Verification Independent verifier, Replay verification, Integrity check Go


Flowchart Pengerjaan (Layer 19)


```text
[START]
│
▼
[1] Implementasi ledger (hash chain, timestamp, sequence, parent-child, signature)
│
▼
[2] Implementasi collector (request, response, screenshot, diff, telemetry)
│
▼
[3] Implementasi redaction (PII, secret, token, cert)
│
▼
[4] Implementasi storage (local, encrypted, S3)
│
▼
[5] Implementasi verification (independent, replay, integrity)
│
▼
[END]
```


---


6.5 Reporting


Struktur File


```text
ANGEL-REPORT/
├── technical/
│ ├── report.go                   # Full report
│ ├── executive_summary.go                # Executive summary
│ ├── findings.go                  # Findings
│ ├── evidence.go                   # Evidence
│ ├── reproduction.go                 # Reproduction steps
│ ├── remediation.go                 # Remediation
│ └── timeline.go                  # Timeline
├── executive/
│ ├── summary.go                     # Summary
│ ├── impact.go                    # Impact
│ ├── recommendation.go                  # Recommendation
│ └── risk_score.go                 # Risk score
├── metrics/
│ ├── severity.go                  # Severity (P0-P5)
│ ├── confidence.go                  # Confidence
│ ├── impact.go                    # Impact
│ ├── business_impact.go                # Business impact
│ └── roi.go                    # ROI
└── delivery/
├── json.go                   # JSON delivery
├── markdown.go                   # Markdown delivery
├── pdf.go                   # PDF delivery
└── encrypted.go                 # Encrypted delivery
```


Penjelasan Teknis


Komponen Fungsi Teknologi
Technical Full report, Executive summary, Findings, Evidence, Reproduction, Remediation, Timeline Go
Executive Summary, Impact, Recommendation, Risk score Go
Metrics Severity (P0-P5), Confidence, Impact, Business impact, ROI Go


Flowchart Pengerjaan (Layer 20)


```text
[START]
│
▼
[1] Implementasi technical (report, summary, findings, evidence, reproduction, remediation, timeline)
│
▼
[2] Implementasi executive (summary, impact, recommendation, risk)
│
▼

[3] Implementasi metrics (severity, confidence, impact, business, ROI)
│
▼
[4] Implementasi delivery (JSON, Markdown, PDF, encrypted)
│
▼
[END]
```


---


6.6 Cleanup & Deletion


Struktur File


```text
ANGEL-CLEANUP/
├── credential/
│ ├── revoke_temp_creds.go            # Revoke temporary credentials
│ ├── rotate_tokens.go            # Rotate tokens
│ └── delete_ssh_keys.go            # Delete SSH keys
├── artifact/
│ ├── delete_tools.go            # Delete tools
│ ├── delete_logs.go             # Delete logs
│ ├── delete_configs.go            # Delete configs
│ └── delete_backups.go             # Delete backups
├── db_cleanup/
│ ├── delete_java_objects.go         # Khunt removal
│ ├── delete_stored_proc.go          # Delete stored procedures
│ ├── delete_admin_accounts.go          # Delete admin accounts
│ └── revert_changes.go             # Revert changes
├── cache_verify/
│ ├── scan_cache.go                # Scan cache
│ └── verify_clean.go            # Verify clean
└── manifest/
├── generate.go              # Generate deletion manifest
├── verify.go              # Verify manifest
└── export.go               # Export manifest
```


Penjelasan Teknis


Komponen Fungsi Teknologi
Credential Revoke temp credentials, Rotate tokens, Delete SSH keys Go
Artifact Delete tools, Delete logs, Delete configs, Delete backups Go
DB Cleanup Delete Java objects, Delete stored procedures, Delete admin accounts, Revert changes Go
Manifest Generate deletion manifest, Verify, Export Go


Flowchart Pengerjaan (Layer 21)


```text
[START]
│
▼
[1] Implementasi credential cleanup (revoke, rotate, delete SSH)
│
▼
[2] Implementasi artifact cleanup (delete tools, logs, configs, backups)
│
▼
[3] Implementasi DB cleanup (delete Java, stored proc, admin, revert)
│
▼
[4] Implementasi cache verify (scan, verify clean)
│
▼
[5] Implementasi manifest (generate, verify, export)
│
▼
[END]
```


---


7. MODUL TAMBAHAN (LAYER 22–25)


7.1 Credential Attack & Auth Bypass Engine


Struktur File


```text
ANGEL-CRACK/
├── hashcat_wrapper.go              # Integrasi Hashcat (Offline Cracking)
├── john_wrapper.go               # Fallback John the Ripper
├── wordlist_manager.go             # Manajemen & Mutasi Wordlist
└── rule_engine.go               # Custom Rule Mutation


ANGEL-AUTHBYPASS/
├── sqli_auth.go               # Bypass via SQLi (OR 1=1)

├── nosql_auth.go                # Bypass via NoSQL ($ne)
├── jwt_attack.go               # JWT Attack (alg:none, key conf)
├── json_tampering.go              # Manipulasi Response/JSON
└── default_cred.go               # Default Credentials Scanner


ANGEL-AUTHPROBE/
├── http_bruteforce.go            # Multi-Threading Login Form
├── credential_stuffing.go         # Combo List (User:Pass bocor)
├── spraying_engine.go              # Password Spraying (Anti-Lockout)
├── rate_limit_bypass.go            # Rotate IP / User-Agent (Anti-WAF)
└── user_enum.go                  # Validasi Username/Email
```


Penjelasan Teknis


Komponen Fungsi Teknologi
Password Spraying 1 Password → Banyak User (Tidak Lockout) Go
JWT Attack Ubah Algoritma & Signature JWT Go
Auth Bypass NoSQL Injection ($ne) & SQLi Go
Hashcat Wrapper Panggil Hashcat dengan Hash Mode Otomatis Go
WAF Bypass Rotate IP & User-Agent Otomatis Go
Multi-Threading Scan & Brute Force Cepat tapi Stabil Go
Logika Hybrid Recon → Spraying → Crack → Bypass (Full Chain) Go


Flowchart Pengerjaan (Layer 22)


```text
[START]
│
▼
[1] Implementasi ANGEL-CRACK (hashcat, john, wordlist, rule engine)
│
▼
[2] Implementasi ANGEL-AUTHBYPASS (SQLi, NoSQL, JWT, JSON, default cred)
│
▼
[3] Implementasi ANGEL-AUTHPROBE (bruteforce, stuffing, spraying, rate limit, user enum)
│
▼
[END]
```


---


7.2 Network Evasion & Traffic Morphing Engine


Struktur File


```text
ANGEL-NETWORK-EVASION/
├── ip_rotation_engine.go           # Rotate IP/Proxy tiap 1-3 detik + Auto-Disconnect
├── traffic_morphing.go            # HTTP/2 Fingerprint Spoofing, TLS Fingerprint, Sleep Jitter
└── packet_obfuscation.go            # Enkripsi Payload + DNS Tunneling
```


Penjelasan Teknis


Komponen Fungsi Teknologi
IP Rotation Ganti IP secara agresif (1-3 detik) biar correlation traffic ke target gagal Go
Traffic Morphing Nyamar jadi traffic browser asli biar EDR/AV nggak curiga Go
Sleep Jitter Delay random antar request biar nggak kelihatan kayak bot/spam Go


Flowchart Pengerjaan (Layer 23)


```text
[START]
│
▼
[1] Implementasi ip_rotation_engine.go
│
▼
[2] Implementasi traffic_morphing.go
│
▼
[3] Implementasi packet_obfuscation.go
│
▼
[END]
```


---


7.3 Full Scope Destruction & Impact Chain


Struktur File


```text
ANGEL-DESTRUCT-IMPACT/
├── impact_calculator.go           # Hitung Blast Radius (Data, Downtime, User Impact)

├── destruction_chain.go          # Eksekusi Ransomware/Wiper/DB Drop dengan Timing Tepat
└── full_scope_attack.go          # Orchestrator Gabungan (Recon → Attack → Destroy → Report)
```


Penjelasan Teknis


Komponen Fungsi Teknologi
Impact Calculator Hitung "seberapa hancur" sistem sebelum eksekusi Go
Destruction Chain Eksekusi penghancuran Database, File, dan Log secara otomatis Go
Full Scope Attack Satu perintah untuk menjalankan seluruh rangkaian serangan Go


Flowchart Pengerjaan (Layer 24)


```text
[START]
│
▼
[1] Implementasi impact_calculator.go
│
▼
[2] Implementasi destruction_chain.go
│
▼
[3] Implementasi full_scope_attack.go
│
▼
[END]
```


---


7.4 Implant Generator (Live C2 Agent)


Struktur File


```text
ANGEL-IMPLANT/
├── implant_generator.go          # Generate Binary .exe/.bin dengan Key Enkripsi Kustom
├── implant_beacon.go             # Callback ke Server (Register, CheckIn, SendResult)
└── payload_encryptor.go          # Enkripsi Shellcode/Payload Anti AV/EDR
```


Penjelasan Teknis


Komponen Fungsi Teknologi
Implant Generator Bikin binary yang bisa di-install di target (Windows/Linux/MacOS) Go
Implant Beacon Agent yang otomatis "call back" ke Server ANGEL Go
Payload Encryptor Enkripsi payload biar AV/EDR nggak bisa baca isi komunikasi Go


Flowchart Pengerjaan (Layer 25)


```text
[START]
│
▼
[1] Implementasi implant_generator.go
│
▼
[2] Implementasi implant_beacon.go
│
▼
[3] Implementasi payload_encryptor.go
│
▼
[END]
```


---


8. STATISTIK TOTAL


Domain Modul
C2 Framework 98+ agents, 6 listeners, Malleable Profile, SMB Beacon
SQL Injection 60+ modules (8 DBMS)
NoSQL Injection 5 DBMS
Database Post-Exploit 4 DBMS, 20+ modules
Evasion & Stealth 50+ modules (7 sleep methods)
AD Attack 40+ modules (ESC1-16)
Lateral Movement 30+ modules + SMB Beacon
Persistence 40+ modules (4 OS + UEFI)
Hardware Rootkit 20+ modules (Ring -2)
Credential Theft 30+ modules
Collector / InfoStealer 15+ modules
Destruction 30+ modules
Orchestrator 25+ modules (Fireteam + MCP)
Autonomous Brain 5+ modules
Infrastructure 20+ modules (Functional Separation)
OSINT 25+ modules
Exploitation 40+ modules

Forensic Evidence 15+ modules
Reporting 15+ modules
Cleanup 15+ modules
TOTAL ~650+ modules


---


9. PRINSIP DASAR


1. "No copy-paste" — tiap baris ditulis sendiri, bukan clone.
2. "If I can't explain every line, it doesn't go in" — paham semua kode.
3. "Signature-free" — defender gak kenal karena gak ada yang sama.
4. "Modular" — tiap modul jalan sendiri, tapi orchestrated.
5. "Evidentiary" — tiap action ada bukti (hash chain, timestamp).
6. "Clean" — post-engagement, semua hilang (terraform destroy + manifest).


---


10. CHECKLIST FINAL


1 C2 Framework (98+ Agents + Malleable Profile + SMB Beacon) [ ]
2 The Decoy / Deception Layer [ ]
3 SQL Injection Engine (Detectors + Exploits + WAF Bypass) [ ]
4 NoSQL Injection Engine (MongoDB + Elasticsearch + Redis) [ ]
5 Database Post-Exploit (khunt-style) [ ]
6 C2 Evasion & Stealth (7 Sleep Methods + Direct Syscall) [ ]
7 AD Attack (Golden/Silver + ADCS + DCSync) [ ]
8 Lateral Movement (SMB/WMI/WinRM + SMB Beacon) [ ]
9 Persistence (Registry/SchTask/UEFI + Cron/Systemd + Magisk) [ ]
10 Hardware Rootkit (UEFI DXE + SMM Ring -2) [ ]
11 Credential Theft (LSASS/SAM/Browser/Cloud) [ ]
12 Collector / InfoStealer Module [ ]
13 Destruction (JADEPUFFER + MAD-CAT + Wiper) [ ]
14 Orchestrator (LangGraph + MCP + Fireteam) [ ]
15 Autonomous Decision-Making (Brain) [ ]
16 Infrastructure (Terraform + Ansible + Functional Separation) [ ]
17 OSINT (DNS/Port/Web/Person/Cloud) [ ]
18 Exploitation (XSS/SSRF/RCE/LFI/CVE) [ ]
19 Forensic Evidence (Hash Chain + Redaction) [ ]
20 Reporting (Technical + Executive) [ ]
21 Cleanup (Revoke + Delete + Manifest) [ ]
22 Credential Attack & Auth Bypass Engine [ ]
23 Network Evasion & Traffic Morphing Engine [ ]
24 Full Scope Destruction & Impact Chain [ ]
25 Implant Generator (Live C2 Agent) [ ]


---


11. TIMELINE PENGERJAAN


Phase Fokus Target Selesai
Phase 1 Layer 1-5 (C2, Decoy, SQLi, NoSQL, Post-Exploit) Minggu 1-2
Phase 2 Layer 6-10 (Evasion, AD, Lateral, Persistence, Rootkit) Minggu 3-4
Phase 3 Layer 11-15 (Credential, Collector, Destruction, Orchestrator, Brain) Minggu 5-6
Phase 4 Layer 16-21 (Infra, OSINT, Exploit, Evidence, Report, Cleanup) Minggu 7-8
Phase 5 Layer 22-25 (AuthBypass, Network Evasion, Destruction Chain, Implant) Minggu 9-10


---


12. KESIMPULAN


ANGEL adalah platform offensive security tingkat lanjut yang dirancang untuk menghasilkan P0/P1 findings dengan bukti nyata dan rekomendasi perbaikan. Blueprint ini adalah satu-satunya referensi untuk seluruh proses pengembangan.


Seluruh aktivitas dilakukan dalam kerangka legal dan etis, dengan izin tertulis dari pemilik sistem.


---


13. LEGAL & SAFETY DISCLAIMER


PENTING: Blueprint ini hanya untuk tujuan pendidikan, penelitian, dan pengujian keamanan yang sah.
Dilarang keras menggunakan kode atau teknik yang dijelaskan di sini untuk menyerang sistem yang tidak Anda miliki atau tanpa izin tertulis.
Pelanggaran hukum dapat dikenakan sanksi pidana dan perdata.
Gunakan hanya di lingkungan lab yang Anda kendalikan atau sistem yang telah Anda dapatkan izin resmi.


```


---

