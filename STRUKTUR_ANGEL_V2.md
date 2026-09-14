Baca STRUKTUR_ANGEL.md.

Tugas lo: rombak TOTAL blueprint ini jadi framework full-attack kelas profesional. SEMUA layer harus kompleks dan lengkap, jangan meninggalkan gap. Jangan fokus satu-satu. Jangan ada layer yang sederhana. Semua wajib nyata yang menghasilkan hard critical P1/P0.

Referensi framework nyata yang harus lo samain atau lampauin kedalamannya:
- Cobalt Strike, Havoc C2, Brute Ratel C4, Nighthawk, Sliver, Aeternum C2
- Kynx Stealer, Lumma, RedLine, Void Stealer
- Ekko, Foliage, Cronos, DeathSleep
- Hell's Gate, Halo's Gate, Tartarus Gate, FreshyCalls, SysWhispers3

=== SETIAP LAYER HARUS PUNYA ===

1. Minimal 5-7 teknik alternatif per modul
2. Mekanisme fallback otomatis: kalau teknik A gagal, coba B, C, D
3. Mekanisme deteksi environment: framework tau EDR/sandbox/OS apa yang aktif
4. Mekanisme adaptasi: pilih teknik berdasarkan environment
5. Edge case, resilience, dan recovery:
   - EDR update di tengah engagement → framework harus tau, dan pindah ke teknik yang belum ke-detect
      - C2 channel ke-block → rotasi otomatis ke channel alternatif
         - Implant ke-detect dan ke-quarantine → re-deploy dengan loader baru
            - Persistence kehapus → re-persist otomatis
               - Credential ke-rotate → re-harvest otomatis
                  - Network segment berubah → re-scan, re-route
                     - Operator kehilangan koneksi → implant tetap jalan, tunggu reconnect
                        - Mekanisme dead man's switch → implant self-destruct kalau nggak ada heartbeat dalam X waktu
                           - Mekanisme self-destruct → wipe semua jejak, hapus diri sendiri
                              - Mekanisme recovery → framework pulih dari setiap edge case di atas
                              6. Test scenario spesifik per modul (environment, teknik, metrik, iterasi)
                              7. Dokumentasi cara pakai
                              8. Kalau lo ngerasa ada yang kurang dari yang gua ketik, lo tambahin sendiri tools/alat yang relevan

                              === DETAIL PER LAYER ===

                              Layer 1 (C2):
                              - Malleable profile: TLS fingerprint Chrome/Firefox/Edge, JA3/JA3S, HTTP/2 fingerprint, header order
                              - Channel: HTTPS, DNS, DoH, WebSocket, SMB, TCP, ICMP, Telegram, Discord, Slack, Twitter, Steam profile, blockchain smart contract (Polygon)
                              - Rotasi channel otomatis, domain fronting (Cloudflare, CloudFront, Azure CDN)
                              - C2 via Steam profile (rotate infrastructure dengan ganti display name)
                              - C2 via blockchain smart contract (command terenkripsi, konfirmasi 3 RPC)
                              - C2 via legitimate service abuse (OneDrive, Google Drive, Dropbox)
                              - Beacon: jitter, sleep, kill date, working hours

                              Layer 2 (Malleable/Decoy):
                              - Profile engine niru Teams, Office365, Google, custom
                              - Decoy layer buat deception

                              Layer 3 (SQL Injection):
                              - Detectors: error-based, boolean, time-based, union, stacked, out-of-band
                              - Exploits: MySQL, PostgreSQL, MSSQL, Oracle
                              - WAF bypass: encoding, comment, case, whitespace, HTTP parameter pollution

                              Layer 4 (NoSQL Injection):
                              - MongoDB: auth bypass, boolean, time, js, lookup, error
                              - Elasticsearch: query, aggregation, script
                              - CouchDB: auth bypass, js injection
                              - Redis: command injection, key dump
                              - Cassandra: CQL injection, user extract

                              Layer 5 (DB Post-Exploit):
                              - Oracle: Java object injection, KhuntCmd, KhuntHash, KhuntFS, KhuntUnzip
                              - MySQL: UDF install, sys_exec, sys_eval, user extract, file system
                              - PostgreSQL: COPY TO PROGRAM, pg_shadow, file system
                              - MSSQL: xp_cmdshell, CLR assembly, sys.sql_logins, file system
                              - Common: backup mechanisms, vault credentials, persistence admin

                              Layer 6 (Evasion):
                              - Sleep masking: Ekko, Foliage, Cronos, DeathSleep, VirtualProtect+RC4, thread stack spoofing, exception handler, module stomping, callback, encrypt fragments, guard page removal
                              - Syscall: Hell's Gate, Halo's Gate, Tartarus Gate, FreshyCalls, SysWhispers3, direct, indirect, recycled gate
                              - AMSI/ETW: hardware breakpoint, in-process patch, registry disable, session hijack, VEH, CLR hook
                              - Unhooking: ntdll, kernel32, KnownDlls, manual mapping
                              - Anti-analysis: anti-debug (IsDebuggerPresent, PEB BeingDebugged, NtGlobalFlag, hardware BP, timing), anti-VM (CPUID, hypervisor, device, process, MAC), anti-sandbox (uptime, mouse, disk, core, memory, process)
                              - Process injection: CRT, APC, hollowing, thread hijacking, module stomping, reflective DLL, section mapping
                              - Log cleanup: wevtutil, audit, USN journal, prefetch, shell history, forensic artifacts
                              - Network evasion: IP rotation, proxy chain, User-Agent rotation, TLS fingerprint rotation, DNS rotation, VPN

                              Layer 7 (AD Attack):
                              - Kerberos: golden, silver, diamond, sapphire, shadow credentials, kerberoast, AS-REP, pass-the-ticket, overpass-the-hash
                              - ADCS: ESC1-ESC16
                              - DCSync: DRSUAPI, replication, VSS
                              - Delegation: constrained, unconstrained, resource-based
                              - Recon: domain, user, group, SPN, GPO, OU, trust, site
                              - Persistence: golden ticket, shadow cred, AdminSDHolder, DCsync
                              - Fallback otomatis

                              Layer 8 (Lateral):
                              - SMB: PsExec, SMBExec, AtExec, WmiExec, DCOMExec, service, named pipe, pass-the-hash
                              - SMB Beacon: named pipe, P2P
                              - WMI: enum, auth, exec, persist
                              - WinRM: auth, exec, shell
                              - DCOM: MMC20, ShellWindows, Excel, Outlook
                              - RDP: auth, connect, tunnel, session hijack, shadow
                              - SSH: auth, exec, tunnel
                              - PowerShell Remoting: session, exec, scriptblock
                              - Pivoting: SOCKS5, port forward, TCP/DNS/ICMP tunnel
                              - Fallback berdasarkan port dan service

                              Layer 9 (Persistence):
                              - Windows: registry, scheduled task, service, WMI subscription, startup, ADS, DLL sideload, COM hijack, AppInit, IFEO, accessibility
                              - Linux: cron, systemd, rc.local, profile, bashrc, SSH keys, PAM, udev, initramfs
                              - macOS: LaunchDaemons, LaunchAgents, cron, SSH keys, login items, kext
                              - Android: Magisk, BOOT_COMPLETED, foreground, device admin, accessibility
                              - Re-persist otomatis

                              Layer 10 (Rootkit):
                              - UEFI: DXE injection, boot chain hook, OSL hook, Secure Boot bypass (MOK, shim, dbx), SPI flash
                              - SMM: handler injection, SMRAM exploit, ROP chain, callout, interrupt hook, self-reinstall
                              - Firmware: SPI read/write, JTAG, UART, emulation

                              Layer 11 (Credential Theft):
                              - LSASS: fork dump, process dump, minidump, PPL bypass, SSP injection, hooking
                              - SAM: registry dump, hive extraction, VSS
                              - Browser: Chrome, Edge, Firefox, Brave — cookie, password, token
                              - Rantai fallback berlapis seperti Kynx: MCE → DBS → ChromeElevator → Raw Copy
                              - DevGrabber: Claude Code, Cursor, GitHub Copilot, Windsurf, VS Code (session state, token, workspace)
                              - 65+ browser extension wallets (MetaMask, Phantom, Coinbase Wallet)
                              - 19+ desktop wallets (Exodus, Atomic, Electrum)
                              - 16+ gaming platforms (Steam, Epic Games, Origin, Roblox)
                              - 9+ VPN clients
                              - Cloud: AWS, Azure, GCP
                              - Token: impersonation, delegation, primary
                              - Certificate: store, smartcard
                              - Session hijacking: Instagram, TikTok, X, Spotify
                              - 2FA/MFA token harvester
                              - Biometric bypass: FaceID, TouchID, Fingerprint
                              - Exchange session hijacker: Coinbase, Binance, Kraken, Bybit

                              Layer 12 (Collector):
                              - Keylogger, clipboard, screenshot, webcam, microphone
                              - File grabber, document stealer
                              - Email, chat, messaging
                              - Network capture

                              Layer 13 (Destruction):
                              - Database: drop, encrypt, corrupt, backup
                              - File: ransomware, wiper, zero overwrite, random overwrite
                              - MBR/MFT: overwrite, corrupt
                              - Service: stop, kill, disable
                              - Network: flood, DoS
                              - Timing: destruction chain dengan timing control
                              - Impact: blast radius, recovery, business, severity

                              Layer 14/15 (Orchestrator + Brain):
                              - Autonomous decision, risk assessment, behavior learning, adaptive timing
                              - Full scope: recon → attack → destroy → report
                              - LangGraph orchestration, MCP, Fireteam
                              - Multi-agent parallel

                              Layer 16 (Infrastructure):
                              - Terraform: VPS provisioning, VPC separation
                              - Ansible: playbook, roles
                              - Functional separation: recon, phishing, C2 HTTPS, C2 DNS

                              Layer 17 (OSINT):
                              - DNS, port, web, person, cloud

                              Layer 18 (Exploitation):
                              - XSS, SSRF, RCE, LFI, RFI, XXE, deserialization
                              - Web framework exploits

                              Layer 19 (Forensic Evidence):
                              - Hash chain, timestamp, redaction

                              Layer 20 (Reporting):
                              - Technical + executive
                              - Metrics: severity, confidence, impact, business, ROI
                              - Delivery: JSON, Markdown, PDF, encrypted

                              Layer 21 (Cleanup):
                              - Revoke, delete, manifest

                              Layer 22 (Auth Bypass):
                              - Credential attack, brute force, password spraying
                              - Session hijacking
                              - 2FA bypass
                              - OAuth manipulation
                              - JWT attack: alg:none, weak secret, kid injection

                              Layer 23 (Network Evasion):
                              - Traffic morphing, protocol tunneling, domain fronting

                              Layer 24 (Full Scope Destruction):
                              - Impact calculator, destruction chain, full scope attack

                              Layer 25 (Implant Generator):
                              - Live C2 agent generator

                              === OUTPUT ===

                              1. Tulis STRUKTUR_ANGEL_V2.md lengkap dengan arsitektur baru + diagram
                              2. Implementasi layer per layer: scaffold, coding, test, iterasi
                              3. Commit tiap layer kelar
                              4. Jangan berhenti sampai SEMUA layer kompleks
                              5. Harus kompleks setiap module/layer