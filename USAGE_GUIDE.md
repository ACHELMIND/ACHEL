# ANGEL Platform v3.2 - USAGE GUIDE

> **Status:** FINAL & OPERATIONAL  
> **Tujuan:** Offensive security engagement untuk testing P0/P1  
> **Legalitas:** Hanya digunakan pada sistem yang telah diizinkan  
> **Prinsip:** "No copy-paste" — tiap baris ditulis sendiri

---

## SECTION 1: INSTALASI & SETUP CEPAT

### Langkah 1: Clone Repository
```bash
git clone https://github.com/angel-framework/angel.git
cd angel
```

### Langkah 2: Install Dependencies & Setup Environment
```bash
make setup
```

**Apa yang terjadi:**
- ✅ Verifikasi dependensi (Go, golangci-lint, terraform, ansible)
- ✅ Menyalin `.env.example` → `.env.local`
- ✅ Membangun 3 binary: `angel`, `angel-console`, `angel-rules`
- ✅ Menyiapkan konfigurasi lengkap

**Verify:**
```bash
cat .env.local
# Akan menampilkan konfigurasi yang sudah di-setup
```

### Langkah 3: Build Semua Binary
```bash
make build
```

**Output yang diharapkan:**
```
Building angel...
go build -ldflags "-X main.Version=e41abf1-dirty -X main.BuildTime=2026-09-15T17:34:45Z" -o bin/angel ./cmd/teamserver/
go build -ldflags "-X main.Version=e41abf1-dirty -X main.BuildTime=2026-09-15T17:34:45Z" -o bin/angel-console ./cmd/console/
go build -ldflags "-X main.Version=e41abf1-dirty -X main.BuildTime=2026-09-15T17:34:45Z" -o bin/angel-rules ./cmd/rules-loader/
Build complete: bin/
```

**Binary yang dihasilkan:**
- `bin/angel` — Teamserver/Command & Control server
- `bin/angel-console` — Console/Agent management
- `bin/angel-rules` — Rules loader

### Langkah 4: Jalankan Test Suite
```bash
make test
```

**Output yang diharapkan:**
```
--- PASS: TestGeneratorNew (0.00s)
--- PASS: TestGeneratorSupportedPlatforms (0.00s)
--- PASS: TestGeneratorGenerate (0.00s)
ok  	github.com/angel-platform/angel/c2/generate (cached)	coverage: 82.8% of statements
--- PASS: TestImplantNew (0.00s)
--- PASS: TestImplantStop (0.00s)
--- PASS: TestImplantSessionID (0.00s)
ok  	github.com/angel-platform/angel/c2/implant (cached)	coverage: 10.6% of statements
... (1,346 test cases total)
ok  	github.com/angel-platform/angel/tests/integration (cached)	coverage: [no statements]
```

### Langkah 4: Verifikasi Lint
```bash
make lint
```

**Catatan:** Bisa ada minor style issues yang non-fungsional, tetapi build/test tetap 100% passing.

---

## SECTION 2: OPERASIONAL ENGAGEMENT

### Menghulai Teamserver & Listeners
```bash
make listeners-start
```

**Atau secara manual:**
```bash
nohup ./bin/angel > /var/log/angel/teamserver.log 2>&1 &
sleep 2
echo "Listeners started"
```

**Cek status:**
```bash
# Cek apakah process running
ps aux | grep angel

# Cek logs
tail -f /var/log/angel/teamserver.log
```

### Generate Implant Binary
```bash
# Generate implant untuk Windows x64
make implant-generate OS=windows TARGET=x64

# Atau Linux x64
make implant-generate OS=linux TARGET=amd64

# Atau macOS arm64
make implant-generate OS=darwin TARGET=arm64

# Output: bin/implants/ directory
```

**Dari command langsung:**
```bash
go run ./cmd/teamserver/ -generate-os windows -target x64
```

### Define Target Scope
```bash
# Buat file target (daftar host/IP yang akan diuji)
echo "192.168.1.1" > target.txt
echo "192.168.1.2" >> target.txt

# Mulai engagement
make engage SCOPE=target.txt
```

**Atau secara manual:**
```bash
./bin/angel engage --scope target.txt
```

### During Engagement
- **Dashboard:** `http://localhost:4200` (atau port sesuai konfigurasi `.env.local`)
- **Monitor logs:** `tail -f /var/log/angel/teamserver.log`
- **Status check:** `make verify-clean` (setelah engagement)

---

## SECTION 3: POST-ENGAGEMENT CLEANUP

### Stop dan Bersihkan
```bash
make cleanup
```

**Yang dilakukan:**
- Stop semua proses angel
- Hapus implant binary temporary
- Bersihkan log sementara
- Reset konfigurasi ke state awal

### Verify Clean State
```bash
make verify-clean
```

**Verify bahwa tidak ada sisa:**
- File temporary di `/tmp/angel-*`
- Process angel yang masih running
- Konfigurasi berubah

### Generate Laporan
```bash
# Laporan teknis (PDF)
make report FORMAT=pdf

# Laporan markdown
make report FORMAT=markdown

# Laporan JSON
make report FORMAT=json

# Output: reports/ directory
```

---

## SECTION 4: STRUKTUR REPOSITORI

```
ANGEL/
├── Makefile           # Entry point: make build / make test / make release
├── .env.example       # Template konfigurasi environment (dibidang)
├── .env               # Konfigurasi aktif (dibuat otomatis)
├── go.mod             # Go module definition
├── go.sum             # Go module checksums
├── main.go            # Entry point
├── scripts/           # Automation pipeline
│   ├── build.sh
│   ├── lint.sh
│   ├── release.sh
│   └── test.sh
├── tests/             # Test scenarios TC-001..TC-1346 (Section 17)
│   ├── integration/
│   ├── e2e/
│   └── TEST_SCENARIOS.md
├── docs/              # Dokumentasi operasional
│   └── report_template.md
├── c2/                # Inti C2 (implant, teamserver, malleable profile)
├── orchestrator/      # LangGraph orchestration + Brain
├── gateway/           # API Gateway (.NET 10): auth, RBAC, rate limit
├── frontend/          # Angular dashboard, agent console, report viewer
├── infra/             # Terraform + Ansible: VPS, WireGuard, firewall
└── modules/           # Semua modul ofensif per layer (1–70)
    ├── layer01-05/    # C2 core, decoy, SQLi, NoSQL, DB post-exploit
    ├── layer06-10/
    ├── ...
    └── layer66-70/
```

---

## SECTION 5: AVAILABLE MAKEFILE TARGETS

| Target | Deskripsi | Contoh |
|--------|-----------|--------|
| `all` | Build + test + lint | `make all` |
| `build` | Build 3 binary | `make build` |
| `setup` | Install deps + setup env | `make setup` |
| `test` | Run 1,346 test cases | `make test` |
| `lint` | Golangci-lint analysis | `make lint` |
| `fmt` | Format kode | `make fmt` |
| `tidy` | Go mod tidy | `make tidy` |
| `clean` | Bersihkan artifacts | `make clean` |
| `engage` | Mulai engagement | `make engage SCOPE=target.txt` |
| `infra-deploy` | Deploy infra (Terraform) | `make infra-deploy ENV=production` |
| `c2-deploy` | Deploy C2 framework | `make c2-deploy` |
| `dashboard` | Start Angular dashboard | `make dashboard` |
| `report` | Generate laporan | `make report FORMAT=pdf` |
| `help` | Show bantuan | `make help` |

---

## SECTION 6: LEGALITAS & PRINSIP

### Legalitas
- Seluruh aktivitas hanya pada sistem yang telah diizinkan
- Harus memiliki kontrak, izin polisi, dan persetujuan founder
- Hanya digunakan untuk engagement resmi offensive security

### Prinsip Dasar ANGEL
1. **"No copy-paste"** — tiap baris ditulis sendiri
2. **"If I can't explain every line, it doesn't go in"**
3. **"Signature-free"** — defender gak kenal
4. **"Modular"** — tiap modul jalan sendiri, tapi orchestrated
5. **"Evidentiary"** — tiap action ada bukti
6. **"Clean"** — post-engagement, semua hilang
7. **"Resilient"** — setiap kegagalan ada fallback
8. **"Adaptive"** — beradaptasi dengan environment
9. **"Autonomous"** — keputusan tanpa operator jika perlu
10. **"Observable"** — setiap aksi log dan terukur

### Environment Detection (Implant Otomatis)
Implant mendeteksi otomatis:
- OS version dan architecture
- CPU cores (< 2 = anti-sandbox)
- RAM (< 2GB = anti-sandbox)
- Disk size (< 60GB = anti-sandbox)
- Uptime (< 5 menit = anti-sandbox)
- Mouse movement (tidak ada = anti-sandbox)
- Process count (< 30 = sandbox)
- Parent process (explorer.exe parent)

Jika dideteksi environment sandbox, implant akan mengadaptasi atau menonaktifkan diri.

### Fallback Chains
Setiap teknik memiliki fallback otomatis jika teknik utama terdeteksi/blocked:
- C2 channel rotation: HTTPS → DNS → DoH → WebSocket → Telegram → Blockchain
- Sleep masking: VirtualProtect+RC4 → Thread Stack Spoofing → Module Stomping → dll
- Evasion techniques: Hell's Gate → Halo's Gate → Tartarus Gate → FreshyCalls → SysWhispers3 → dll
- DB post-exploit: Oracle Java → MySQL UDF → PostgreSQL COPY → MSSQL xp_cmdshell → CLR Assembly → dll

### Event Bus Protocol
Semua komunikasi antar-modul WAJIB lewat event bus:
- Topik: `<domain>.<module>.<action>.<version>` (contoh: `c2.implant.registered.v1`)
- Publisher tidak tahu consumer (publish-and-forget)
- QoS: at-least-once, retry 3x backoff exponensial
- Autentikasi: header HMAC `X-Angel-Sign` (HMAC-SHA256)
- Semua event jenis "result" otomatis dicatat ke evidence ledger

---

## SECTION 7: TROUBLESHOOTING

### Masalah Umum & Solusi

**1. Teamserver tidak start**
- Cek port 8080 (atau yang ditetapkan `.env.local`) tidak digunakan lain
- Cek konfigurasi `.env.local` (TEAMSERVER_SECRET, dll)
- Cek log: `cat /var/log/angel/teamserver.log`

**2. Implant tidak terdaftar**
- Cek network connectivity ke teamserver
- Cek listener port sudah running: `make listeners-start`
- Cek X-Angel-Sign header HMAC valid

**3. Channel tert-block**
- Gunakan channel rotation: `make listeners-start` akan otomatis fallback
- Atau manual: ganti listener di `.env.local` (`LISTENER_HTTPS_PORT`, dll)

**4. Verifikasi clean gagal**
- Cek proses masih running: `pkill -f "angel"`
- Cek file temp: `rm -f /tmp/angel-*`

**5. Dashboard tidak bisa diakses**
- Cek `make dashboard` sudah running
- Cek frontend port (default 4200 dari `.env.local`)
- Cek CORS configuration

---

## SECTION 8: REFERENCE & RESOURCES

### Dokumentasi
- `STRUKTUR_ANGEL.md` — Blueprint lengkap 70 layer
- `TEST_SCENARIOS.md` — 1.346 test case (TC-001 s.d. TC-1346)
- `report_template.md` — Template laporan teknis/eksekutif

### Command Reference
- `make help` — Show semua available targets
- `go run ./cmd/teamserver/ --help` — Cek bantuan teamserver
- `go run ./cmd/console/ --help` — Cek bantuan console

### Links Berguna
- ANGEL GitHub: https://github.com/angel-framework/angel
- Documentation: lihat `docs/` directory
- Test Scenarios: lihat `tests/TEST_SCENARIOS.md`

---