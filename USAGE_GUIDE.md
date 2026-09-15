# ANGEL — Cara Pakai (Usage Guide)

> **Status:** FINAL & EXECUTABLE
> **Tujuan:** Platform offensive security (red team) untuk engagement resmi.
> **Prinsip:** "No copy-paste" — tiap baris ditulis sendiri.
> **Legalitas:** Hanya digunakan pada sistem yang telah diizinkan.

---

## 1. Setup Awal

```bash
# Clone repository
git clone https://github.com/angel-framework/angel.git
cd angel

# Setup dependensi dan build
make setup

# Copy environment file dan edit
cp .env.example .env
# Edit .env dengan konfigurasi target Anda
```

### Konfigurasi Environment (`.env`)

Copy dari `.env.example` dan isi nilai-nilai tersebut:

```bash
cp .env.example .env
```

Edit file `.env` dengan konfigurasi target Anda, antar lain:

- `TEAMSERVER_ADDR` - Alamat teamserver (0.0.0.0 untuk semua interface)
- `TEAMSERVER_PORT` - Port teamserver (default 8080)
- `TEAMSERVER_SECRET` - Kunci rahasia C2
- `DATABASE_URL` - URL database (sqlite:///data/angel.db)
- `C2_DEFAULT_PROFILE` - Profile malleable C2 (teams, office, google)
- `LISTENER_HTTPS_PORT` - Port HTTPS listener (default 443)
- `LISTENER_DNS_PORT` - Port DNS listener (default 53)
- `INFRA_PROVIDER` - Provider infrastruktur (aws, azure, gcp)

---

## 2. Deployment

### Infrastruktur (VPS + WireGuard + Nginx)

```bash
# Deploy infrastruktur menggunakan Terraform + Ansible
make infra-deploy ENV=production
```

### C2 Framework (Teamserver + Implant)

```bash
# Build semua binary
make build

# Deploy C2 framework ke /opt/angel/
make c2-deploy
```

### Orchestrator (LangGraph + Fireteam)

```bash
# Build dan deploy orchestrator
make orchestrator-deploy
```

### Dashboard (Angular)

```bash
# Start Angular dashboard
make dashboard
# Atau secara manual:
# cd frontend && ng serve --host 0.0.0.0
```

---

## 3. Operasional Engagements

### Start Listeners (C2 Channels)

```bash
# Start teamserver dengan semua listeners
make listeners-start
# Atau secara manual:
# nohup ./bin/angel > /var/log/angel/teamserver.log 2>&1 &
# sleep 2
# echo "Listeners started"
```

### Generate Implant

```bash
# Generate implant binary untuk sistem operasi tertentu
make implant-generate OS=windows TARGET=x64
# Atau:
make implant-generate OS=linux TARGET=amd64
make implant-generate OS=darwin TARGET=amd64
# Output akan di bin/implants/

# Atau dari command langsung:
# go run ./cmd/teamserver/ -generate-os windows -target x64
```

### Engage Target

```bash
# Mulai engagement dengan file scope target
make engage SCOPE=target.txt

# Atau secara manual dari command:
# ./bin/angel engage --scope target.txt
```

### During Engagement

- Monitor dashboard di `http://localhost:4200` (atau port yang ditetapkan)
- Cek logs di `/var/log/angel/teamserver.log`
- Gunakan `make verify-clean` setelah engagement untuk memastikan cleanup lengkap

---

## 4. Post-Engagement (Cleanup)

```bash
# Stop semua proses angel
make cleanup

# Verify state bersih (tidak ada file/sisa)
make verify-clean

# Generate laporan teknis
make report FORMAT=pdf
# Atau format lain:
# make report FORMAT=markdown
# make report FORMAT=json

# Atau generate laporan dari command:
# go run ./cmd/console/ report --format html --output report.html
```

---

## 5. Maintenance & Maintenance

```bash
# Build ulang semua binary
make build

# Run linter untuk kode quality
make lint

# Format kode
make fmt

# Tidy modul-go
make tidy

# Security scan
make security

# Cek dependencies
make deps
```

---

## 6. Struktur File Penting

### Root Directory

```
ANGEL/
├── Makefile           # Entry point: make build / make test / make release
├── .env.example       # Template konfigurasi environment
├── .env               # Konfigurasi (copy dari .env.example)
├── go.mod             # Go module definition
├── go.sum             # Go module checksums
├── main.go            # Entry point (atau cmd/teamserver/main.go)
├── scripts/           # Automation, build, lint, release pipeline
│   ├── build.sh
│   ├── lint.sh
│   ├── release.sh
│   └── test.sh
├── tests/             # Test scenarios TC-001..TC-1346 (Section 17)
│   ├── integration/
│   ├── e2e/
│   └── TEST_SCENARIOS.md
├── docs/              # Dokumentasi operasional + report template
│   ├── README.md
│   └── report_template.md
├── c2/                # Inti C2 (implant, teamserver, malleable profile)
├── orchestrator/      # LangGraph orchestration + Brain (intent classifier)
├── gateway/           # API Gateway (.NET 10): auth, RBAC, rate limit
├── frontend/          # Angular dashboard, agent console, report viewer
├── infra/             # Terraform + Ansible: VPS, WireGuard, firewall
└── modules/           # Semua modul ofensif per layer (1–70)
    ├── layer01-05/    # C2 core, decoy, SQLi, NoSQL, DB post-exploit
    ├── layer06-10/
    ├── ...
    └── layer66-70/
```

### Modular Structure (Per Layer)

Setiap layer di `modules/layerNN–MM/` terpisah fungsional dan berinteraksi lewat **event bus** — tidak ada panggilan langsung antar komponen.

---

## 7. Available Makefile Targets

```make
all              -> build test lint
build            -> Build all binaries
build-linux      -> Build for Linux
build-windows    -> Build for Windows
build-darwin     -> Build for macOS
build-all        -> Build for all platforms
test             -> Run tests (go test -v -race -cover ./...)
test-coverage    -> Run tests with coverage report
lint             -> Run golangci-lint
fmt              -> Format kode (gofmt/goimports)
tidy             -> go mod tidy
clean            -> Bersihkan build artifacts
install          -> Go install ke $GOPATH
dev              -> Start development mode
report           -> Generate report
rules            -> Load rules
docker           -> Build Docker image
security         -> Run security scan (gosec)
deps             -> Check dependencies (go mod verify)
setup            -> Full setup (deps + build)
infra-deploy     -> Deploy infrastructure (terraform + ansible)
c2-deploy        -> Deploy C2 framework
orchestrator-deploy -> Deploy orchestrator
listeners-start  -> Start listeners
implant-generate -> Generate implant binary
dashboard        -> Start Angular dashboard
engage           -> Engage target (required: SCOPE=<file>)
cleanup          -> Cleanup after engagement
verify-clean     -> Verify clean state
help             -> Show this help menu
```

---

## 8. Catatan Penting

### Legalitas
- Seluruh aktivitas hanya pada sistem yang telah diizinkan
- Pastikan memiliki kontrak, izin polisi, dan persetujuan founder
- Hanya digunakan untuk engagement resmi

### Prinsip Dasar
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

### Environment Detection
Implant otomatis mendeteksi:
- OS version dan architecture
- CPU cores (< 2 = anti-sandbox)
- RAM (< 2GB = anti-sandbox)
- Disk size (< 60GB = anti-sandbox)
- Uptime (< 5 menit = anti-sandbox)
- Mouse movement (tidak ada = anti-sandbox)
- Process count (< 30 = sandbox)
- Parent process (explorer.exe parent)

Jika dideteksi environment sandbox, implant akan mengadaptasi perilaku atau menonaktifkan diri.

### Fallback Chains
Setiap teknik memiliki fallback otomatis jika teknik utama terdeteksi/blocked:
- C2 channel rotation: HTTPS → DNS → DoH → WebSocket → Telegram → Blockchain
- Sleep masking: VirtualProtect+RC4 → Thread Stack Spoofing → Module Stomping → Exception Handler → dll
- Evasion techniques: Hell's Gate → Halo's Gate → Tartarus Gate → FreshyCalls → SysWhispers3 → dll
- DB post-exploit: Oracle Java → MySQL UDF → PostgreSQL COPY → MSSQL xp_cmdshell → CLR Assembly → dll

### Event Bus Protocol
Semua komunikasi antar-modul WAJIB lewat event bus:
- Topik: `<domain>.<module>.<action>.<version>` (contoh: `c2.implant.registered.v1`)
- Publisher tidak tahu consumer (publish-and-forget)
- QoS: at-least-once, retry 3x backoff exponensial (1s → 2s → 4s)
- Autentikasi: header HMAC `X-Angel-Sign` (HMAC-SHA256) di tiap event
- Semua event jenis "result" otomatis dicatat ke evidence ledger (CHAIN_CUSTODY)

---

## 8. Troubleshooting

### Masalah Umum

**1. Teamserver tidak start**
- Cek port 8080 (atau yang ditetapkan) tidak digunakan lain
- Cek konfigurasi .env (TEAMSERVER_SECRET, dll)
- Cek log: `cat /var/log/angel/teamserver.log`

**2. Implant tidak terdaftar**
- Cek network connectivity ke teamserver
- Cek listener port sudah running (`make listeners-start`)
- Cek X-Angel-Sign header HMAC

**3. Channel tert-block**
- Gunakan channel rotation: `make listeners-start` akan otomatis fallback
- Atau manual: ganti listener di `.env` (`LISTENER_HTTPS_PORT`, dll)

**4. Verifikasi clean gagal**
- Cek proses masih running: `pkill -f "angel"`
- Cek file temp: `rm -f /tmp/angel-*`

**5. Dashboard tidak bisa diakses**
- Cek `make dashboard` sudah running
- Cek frontend port (default 4200)
- Cek CORS configuration di `.env`

---

## 9. Reference & Resources

### Documentation
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