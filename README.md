# ANGEL Platform v3.2

**Offensive Security Platform untuk Engagement Resmi**

> **Status:** FINAL & EXECUTABLE  
> **Tujuan:** P0/P1, Hard/Expert, Full Attack, No Demo, No Placeholder  
> **Legalitas:** Hanya digunakan pada sistem yang telah diizinkan

---

## CEPAT MULAI (Quick Start)

```bash
# 1. Clone repository
git clone https://github.com/angel-framework/angel.git
cd angel

# 2. Install & setup environment
make setup

# 3. Build binary
make build

# 4. Jalankan test suite
make test

# 5. Mulai engagement
make engage SCOPE=target.txt
```

---

## FITUR UTAMA

| kategori | detail |
|----------|---------|
| **70 Layer** | C2 Framework, Evasion, AD Attack, Persistence, Rootkit |
| **427 file Go** | Terstruktur per layer 1-70 |
| **1,346 test case** | TC-001 hingga TC-1346 — semua passing |
| **3 binary** | `angel`, `angel-console`, `angel-rules` |
| **Event Bus** | Semua komunikasi lewat central event bus |
| **700+ teknik** | Fallback chains, anti-analysis, opsec procedures |

---

## CARA PAKAI

### Setup Lengkap
```bash
make setup     # Install deps + buat .env.local
make build     # Build 3 binary
make test      # Jalankan 1,346 test case
make engage SCOPE=target.txt  # Start engagement
```

### Manajemen C2
```bash
make listeners-start     # Start listeners
make implant-generate OS=windows TARGET=x64  # Generate implant
make engage SCOPE=target.txt  # Mulai engagement
make cleanup  # Post-engagement cleanup
```

### Dashboard & Monitoring
```bash
make dashboard  # Start Angular dashboard di http://localhost:4200
```

### Laporan
```bash
make report FORMAT=pdf   # Generate laporan PDF
make report FORMAT=markdown  # Generate laporan markdown
```

---

## ARSITEKTUR

```
Tier 1: Infrastructure   (Terraform/Ansible, 4 VPC nodes)
Tier 2: C2 Framework     (Implant, Teamserver, Listeners)
Tier 3: Orchestrator     (LangGraph + Brain + Fireteam)
Tier 4: API Gateway      (RBAC, Rate limiting, Auth)
Tier 5: Frontend         (Angular dashboard, agent console)
```

Setiap layer terpisah fungsional, komunikasi lewat **Event Bus Protocol**.

---

## LEGALITAS

- Seluruh aktivitas hanya pada sistem yang telah diizinkan
- Harus memiliki kontrak, izin polisi, dan persetujuan founder
- Hanya digunakan untuk engagement resmi offensive security

### Prinsip Dasar
1. **"No copy-paste"** — tiap baris ditulis sendiri
2. **"Signature-free"** — defender gak kenal
3. **"Modular"** — tiap modul jalan sendiri, tapi orchestrated
4. **"Evidentiary"** — tiap action ada bukti
5. **"Clean"** — post-engagement, semua hilang

---

## GITHUB & RESOURCES

- **Repository:** https://github.com/angel-framework/angel
- **Blueprint:** STRUKTUR_ANGEL.md v3.2
- **Test Scenarios:** tests/TEST_SCENARIOS.md (1,346 test)
- **Dokumentasi:** docs/ directory

---

## PERINGATAN PENTING

⚠️ **Hanya gunakan pada sistem yang telah diizinkan.**  
⚠️ **Pastikan memiliki kontrak, izin tertulis, dan persetujuan founder.**  
⚠️ **Platform dirancang untuk engagement offensive security resmi.**  
⚠️ **Semua aktivitas dilacak melalui evidence ledger (CHAIN_CUSTODY).**

---

**ANGEL Platform - Offensive Security Framework untuk Engagement Resmi**