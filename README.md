# KyyTools Security Scanner 🛡️

**KyyTools Security Scanner** adalah tool penilaian keamanan (security assessment tool) berbasis bahasa pemrograman **Golang** yang dirancang modular, aman, tangguh, dan ramah pengguna. 

Dilengkapi antarmuka terminal interaktif (CLI menu) dan perintah otomatisasi berbasis flag, KyyTools memungkinkan auditor keamanan, DevOps engineer, dan administrator sistem memeriksa domain, alamat IP, dan aplikasi web yang dimiliki atau yang telah mengantongi izin tertulis resmi.

---

## 🌟 Fitur Utama

- **Engine Scanning Mandiri**: Dibangun murni menggunakan Go standard library dan dependensi native tanpa mewajibkan tool pihak ketiga (seperti Nuclei atau Nmap).
- **CLI Interaktif & Ramah Pengguna**: Cukup jalankan `kyytools`, pilih menu bernomor, masukkan target, dan saksikan proses scan dengan spinner & progress status.
- **Proteksi Scope Ketat & Anti-SSRF**: Menolak loopback (localhost), private IP, dan link-local secara default. Memeriksa seluruh hasil DNS A/AAAA sebelum koneksi dibuka.
- **Deteksi Masalah Keamanan Web**: Memeriksa HTTP headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options), banner exposure, dan flag cookie.
- **TLS/SSL Analyzer**: Validasi rantai sertifikat, hostname matching, sisa masa aktif (expiration), dan peringatan sertifikat kadaluwarsa.
- **TCP Port Scanner**: Pemindaian port terkontrol dengan batas konkurensi aman dan identifikasi layanan banner.
- **Penyimpanan Lokal SQLite**: Seluruh sesi scan, target, profil, dan temuan tersimpan otomatis di database lokal `kyytools.db`.
- **Ekspor Laporan Multi-Format**: Buat laporan profesional dalam format **HTML** interaktif, **JSON**, dan **CSV**.
- **Template Kerentanan YAML**: Engine template deklaratif untuk mendeteksi paparan file sensitif dan miskonfigurasi.

---

## 🚀 Quick Start

### 1. Build Binary
Pastikan Go versi 1.22+ telah terpasang:
```bash
# Windows CMD / PowerShell
go build -o kyytools.exe .\cmd\kyytools

# Linux / macOS
go build -o kyytools ./cmd/kyytools
```

### 2. Jalankan Mode Interaktif
Cukup ketik:
```bash
kyytools
```
Menu interaktif akan tampil di terminal:
```text
==================================================
       KyyTools Security Scanner
       Go-Based Security Assessment Tool
==================================================

 [1] Quick Scan
 [2] Web Security Scan
 [3] Domain Scanner
 [4] IP & Port Scanner
 [5] Subdomain Discovery
 [6] Vulnerability Templates
 [7] Scan History
 [8] View Findings
 [9] Generate Report
[10] Scan Profiles
[11] Configuration
[12] Help & Documentation
 [0] Exit

Select an option:
```

### 3. Penggunaan Non-Interaktif (Automation / CI/CD)
```bash
# Quick Scan domain
kyytools scan --target example.com --profile quick

# Standard Scan web app
kyytools scan --target https://example.com --profile standard

# Tampilkan riwayat scan
kyytools history

# Lihat temuan scan tertentu
kyytools findings --scan-id 1

# Ekspor laporan HTML
kyytools report --scan-id 1 --format html

# Validasi template YAML
kyytools templates validate

# Tampilkan konfigurasi saat ini
kyytools config show
```

---

## 📂 Struktur Project

```text
kyytools/
├── cmd/
│   └── kyytools/
│       └── main.go          # Entry point utama aplikasi
├── internal/
│   ├── app/                 # Bootstrapper dan orchestrator
│   ├── cli/                 # Menu interaktif, table formatter, warna ANSI
│   ├── config/              # YAML config loader & default scan profiles
│   ├── target/              # Target parser, normalizer, dan DNS resolver
│   ├── scanner/             # Engine scanner modul & concurrent worker
│   ├── templates/           # Engine validasi template YAML
│   ├── risk/                # Penghitungan skor risiko & severity level
│   ├── models/              # Struktur data inti KyyTools
│   ├── storage/             # SQLite database manager & migrasi skema
│   ├── reports/             # Generator laporan HTML, JSON, CSV
│   └── safety/              # Scope validator, proteksi SSRF & DNS rebinding
├── templates/               # Koleksi template aturan kerentanan YAML
│   ├── http/
│   ├── tls/
│   ├── network/
│   └── misconfiguration/
├── configs/
│   └── config.yaml          # File konfigurasi default KyyTools
├── docs/
│   ├── BOOK.md              # Buku panduan lengkap (Bahasa Indonesia)
│   ├── COMMANDS.md          # Referensi lengkap perintah CLI & opsi
│   ├── INSTALL.md           # Panduan instalasi multi-platform
│   ├── CONFIGURATION.md     # Penjelasan detail parameter config
│   └── SECURITY.md          # Etika hukum & kebijakan scope guardrail
├── reports/                 # Direktori penyimpanan hasil ekspor laporan
├── tests/                   # Kumpulan unit test & fixtures lokal
├── kyytools.db              # Database SQLite lokal
├── Makefile                 # Otomatisasi build & testing
└── README.md
```

---

## 📑 Dokumentasi

Panduan komprehensif tersedia di folder `docs/`:
- [Buku Panduan KyyTools (docs/BOOK.md)](docs/BOOK.md)
- [Daftar Perintah & CLI Reference (docs/COMMANDS.md)](docs/COMMANDS.md)
- [Panduan Instalasi (docs/INSTALL.md)](docs/INSTALL.md)
- [Panduan Keamanan & Legalitas (docs/SECURITY.md)](docs/SECURITY.md)

---

## ⚖️ Lisensi
Didistribusikan di bawah lisensi MIT. Gunakan tool ini hanya pada sistem dan infrastruktur yang Anda miliki atau telah mendapatkan izin tertulis resmi.
