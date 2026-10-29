# Buku Panduan Resmi KyyTools Security Scanner 🛡️
*Panduan Komprehensif Penilaian Keamanan Sistem Berbasis Golang*

---

## Daftar Isi

1. [Bab 1: Instalasi Go](#bab-1-instalasi-go)
2. [Bab 2: Persiapan Project](#bab-2-persiapan-project)
3. [Bab 3: Instalasi Dependensi](#bab-3-instalasi-dependensi)
4. [Bab 4: Build KyyTools](#bab-4-build-kyytools)
5. [Bab 5: Menjalankan KyyTools](#bab-5-menjalankan-kyytools)
6. [Bab 6: Menggunakan Menu Interaktif](#bab-6-menggunakan-menu-interaktif)
7. [Bab 7: Quick Scan](#bab-7-quick-scan)
8. [Bab 8: Domain Scan](#bab-8-domain-scan)
9. [Bab 9: IP & Port Scan](#bab-9-ip--port-scan)
10. [Bab 10: Web Security Scan](#bab-10-web-security-scan)
11. [Bab 11: TLS Scanner](#bab-11-tls-scanner)
12. [Bab 12: Subdomain Discovery](#bab-12-subdomain-discovery)
13. [Bab 13: Membuat Template YAML](#bab-13-membuat-template-yaml)
14. [Bab 14: Melihat Riwayat Scan](#bab-14-melihat-riwayat-scan)
15. [Bab 15: Membaca Severity & Risk Scoring](#bab-15-membaca-severity--risk-scoring)
16. [Bab 16: Membuat Laporan JSON, CSV, dan HTML](#bab-16-membuat-laporan-json-csv-dan-html)
17. [Bab 17: Mengubah Konfigurasi](#bab-17-mengubah-konfigurasi)
18. [Bab 18: Mengelola Scope dan Allowlist](#bab-18-mengelola-scope-dan-allowlist)
19. [Bab 19: Menghentikan Scan](#bab-19-menghentikan-scan)
20. [Bab 20: Backup dan Restore Database](#bab-20-backup-dan-restore-database)
21. [Bab 21: Troubleshooting](#bab-21-troubleshooting)
22. [Bab 22: Build Lintas Platform](#bab-22-build-lintas-platform)
23. [Bab 23: Penggunaan dalam CI/CD](#bab-23-penggunaan-dalam-cicd)
24. [Bab 24: Praktik Keamanan Penggunaan KyyTools](#bab-24-praktik-keamanan-penggunaan-kyytools)

---

## Bab 1: Instalasi Go

KyyTools membutuhkan runtime Golang versi 1.22 atau lebih baru.

### Windows (CMD & PowerShell)
1. Unduh installer resmi MSI dari [https://go.dev/dl/](https://go.dev/dl/).
2. Jalankan installer dan ikuti petunjuk wizard default.
3. Buka jendela Terminal baru, lalu verifikasi:
```cmd
go version
```

### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install -y golang-go
go version
```

### macOS (Homebrew)
```bash
brew install go
go version
```

---

## Bab 2: Persiapan Project

Clone atau buka direktori project `kyytools`:

### Windows CMD:
```cmd
cd /d d:\Kyytools
dir
```

### Windows PowerShell:
```powershell
Set-Location -Path "d:\Kyytools"
Get-ChildItem
```

### Linux / macOS:
```bash
cd ~/kyytools
ls -la
```

---

## Bab 3: Instalasi Dependensi

KyyTools menggunakan dependensi native Go:
- `modernc.org/sqlite`: Driver SQLite 100% murni Go tanpa memerlukan compiler C/CGO.
- `gopkg.in/yaml.v3`: Parser dokumen konfigurasi dan template aturan kerentanan.

Jalankan perintah pengunduhan dependensi:
```bash
go mod tidy
go mod verify
```

---

## Bab 4: Build KyyTools

Proses kompilasi menghasilkan satu binary portabel tanpa dependensi eksternal.

### Windows CMD:
```cmd
go build -o kyytools.exe .\cmd\kyytools
```

### Windows PowerShell:
```powershell
go build -o kyytools.exe .\cmd\kyytools
```

### Linux / macOS:
```bash
go build -o kyytools ./cmd/kyytools
chmod +x kyytools
```

---

## Bab 5: Menjalankan KyyTools

Setelah binary dibuat, Anda dapat mengeksekusinya secara langsung.

### Windows CMD:
```cmd
kyytools.exe
```

### Windows PowerShell:
```powershell
.\kyytools.exe
```

### Linux / macOS:
```bash
./kyytools
```

---

## Bab 6: Menggunakan Menu Interaktif

Saat dijalankan tanpa parameter tambahan, KyyTools menyajikan menu interaktif terminal yang intuitif:

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

Pengguna cukup mengetikkan angka menu yang diinginkan (misalnya `1` untuk Quick Scan) lalu menekan `Enter`. Setiap menu dilengkapi validasi input dan petunjuk navigasi yang jelas.

---

## Bab 7: Quick Scan

Alur kerja Quick Scan dirancang agar pengguna dapat melakukan penilaian cepat dalam hitungan detik:
1. Pilih menu `[1] Quick Scan`.
2. Masukkan target (contoh: `example.com`, `https://example.com`, atau `93.184.216.34`).
3. KyyTools melakukan validasi DNS dan memeriksa kebijakan scope allowlist.
4. Ringkasan target (IP hasil resolusi, port, tipe target) ditampilkan.
5. Konfirmasi eksekusi dengan menekan `Enter` atau mengetik `y`.
6. Progress scan berjalan dengan status interaktif per modul.
7. Temuan dikategorisasikan berdasarkan severity dan disimpan ke database `kyytools.db`.
8. Laporan HTML otomatis di-generate ke folder `reports/`.

---

## Bab 8: Domain Scan

Modul Domain Scan memeriksa:
- Resolusi DNS record A dan AAAA.
- Deteksi Mail Server (MX records).
- Validasi keberadaan SPF (`v=spf1`) untuk memitigasi email spoofing.
- Validasi DMARC (`_dmarc.<domain>`) untuk kebijakan pengamanan email domain organisasi.

Contoh CLI:
```bash
kyytools scan --target mycompany.com --profile quick
```

---

## Bab 9: IP & Port Scan

Modul Port Scanner melakukan TCP handshake terkontrol secara non-destruktif terhadap port-port krusial:
- Web: 80 (HTTP), 443 (HTTPS), 8080, 8443.
- Database: 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis).
- Administrasi: 21 (FTP), 22 (SSH), 3389 (RDP).

Scan dilengkapi batas konkurensi (concurrency limiter) untuk mencegah lonjakan lalu lintas yang dapat membebani target.

Contoh CLI:
```bash
kyytools scan --target 198.51.100.25 --profile network
```

---

## Bab 10: Web Security Scan

Modul Web Security memeriksa parameter pengerasan (hardening) aplikasi:
- **Server Banner Disclosure**: Memeriksa kebocoran versi web server pada header `Server`.
- **Backend Framework Disclosure**: Memeriksa header `X-Powered-By`.
- **HSTS (Strict-Transport-Security)**: Memastikan HTTPS dipaksakan oleh browser.
- **Content-Security-Policy (CSP)**: Memitigasi serangan XSS dan data injection.
- **X-Frame-Options**: Mencegah Clickjacking di dalam iframe.
- **X-Content-Type-Options: nosniff**: Mencegah MIME-sniffing.
- **Cookie Security Flags**: Memastikan flag `HttpOnly` dan `Secure` aktif pada cookie sensitif.

Contoh CLI:
```bash
kyytools scan --target https://myportal.com --profile web
```

---

## Bab 11: TLS Scanner

Modul TLS melakukan handshaking kriptografi untuk memeriksa:
- Validitas rantai sertifikat terhadap Certificate Authority (CA) publik.
- Hostname matching pada Common Name (CN) dan Subject Alternative Name (SAN).
- Sisa hari masa aktif (peringatan jika kedaluwarsa kurang dari 15 hari).
- Peringatan sertifikat kedaluwarsa (Expired) atau Self-Signed.

---

## Bab 12: Subdomain Discovery

KyyTools mendukung pengenalan dan validasi subdomain pada domain target:
- Verifikasi DNS pada kandidat subdomain.
- Penolakan otomatis jika IP hasil resolusi berada di luar scope allowlist.
- Penghindaran brute-force agresif untuk menjaga kestabilan jaringan.

---

## Bab 13: Membuat Template YAML

KyyTools menyertakan engine template berbasis file YAML di direktori `templates/`.

Struktur Template:
```yaml
id: custom-header-check
name: Pemeriksaan Header Kustom
description: Memastikan header otorisasi organisasi terpasang.
severity: MEDIUM
category: Configuration
target_type: URL
check_type: http_header
evidence: "Header X-Company-Auth tidak ditemukan"
remediation: Konfigurasikan reverse proxy untuk menyertakan header X-Company-Auth.
references:
  - https://internal-docs.corp/security
tags:
  - compliance
  - custom
```

Validasi seluruh template yang terpasang dengan:
```bash
kyytools templates validate
```

---

## Bab 14: Melihat Riwayat Scan

Seluruh pengujian tercatat dalam database SQLite `kyytools.db`.

Untuk melihat ringkasan riwayat:
```bash
kyytools history
```

Output menampilkan ID Sesi, Target, Profil, Status, Skor Risiko, Jumlah Temuan, dan Waktu Eksekusi.

Untuk melihat rincian temuan pada sesi scan tertentu:
```bash
kyytools findings --scan-id 1
```

---

## Bab 15: Membaca Severity & Risk Scoring

KyyTools membagi temuan ke dalam lima tingkat keparahan standar industri:
- **CRITICAL** (Merah): Kerentanan kritis yang memerlukan tindakan perbaikan instan.
- **HIGH** (Oranye): Celah keamanan signifikan dengan potensi eksploitasi tinggi.
- **MEDIUM** (Kuning): Masalah konfigurasi keamanan yang perlu diperbaiki.
- **LOW** (Hijau): Praktik keamanan terbaik dan rekomendasi hardening.
- **INFORMATIONAL** (Biru): Informasi arsitektur atau observasi non-vulnerabilitas.

Skor risiko dihitung pada skala 0.0 hingga 10.0 dengan mempertimbangkan bobot severity dan tingkat kepastian (*confidence*).

---

## Bab 16: Membuat Laporan JSON, CSV, dan HTML

Laporan dapat diekspor kapan saja dari riwayat scan:

### Ekspor HTML:
```bash
kyytools report --scan-id 1 --format html
```
Menghasilkan laporan visual interaktif di `reports/scan-001.html`.

### Ekspor JSON:
```bash
kyytools report --scan-id 1 --format json
```
Cocok untuk integrasi API dan ingest ke SIEM.

### Ekspor CSV:
```bash
kyytools report --scan-id 1 --format csv
```
Cocok untuk dibuka di spreadsheet Excel atau Google Sheets.

---

## Bab 17: Mengubah Konfigurasi

File konfigurasi berada di `configs/config.yaml`. Anda dapat mengubah timeout, konkurensi, format default laporan, dan profil pemindaian.

Tampilkan konfigurasi aktif dengan:
```bash
kyytools config show
```

---

## Bab 18: Mengelola Scope dan Allowlist

Secara default, KyyTools menerapkan kebijakan keamanan ketat:
- **Loopback Protection**: `127.0.0.1`, `::1`, dan `localhost` ditolak otomatis.
- **Private Network Protection**: IP privat RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) ditolak secara default.
- **Cloud Metadata Protection**: IP `169.254.169.254` diblokir untuk mencegah serangan SSRF terhadap instance cloud (AWS, GCP, Azure).

Jika Anda ingin melakukan pengujian pada lab internal yang terisolasi, edit `configs/config.yaml`:
```yaml
scope:
  allow_private_ips: true
  allow_loopback: true
```

---

## Bab 19: Menghentikan Scan

Jika scan sedang berjalan dan Anda ingin membatalkannya:
- Tekan **Ctrl + C** satu kali pada terminal.
- KyyTools menangkap sinyal interupsi melalui `context.Context` pembatalan, menutup koneksi jaringan yang sedang terbuka, mencatat status `CANCELLED` pada database SQLite, dan keluar dengan bersih tanpa meninggalkan koneksi menggantung.

---

## Bab 20: Backup dan Restore Database

Database KyyTools disimpan dalam satu file SQLite: `kyytools.db`.

### Backup:
- Windows:
```cmd
copy kyytools.db kyytools_backup.db
```
- Linux / macOS:
```bash
cp kyytools.db kyytools_backup.db
```

### Restore:
Cukup salin kembali file backup ke `kyytools.db`.

---

## Bab 21: Troubleshooting

### Error: "target mengarah ke alamat IP privat/internal"
*Penyebab*: KyyTools memblokir IP privat secara default demi keamanan.  
*Solusi*: Jika target adalah lab internal resmi, aktifkan `allow_private_ips: true` pada `configs/config.yaml`.

### Error: "resolusi DNS mengandung IP terlarang"
*Penyebab*: Fitur Anti-DNS Rebinding mendeteksi domain publik mengarah ke IP internal.  
*Solusi*: Periksa konfigurasi DNS target Anda.

### Error database SQLite terkunci (*database is locked*)
*Penyebab*: File SQLite dibuka oleh aplikasi lain.  
*Solusi*: KyyTools telah mengaktifkan mode WAL (*Write-Ahead Logging*). Pastikan tidak ada aplikasi database eksternal yang memegang lock eksklusif pada file `kyytools.db`.

---

## Bab 22: Build Lintas Platform

Go mendukung kompilasi silang (cross-compilation) bawaan. Anda dapat mem-build binary untuk sistem operasi lain langsung dari mesin Anda:

### Build untuk Linux AMD64:
```cmd
set GOOS=linux
set GOARCH=amd64
go build -o kyytools .\cmd\kyytools
```

### Build untuk macOS ARM64 (Apple Silicon):
```cmd
set GOOS=darwin
set GOARCH=arm64
go build -o kyytools-mac .\cmd\kyytools
```

### Build untuk Windows x64:
```cmd
set GOOS=windows
set GOARCH=amd64
go build -o kyytools.exe .\cmd\kyytools
```

---

## Bab 23: Penggunaan dalam CI/CD

KyyTools dapat diintegrasikan ke dalam pipeline GitHub Actions atau GitLab CI untuk automated security testing:

```yaml
# Contoh GitHub Actions Step
- name: Run KyyTools Security Assessment
  run: |
    ./kyytools scan --target https://staging.mycompany.com --profile web
    ./kyytools report --scan-id 1 --format json
```

Jika terdeteksi temuan berkategori `CRITICAL`, proses pipeline dapat dikonfigurasi untuk fail otomatis guna mencegah rilis aplikasi yang rentan.

---

## Bab 24: Praktik Keamanan Penggunaan KyyTools

1. **Otorisasi Tertulis**: Selalu pastikan Anda mengantongi izin tertulis dari pemilik sistem sebelum melakukan scanning.
2. **Batasi Jam Scanning**: Lakukan pemindaian intensif di luar jam sibuk untuk menghindari degradasi layanan operasional.
3. **Penyimpanan Laporan**: Laporan hasil scan berisi informasi topologi sistem dan temuan kerentanan; simpan file laporan di direktori yang terenkripsi dan terlindungi hak aksesnya.
4. **Non-Destructive**: KyyTools didesain untuk audit non-destruktif. Hindari memodifikasi modul untuk melakukan injeksi payload destruktif.
