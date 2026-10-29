# Referensi Perintah CLI KyyTools 📖

Dokumen ini memuat seluruh perintah, argumen, opsi, contoh output, dan kode keluar (*exit code*) yang didukung oleh binary `kyytools`.

---

## Ringkasan Perintah

| Perintah | Deskripsi |
|---|---|
| `kyytools` | Menjalankan Menu Interaktif berbasis terminal |
| `kyytools scan` | Menjalankan proses security scan secara non-interaktif |
| `kyytools history` | Menampilkan tabel riwayat sesi pemindaian |
| `kyytools findings` | Menampilkan detail temuan berdasarkan Scan ID |
| `kyytools report` | Mengekspor laporan dalam format HTML, JSON, atau CSV |
| `kyytools templates list` | Menampilkan daftar template aturan kerentanan YAML |
| `kyytools templates validate` | Memvalidasi sintaks dan metadata seluruh template |
| `kyytools config show` | Menampilkan konfigurasi yang sedang aktif |
| `kyytools version` | Menampilkan nomor versi KyyTools |
| `kyytools help` | Menampilkan panduan bantuan cepat |

---

## 1. `kyytools` (Menu Interaktif)

Menjalankan antarmuka terminal interaktif.

### Contoh Eksekusi:
```bash
kyytools
```

### Tampilan Output:
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

---

## 2. `kyytools scan`

Menjalankan pemindaian non-interaktif terhadap target tertentu.

### Sintaks:
```bash
kyytools scan --target <HOST|IP|URL> [--profile <quick|standard|web|network|custom>]
```

### Parameter:
- `--target` *(Wajib)*: Domain (mis. `example.com`), IP (mis. `93.184.216.34`), atau URL (mis. `https://example.com`).
- `--profile` *(Opsional)*: Pilihan profil scanning. Nilai default: `quick`.
  - `quick`: Validasi target, DNS resolver, status HTTP headers, port vital (80, 443, 8080, 8443).
  - `standard`: DNS komprehensif, HTTP/TLS, security headers, cookie flags, 20 port umum.
  - `web`: Fokus aplikasi web, sertifikat TLS, headers, cookie security, template checks.
  - `network`: Resolusi IP, port scan diperluas, identifikasi layanan banner.
  - `custom`: Konfigurasi profil yang disesuaikan pengguna.

### Contoh Penggunaan:
```bash
kyytools scan --target example.com --profile quick
kyytools scan --target 198.51.100.10 --profile standard
kyytools scan --target https://mycompany.org --profile web
```

---

## 3. `kyytools history`

Menampilkan daftar sesi pemindaian yang pernah dijalankan dan tersimpan di database `kyytools.db`.

### Contoh Eksekusi:
```bash
kyytools history
```

### Contoh Output:
```text
=== Riwayat Sesi Scan KyyTools ===
┌────┬─────────────┬────────┬───────────┬──────┬────────┬────────┬──────────────┬─────────┐
│ ID │ Target      │ Profil │ Status    │ Skor │ Temuan │ Durasi │ Mulai        │ Selesai │
├────┼─────────────┼────────┼───────────┼──────┼────────┼────────┼──────────────┼─────────┤
│ 1  │ example.com │ quick  │ COMPLETED │ 4.5  │ 3      │ 850ms  │ 29 Oct 16:30 │ 16:30   │
└────┴─────────────┴────────┴───────────┴──────┴────────┴────────┴──────────────┴─────────┘
```

---

## 4. `kyytools findings`

Menampilkan daftar temuan keamanan lengkap pada suatu sesi pemindaian.

### Sintaks:
```bash
kyytools findings --scan-id <ID>
```

### Parameter:
- `--scan-id` *(Wajib)*: Nomor ID sesi pemindaian (dapat dilihat dari `kyytools history`).

### Contoh Penggunaan:
```bash
kyytools findings --scan-id 1
```

---

## 5. `kyytools report`

Mengekspor laporan hasil penilaian keamanan ke dalam file laporan.

### Sintaks:
```bash
kyytools report --scan-id <ID> [--format <html|json|csv>]
```

### Parameter:
- `--scan-id` *(Wajib)*: Nomor ID sesi pemindaian.
- `--format` *(Opsional)*: Format output file: `html` (default), `json`, atau `csv`.

### Contoh Penggunaan:
```bash
kyytools report --scan-id 1 --format html
kyytools report --scan-id 1 --format json
kyytools report --scan-id 1 --format csv
```

### Lokasi Output:
File tersimpan di direktori `reports/`:
- `reports/scan-001.html`
- `reports/scan-001.json`
- `reports/scan-001.csv`

---

## 6. `kyytools templates`

Mengelola dan memverifikasi template aturan kerentanan YAML KyyTools.

### Sintaks:
```bash
# Menampilkan daftar template yang terpasang
kyytools templates list

# Memvalidasi sintaks seluruh template YAML
kyytools templates validate
```

---

## 7. `kyytools config show`

Menampilkan ringkasan konfigurasi sistem saat ini dari file `configs/config.yaml`.

### Contoh Eksekusi:
```bash
kyytools config show
```

---

## 8. `kyytools version`

Menampilkan informasi versi KyyTools yang terpasang.

### Contoh Eksekusi:
```bash
kyytools version
```

### Output:
```text
KyyTools Security Scanner v1.0.0 (Golang native security assessment tool)
```

---

## Kode Keluar (*Exit Codes*)

| Exit Code | Makna |
|---|---|
| `0` | Operasi berhasil diselesaikan tanpa error |
| `1` | Terjadi kesalahan validasi target, konfigurasi, atau argumen CLI tidak valid |
| `130` | Proses dihentikan paksa oleh pengguna melalui sinyal pembatalan (**Ctrl + C**) |
