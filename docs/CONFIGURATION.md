# Panduan Konfigurasi KyyTools (config.yaml) ⚙️

File konfigurasi utama KyyTools berada di:
`configs/config.yaml`

File ini dibuat secara otomatis jika belum ada saat pertama kali KyyTools dijalankan.

---

## Struktur File Konfigurasi

```yaml
app:
  name: "KyyTools Security Scanner"
  version: "1.0.0"
  environment: "production"
  log_level: "info"
  no_color: false # Set true jika terminal Anda tidak mendukung kode ANSI warna

scope:
  allow_private_ips: false # Default false: menolak IP privat RFC 1918 demi keamanan
  allow_loopback: false    # Default false: menolak localhost dan 127.0.0.1
  allowed_domains: []      # Batasi pemindaian hanya pada domain ini (contoh: ["*.example.com"])
  allowed_cidrs: []        # Batasi pemindaian hanya pada blok CIDR ini
  blocked_domains:
    - "localhost"
  blocked_cidrs:
    - "127.0.0.0/8"
    - "169.254.0.0/16"
    - "::1/128"

scanner:
  default_profile: "quick"
  global_timeout: 300      # Batas waktu global scanning (detik)
  module_timeout: 30       # Batas waktu maksimum per modul (detik)
  max_concurrency: 50      # Jumlah thread bersamaan
  rate_limit_rps: 30       # Batas permintaan per detik
  follow_redirect: false   # Anti-SSRF: nonaktifkan otomatis mengikuti redirect
  max_redirects: 3
  user_agent: "KyyTools-Security-Scanner/1.0.0 (+https://github.com/kyybogor/Kyytools)"

database:
  driver: "sqlite"
  path: "kyytools.db"      # Lokasi file database SQLite

reports:
  output_dir: "reports"    # Folder penyimpanan hasil ekspor
  auto_export: true        # Ekspor laporan otomatis setelah scan selesai
  default_type: "html"     # Pilihan default: html, json, atau csv
```

---

## Profil Pemindaian (Scan Profiles)

KyyTools menyertakan 5 profil default:
1. `quick`: Validasi target, DNS resolver, status HTTP headers, port vital (80, 443, 8080, 8443).
2. `standard`: DNS komprehensif, HTTP/TLS, security headers, cookie flags, 20 port umum.
3. `web`: Fokus aplikasi web, sertifikat TLS, headers, cookie security, template checks.
4. `network`: Resolusi IP, port scan diperluas, identifikasi layanan banner.
5. `custom`: Profil fleksibel yang dapat disesuaikan pengguna.
