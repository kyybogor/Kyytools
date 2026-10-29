# Panduan Pemecahan Masalah (Troubleshooting) 🔧

Daftar kendala umum dan solusi saat menggunakan KyyTools Security Scanner.

---

## 1. Target Ditolak Saat Memulai Scan

### Pesan Error:
`target mengarah ke alamat IP privat/internal (RFC 1918/ULA) yang ditolak secara default`

### Penjelasan:
KyyTools memblokir IP privat (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) secara otomatis untuk mencegah serangan SSRF dan scanning internal yang tidak sengaja.

### Solusi:
Jika Anda memang sedang mengaudit server lokal/internal lab yang sah, buka `configs/config.yaml` dan ubah:
```yaml
scope:
  allow_private_ips: true
```

---

## 2. Target Localhost Ditolak

### Pesan Error:
`target secara eksplisit diblokir dalam konfigurasi scope: localhost terdaftar di blocked_domains`

### Solusi:
Untuk menguji aplikasi lokal di mesin sendiri:
```yaml
scope:
  allow_loopback: true
```
Lalu hapus `localhost` dari daftar `blocked_domains` pada `configs/config.yaml`.

---

## 3. SQLite Database Locked

### Penjelasan:
Aplikasi database eksternal membuka file `kyytools.db` dengan mode penulisan eksklusif.

### Solusi:
Tutup viewer SQLite pihak ketiga. KyyTools menggunakan mode WAL (*Write-Ahead Logging*) dengan timeout 5000ms untuk mendukung konkuren baca-tulis.

---

## 4. Tampilan Warna Berantakan di Terminal Tertentu

### Solusi:
Jalankan KyyTools dengan variabel lingkungan `NO_COLOR=1` atau aktifkan `no_color: true` di `configs/config.yaml`.
- PowerShell: `$env:NO_COLOR="1"; .\kyytools.exe`
- CMD: `set NO_COLOR=1 && kyytools.exe`
- Linux/macOS: `NO_COLOR=1 ./kyytools`
