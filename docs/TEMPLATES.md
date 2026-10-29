# Panduan Template Kerentanan KyyTools 📜

KyyTools menyertakan engine template deklaratif berbasis YAML yang aman, cepat, dan non-destruktif.

---

## Filosofi Keamanan Template

- **Tanpa Eksekusi Kode Arbitrer**: Template KyyTools tidak mengizinkan eksekusi shell command atau binary eksternal untuk mencegah risiko keamanan pada mesin pengguna (*zero code execution risk*).
- **Audit Non-Destruktif**: Seluruh rule dirancang untuk memeriksa header HTTP, respon path statis, metadata sertifikat TLS, dan banner port.

---

## Struktur Anatomi Template YAML

Setiap file `.yaml` di folder `templates/` memuat field berikut:

```yaml
id: unique-rule-id
name: Judul Singkat Kerentanan
description: Penjelasan mengenai sifat dan dampak kerentanan.
severity: CRITICAL | HIGH | MEDIUM | LOW | INFO
category: Kategori Masalah (mis. Information Disclosure, Misconfiguration)
target_type: DOMAIN | IPV4 | IPV6 | URL
check_type: http_path | http_header | tls_handshake | port_banner
evidence: "Ringkasan bukti yang diharapkan saat rule cocok"
remediation: Langkah perbaikan teknis yang disarankan.
references:
  - https://owasp.org/...
tags:
  - tag1
  - tag2
metadata:
  key: value
```

---

## Contoh Template Bawaan

1. `templates/http/git-exposure.yaml`: Mendeteksi paparan direktori `/.git/config`.
2. `templates/http/env-disclosure.yaml`: Mendeteksi file konfigurasi sensitif `/.env`.
3. `templates/http/cors-misconfig.yaml`: Mendeteksi wildcard `Access-Control-Allow-Origin: *`.
4. `templates/tls/tls-deprecated-version.yaml`: Mendeteksi protokol usang TLS 1.0 dan 1.1.
5. `templates/misconfiguration/default-admin.yaml`: Mendeteksi interface panel login publik.

---

## Validasi Template

Jalankan perintah berikut untuk memverifikasi sintaks template Anda:
```bash
kyytools templates validate
```
