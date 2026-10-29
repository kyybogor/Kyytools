# Kebijakan Keamanan & Panduan Penggunaan Legal ⚖️

KyyTools Security Scanner dirancang khusus untuk tujuan audit keamanan defensif, perbaikan sistem (*remediation*), dan pemantauan kepatuhan (*compliance monitoring*).

---

## 1. Etika & Legalitas

- **Izin Tertulis**: Dilarang keras melakukan scanning terhadap jaringan, domain, atau server tanpa izin tertulis (*written consent*) dari pemilik sah aset tersebut.
- **Tanggung Jawab Pengguna**: Pengembang KyyTools tidak bertanggung jawab atas penyalahgunaan atau kerugian yang ditimbulkan akibat penggunaan tool ini di luar koridor hukum.
- **Kepatuhan Regulasi**: Pastikan aktivitas scanning Anda mematuhi regulasi perlindungan data dan undang-undang keamanan siber yang berlaku (seperti UU ITE di Indonesia).

---

## 2. Fitur Keamanan Bawaan (Built-in Guardrails)

KyyTools mengimplementasikan kontrol defensif berlapis untuk mencegah penyalahgunaan secara tidak disengaja:

1. **Penolakan Loopback (Localhost)**:
   - Alamat `127.0.0.1`, `::1`, dan hostname `localhost` ditolak otomatis secara default.
2. **Penolakan Jaringan Privat (RFC 1918)**:
   - Rentang `10.0.0.0/8`, `172.16.0.0/12`, dan `192.168.0.0/16` ditolak secara default.
3. **Mitigasi SSRF & DNS Rebinding**:
   - Seluruh hasil resolusi DNS record A dan AAAA divalidasi sebelum koneksi soket jaringan dibuka.
   - Jika suatu domain publik menghasilkan resolusi ke alamat IP internal, koneksi langsung dibatalkan seketika.
4. **Pencegahan Redirect Keluar Scope**:
   - Fitur HTTP redirect memeriksa target lokasi baru sebelum membuat koneksi berikutnya.
5. **Pemeriksaan Non-Destruktif**:
   - KyyTools tidak pernah menyertakan payload eksploitasi destruktif atau eksekusi kode arbitrer.
