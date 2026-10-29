# Panduan Instalasi KyyTools Security Scanner 📦

Panduan langkah demi langkah untuk menginstal dan menyiapkan KyyTools di sistem operasi Windows, Linux, dan macOS.

---

## 1. Prasyarat Sistem

- **Golang**: Versi 1.22 atau lebih baru.
- **Git** (opsional): Untuk mengkloning kode sumber.
- **SQLite**: Runtime embedded sudah disertakan via pure Go driver (`modernc.org/sqlite`), sehingga tidak membutuhkan instalasi DLL atau dependensi CGO terpisah!

---

## 2. Instalasi di Windows

### Langkah 1: Buka Command Prompt atau PowerShell
Arahkan ke folder project `Kyytools`:
```cmd
cd /d d:\Kyytools
```

### Langkah 2: Unduh Dependensi
```cmd
go mod download
```

### Langkah 3: Kompilasi Binary
```cmd
go build -o kyytools.exe .\cmd\kyytools
```

### Langkah 4: (Opsional) Menambahkan ke System PATH
Agar `kyytools` dapat dipanggil dari mana saja:
```powershell
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";d:\Kyytools", [EnvironmentVariableTarget]::User)
```

Verifikasi:
```cmd
kyytools.exe version
```

---

## 3. Instalasi di Linux (Ubuntu / Debian / CentOS / Arch)

### Langkah 1: Masuk ke Direktori Project
```bash
cd ~/kyytools
```

### Langkah 2: Build Binary
```bash
go build -o kyytools ./cmd/kyytools
chmod +x kyytools
```

### Langkah 3: Pindahkan ke System Binary
```bash
sudo mv kyytools /usr/local/bin/
```

Verifikasi:
```bash
kyytools version
```

---

## 4. Instalasi di macOS

### Langkah 1: Build Binary
```bash
go build -o kyytools ./cmd/kyytools
chmod +x kyytools
```

### Langkah 2: Pasang ke PATH
```bash
sudo cp kyytools /usr/local/bin/
```

Verifikasi:
```bash
kyytools version
```
