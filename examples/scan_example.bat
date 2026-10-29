@echo off
REM Contoh Skrip Otomatisasi Scan KyyTools untuk Windows CMD / Batch

echo [INFO] Menjalankan Quick Scan pada target...
kyytools.exe scan --target example.com --profile quick

echo [INFO] Mengekspor laporan HTML untuk scan terbaru...
kyytools.exe report --scan-id 1 --format html

echo [INFO] Selesai! Buka folder reports/ untuk melihat hasil laporan.
pause
