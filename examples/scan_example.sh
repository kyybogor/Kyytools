#!/usr/bin/env bash
# Contoh Skrip Otomatisasi Scan KyyTools untuk Linux / macOS

set -euo pipefail

echo "[INFO] Menjalankan Quick Scan pada target..."
./kyytools scan --target example.com --profile quick

echo "[INFO] Mengekspor laporan HTML..."
./kyytools report --scan-id 1 --format html

echo "[INFO] Selesai! Periksa file laporan di direktori reports/."
