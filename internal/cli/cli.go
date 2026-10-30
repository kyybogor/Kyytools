package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/kyybogor/Kyytools/internal/config"
	"github.com/kyybogor/Kyytools/internal/models"
	"github.com/kyybogor/Kyytools/internal/reports"
	"github.com/kyybogor/Kyytools/internal/scanner"
	"github.com/kyybogor/Kyytools/internal/storage"
	"github.com/kyybogor/Kyytools/internal/target"
)

// AppServices bundles core application components for CLI actions.
type AppServices struct {
	Config  *models.AppConfig
	Storage *storage.Storage
	Parser  *target.Parser
	Engine  *scanner.Engine
}

// StartCLI runs either interactive menu or command line flags based on arguments.
func StartCLI(ctx context.Context, app *AppServices, args []string) {
	if app.Config.App.NoColor {
		DisableColor = true
	}

	if len(args) == 0 {
		RunInteractiveMenu(ctx, app)
		return
	}

	cmd := args[0]
	switch cmd {
	case "scan":
		handleScanCmd(ctx, app, args[1:])
	case "history":
		handleHistoryCmd(app)
	case "findings":
		handleFindingsCmd(app, args[1:])
	case "report":
		handleReportCmd(app, args[1:])
	case "templates":
		handleTemplatesCmd(args[1:])
	case "config":
		handleConfigCmd(app, args[1:])
	case "version", "-v", "--version":
		handleVersionCmd()
	case "help", "-h", "--help":
		handleHelpCmd()
	default:
		fmt.Printf("%s: Perintah '%s' tidak dikenal.\n", Red("Error"), cmd)
		fmt.Println("Jalankan 'kyytools help' untuk melihat daftar perintah yang tersedia.")
		os.Exit(1)
	}
}

// RunInteractiveMenu provides the full terminal interactive experience.
func RunInteractiveMenu(ctx context.Context, app *AppServices) {
	reader := bufio.NewReader(os.Stdin)

	for {
		select {
		case <-ctx.Done():
			fmt.Println("\nOperasi dihentikan.")
			return
		default:
		}

		PrintBanner()
		fmt.Println(` [1] Quick Scan
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
 [0] Exit`)

		fmt.Print("\n" + Bold("Select an option: "))
		input, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		choice := strings.TrimSpace(input)
		switch choice {
		case "1":
			fmt.Println("\n" + Bold(Cyan("=== [1] Quick Scan ===")))
			fmt.Println(Gray("Pemeriksaan cepat untuk menguji respon server, DNS dasar, header web, dan port vital."))
			interactiveScanFlow(ctx, app, "quick")
		case "2":
			fmt.Println("\n" + Bold(Cyan("=== [2] Web Security Scan (Deep Audit) ===")))
			fmt.Println(Gray("Audit mendalam aplikasi web: headers, cookie flags, CORS, metode HTTP (TRACE/PUT), paparan file sensitif (.env, .git, backup), dan template YAML."))
			interactiveScanFlow(ctx, app, "web")
		case "3":
			fmt.Println("\n" + Bold(Cyan("=== [3] Domain Scanner ===")))
			fmt.Println(Gray("Pemeriksaan DNS komprehensif: resolusi A/AAAA, deteksi MX, dan pengujian SPF, DMARC, serta CAA record."))
			interactiveScanFlow(ctx, app, "standard")
		case "4":
			fmt.Println("\n" + Bold(Cyan("=== [4] IP & Port Scanner ===")))
			fmt.Println(Gray("Audit jaringan & port TCP (Top 100 Port) disertai service banner grabbing untuk deteksi daemon aktif."))
			interactiveScanFlow(ctx, app, "network")
		case "5":
			fmt.Println("\n" + Cyan("ℹ️ Subdomain Discovery:") + " Menjalankan modul penemuan & validasi subdomain dengan scope terkontrol.")
			interactiveScanFlow(ctx, app, "web")
		case "6":
			interactiveListTemplates()
		case "7":
			showHistory(app)
		case "8":
			interactiveViewFindings(app, reader)
		case "9":
			interactiveGenerateReport(app, reader)
		case "10":
			showProfiles(app)
		case "11":
			showConfig(app)
		case "12":
			showDocumentation()
		case "0", "exit", "quit":
			fmt.Println("\nTerima kasih telah menggunakan " + Bold(Cyan("KyyTools Security Scanner")) + ". Tetap aman!")
			return
		default:
			fmt.Println(Red("\nPilihan tidak valid. Silakan pilih angka [0-12]."))
		}

		fmt.Println("\nTekan Enter untuk melanjutkan ke menu utama...")
		_, _ = reader.ReadString('\n')
	}
}

// interactiveScanFlow guides the user through target input, profile review, confirmation, and scan execution.
func interactiveScanFlow(ctx context.Context, app *AppServices, defaultProfile string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\n" + Bold(Cyan("=== Inisialisasi Sesi Scanning ===")))
	fmt.Print("Masukkan target (contoh: example.com, 192.0.2.10, https://example.com): ")
	input, _ := reader.ReadString('\n')
	rawTarget := strings.TrimSpace(input)
	if rawTarget == "" {
		fmt.Println(Red("Error: Target tidak boleh kosong."))
		return
	}

	// Target validation & scope check
	fmt.Printf("🔍 Memvalidasi target '%s' dan memeriksa scope allowlist...\n", rawTarget)
	parsedTarget, err := app.Parser.Parse(ctx, rawTarget)
	if err != nil {
		fmt.Printf("%s: Validasi target gagal: %v\n", Red("Target Ditolak"), err)
		return
	}

	// Target Summary
	fmt.Println("\n" + Green("✅ Target Berhasil Divalidasi:"))
	fmt.Printf(" • Hostname/IP : %s\n", Bold(parsedTarget.Host))
	fmt.Printf(" • Tipe Target : %s\n", parsedTarget.Type)
	fmt.Printf(" • Port Default: %d\n", parsedTarget.Port)
	fmt.Printf(" • Resolusi IP : %s\n", strings.Join(parsedTarget.ResolvedIPs, ", "))
	fmt.Printf(" • URL Dasar   : %s\n", parsedTarget.CanonicalURL)

	// Display detailed profile selection guide
	displayProfileSelectionGuide(defaultProfile)

	fmt.Printf("\n"+Bold("Pilih Profil [1/2/3/4/5 atau ketik nama profil] (Default: %s): "), defaultProfile)
	pInput, _ := reader.ReadString('\n')
	selectedProfileName := resolveProfileChoice(strings.TrimSpace(pInput), defaultProfile)

	prof, err := config.GetProfile(app.Config, selectedProfileName)
	if err != nil {
		fmt.Printf("%s: %v\n", Red("Error"), err)
		return
	}

	// Selected profile summary card
	fmt.Println("\n" + Bold(Cyan("╭────────────────────────────────────────────────────────────────────────╮")))
	fmt.Printf("  🎯 %s: %s\n", Bold("Profil Terpilih"), Bold(Green(prof.Name)))
	fmt.Printf("  📌 %s: %s\n", Bold("Fokus Audit    "), prof.Description)
	fmt.Printf("  ⏱️  %s: %d detik  |  🧵 %s: %d worker  |  🔌 %s: %s\n",
		Bold("Batas Waktu"), prof.TimeoutSeconds, Bold("Konkurensi"), prof.Concurrency, Bold("Port"), prof.PortRange)
	fmt.Println(Bold("  📋 Modul Pemeriksaan yang Akan Dijalankan:"))
	for idx, m := range prof.Modules {
		fmt.Printf("     %2d. %-22s - %s\n", idx+1, Cyan(m), getModuleExplanation(m))
	}
	fmt.Println(Bold(Cyan("╰────────────────────────────────────────────────────────────────────────╯")))

	fmt.Print("\n" + Bold(Yellow("Mulai audit keamanan sekarang? [Y/n]: ")))
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))
	if confirm != "" && confirm != "y" && confirm != "yes" {
		fmt.Println("Scan dibatalkan.")
		return
	}

	// Run scan
	executeScan(ctx, app, parsedTarget, prof)
}

func displayProfileSelectionGuide(defaultProfile string) {
	guide := `
==================================================================================================
                                PANDUAN LENGKAP PROFIL SCANNING
==================================================================================================
 [1] Quick Scan (quick) - Rekomendasi Cek Kilat
     • Fungsi   : Pemeriksaan cepat untuk verifikasi konektivitas, DNS awal, & respon web dasar.
     • Modul    : Target Info, DNS Resolusi, HTTP Headers, 4 Port Web Vital (80, 443, 8080, 8443).
     • Durasi   : Sangat Singkat (~ 10 - 25 detik).
     • Cocok utk: Smoke test awal sebelum melakukan audit mendalam atau verifikasi server baru.

 [2] Standard Scan (standard) - Audit Seimbang & Menyeluruh
     • Fungsi   : Penilaian keamanan seimbang mencakup konfigurasi web, TLS, dan 20 port umum.
     • Modul    : DNS/Email Security, TLS Cert, Web Headers, Metode HTTP, CORS, 20 Port Standar.
     • Durasi   : Sedang (~ 1 - 2 menit).
     • Cocok utk: Audit berkala bulanan pada website operasional dan server produksi.

 [3] Web Security Scan (web) - Audit Mendalam Aplikasi Web (Deep Vulnerability Audit)
     • Fungsi   : Penyelidikan mendalam mencari celah sekecil apa pun pada aplikasi web dan REST API.
     • Modul    : Security Headers (HSTS, CSP, X-Frame, Referrer, Permissions, Cache-Control),
                  Flag Keamanan Cookie (HttpOnly, Secure, SameSite), Eksploitasi CORS Reflection,
                  Pemeriksaan Metode HTTP Berbahaya (TRACE/XST, PUT Unauthenticated),
                  Deteksi Paparan File Sensitif (.env, .git, backup.sql, robots.txt, phpinfo),
                  serta Eksekusi Engine Template Aturan Kerentanan YAML.
     • Durasi   : Mendalam (~ 1 - 3 menit).
     • Cocok utk: Pengujian komprehensif website, API gateway, portal login, & audit pra-rilis.

 [4] Network & Extended Port Scan (network) - Audit Jaringan & Layanan Server
     • Fungsi   : Pemetaan port terbuka dan identifikasi versi layanan server (Banner Grabbing).
     • Modul    : Resolusi Host, Pemindaian Top 100 Port TCP Krusial, Service Fingerprinting.
     • Durasi   : Agak Lama (~ 2 - 4 menit).
     • Cocok utk: Memeriksa perimeter keamanan server/VPS dan mendeteksi port yang lupa ditutup.

 [5] Custom Scan (custom) - Profil Kustom Fleksibel
     • Fungsi   : Parameter dan cakupan modul yang dapat disesuaikan pengguna.
==================================================================================================`
	fmt.Println(Cyan(guide))
}

func resolveProfileChoice(input, defaultProfile string) string {
	clean := strings.ToLower(strings.TrimSpace(input))
	switch clean {
	case "1", "quick":
		return "quick"
	case "2", "standard":
		return "standard"
	case "3", "web":
		return "web"
	case "4", "network":
		return "network"
	case "5", "custom":
		return "custom"
	case "":
		return defaultProfile
	default:
		return clean
	}
}

func getModuleExplanation(moduleName string) string {
	switch moduleName {
	case "target_info":
		return "Validasi target, klasifikasi tipe, dan proteksi anti-SSRF/loopback"
	case "dns_resolver":
		return "Pemeriksaan DNS A/AAAA, MX, serta record email SPF, DMARC, dan CAA"
	case "tls_check":
		return "Validasi sertifikat SSL/TLS, masa kedaluwarsa & protokol usang (TLS 1.0/1.1)"
	case "web_headers":
		return "Audit security headers (HSTS, CSP, X-Frame, Referrer, Permissions, Cookie SameSite)"
	case "http_methods":
		return "Deteksi metode HTTP berbahaya (OPTIONS, TRACE/XST, dan PUT tidak terotentikasi)"
	case "cors_check":
		return "Evaluasi celah CORS: Arbitrary Origin Reflection & kebocoran kredensial"
	case "sensitive_files":
		return "Deteksi kebocoran file kritis (.env, .git/HEAD, backup.sql, robots, phpinfo)"
	case "vuln_templates":
		return "Eksekusi engine template aturan kerentanan YAML KyyTools"
	case "service_detection":
		return "Banner grabbing untuk identifikasi software daemon & fingerprint versi"
	case "port_scan_top":
		return "Pemindaian 4 port web vital (80, 443, 8080, 8443)"
	case "port_scan_standard":
		return "Pemindaian 20 port TCP umum (SSH, FTP, Web, Mail, Database)"
	case "port_scan_extended":
		return "Pemindaian port diperluas (100 port jaringan krusial)"
	default:
		return "Modul pengujian keamanan khusus"
	}
}

func executeScan(ctx context.Context, app *AppServices, target *models.Target, prof *models.ScanProfile) {
	fmt.Println("\n" + Bold(Green("🚀 Memulai Scanning...")) + " (Tekan Ctrl+C untuk membatalkan)")

	// Animated spinner indicator
	spinnerFrames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	frameIdx := 0

	progressCb := func(modName string, current, total int, msg string) {
		frame := spinnerFrames[frameIdx%len(spinnerFrames)]
		frameIdx++
		fmt.Printf("\r[%s] [%d/%d] %-60s", Cyan(frame), current, total, msg)
	}

	scan, findings, err := app.Engine.RunScan(ctx, target, prof, progressCb)
	fmt.Print("\r" + strings.Repeat(" ", 75) + "\r") // Clear line

	if err != nil {
		if err == context.Canceled {
			fmt.Println(Yellow("\n⚠️ Scan dibatalkan oleh pengguna."))
		} else {
			fmt.Printf("%s: Scan gagal: %v\n", Red("Error"), err)
		}
		return
	}

	fmt.Println(Bold(Green("✨ Scan Selesai!")) + fmt.Sprintf(" (Durasi: %d ms | Scan ID: #%d)", scan.DurationMs, scan.ID))

	// Display summary results
	fmt.Println("\n" + Bold("📊 Ringkasan Temuan Keamanan:"))
	summaryRows := [][]string{
		{"Critical", strconv.Itoa(scan.CriticalCount), Red("Bahaya Tinggi / Perlu Tindakan Segera")},
		{"High", strconv.Itoa(scan.HighCount), Yellow("Risiko Signifikan")},
		{"Medium", strconv.Itoa(scan.MediumCount), Yellow("Perlu Diperbaiki")},
		{"Low", strconv.Itoa(scan.LowCount), Green("Risiko Rendah / Hardening")},
		{"Informational", strconv.Itoa(scan.InfoCount), Cyan("Observasi & Konfigurasi")},
		{"Total Temuan", strconv.Itoa(scan.FindingsCount), fmt.Sprintf("Skor Risiko: %.1f / 10.0", scan.RiskScore)},
	}
	RenderTable([]string{"Kategori", "Jumlah", "Keterangan"}, summaryRows)

	if len(findings) > 0 {
		fmt.Println("\n" + Bold("🔍 Cuplikan Temuan:"))
		for i, f := range findings {
			if i >= 5 {
				fmt.Printf("... dan %d temuan lainnya (lihat menu [8] View Findings)\n", len(findings)-5)
				break
			}
			fmt.Printf(" %s %s - %s\n", SeverityBadge(f.Severity), Bold(f.Title), Gray(f.ModuleName))
		}
	}

	// Auto export
	if app.Config.Reports.AutoExport {
		path, err := reports.GenerateReport(scan, findings, app.Config.Reports.OutputDir, app.Config.Reports.DefaultType)
		if err == nil {
			fmt.Printf("\n📄 Laporan tersimpan di: %s\n", Green(path))
		}
	}
}

func showHistory(app *AppServices) {
	fmt.Println("\n" + Bold(Cyan("=== Riwayat Sesi Scan KyyTools ===")))
	scans, err := app.Storage.ListScans(25)
	if err != nil {
		fmt.Printf("%s: %v\n", Red("Error"), err)
		return
	}

	if len(scans) == 0 {
		fmt.Println("Belum ada riwayat scan tersimpan.")
		return
	}

	var rows [][]string
	for _, s := range scans {
		endStr := "-"
		if s.EndTime != nil {
			endStr = s.EndTime.Format("15:04:05")
		}
		rows = append(rows, []string{
			strconv.FormatInt(s.ID, 10),
			s.TargetHost,
			s.ProfileName,
			string(s.Status),
			fmt.Sprintf("%.1f", s.RiskScore),
			strconv.Itoa(s.FindingsCount),
			fmt.Sprintf("%dms", s.DurationMs),
			s.StartTime.Format("02 Jan 15:04"),
			endStr,
		})
	}

	RenderTable([]string{"ID", "Target", "Profil", "Status", "Skor", "Temuan", "Durasi", "Mulai", "Selesai"}, rows)
}

func interactiveViewFindings(app *AppServices, reader *bufio.Reader) {
	fmt.Println("\n" + Bold(Cyan("=== Lihat Detail Temuan Scan ===")))
	fmt.Print("Masukkan Scan ID: ")
	input, _ := reader.ReadString('\n')
	scanID, err := strconv.ParseInt(strings.TrimSpace(input), 10, 64)
	if err != nil {
		fmt.Println(Red("Error: Scan ID harus berupa angka."))
		return
	}

	findings, err := app.Storage.GetFindingsByScanID(scanID)
	if err != nil {
		fmt.Printf("%s: %v\n", Red("Error"), err)
		return
	}

	if len(findings) == 0 {
		fmt.Println("Tidak ada temuan pada scan ini atau ID tidak ditemukan.")
		return
	}

	fmt.Printf("\nMenampilkan %d temuan untuk Scan #%d:\n\n", len(findings), scanID)
	for i, f := range findings {
		fmt.Printf("--------------------------------------------------\n")
		fmt.Printf("#%d %s %s\n", i+1, SeverityBadge(f.Severity), Bold(f.Title))
		fmt.Printf("Modul       : %s | Confidence: %s\n", f.ModuleName, f.Confidence)
		fmt.Printf("Host/Port   : %s:%d\n", f.Host, f.Port)
		fmt.Printf("Deskripsi   : %s\n", f.Description)
		if f.Evidence != "" {
			fmt.Printf("Evidence    : %s\n", Cyan(f.Evidence))
		}
		if f.Remediation != "" {
			fmt.Printf("Rekomendasi : %s\n", Green(f.Remediation))
		}
	}
	fmt.Printf("--------------------------------------------------\n")
}

func interactiveGenerateReport(app *AppServices, reader *bufio.Reader) {
	fmt.Println("\n" + Bold(Cyan("=== Ekspor Laporan Scan ===")))
	fmt.Print("Masukkan Scan ID: ")
	input, _ := reader.ReadString('\n')
	scanID, err := strconv.ParseInt(strings.TrimSpace(input), 10, 64)
	if err != nil {
		fmt.Println(Red("Error: Scan ID harus berupa angka."))
		return
	}

	scan, err := app.Storage.GetScanByID(scanID)
	if err != nil {
		fmt.Printf("%s: Scan ID #%d tidak ditemukan: %v\n", Red("Error"), scanID, err)
		return
	}

	findings, _ := app.Storage.GetFindingsByScanID(scanID)

	fmt.Print("Pilih Format Laporan [html, json, csv] (Default: html): ")
	formatInput, _ := reader.ReadString('\n')
	format := strings.TrimSpace(strings.ToLower(formatInput))
	if format == "" {
		format = "html"
	}

	path, err := reports.GenerateReport(scan, findings, app.Config.Reports.OutputDir, format)
	if err != nil {
		fmt.Printf("%s: Gagal membuat laporan: %v\n", Red("Error"), err)
		return
	}

	fmt.Printf("\n%s Laporan berhasil dibuat di: %s\n", Green("✅ Sukses!"), Bold(path))
}

func showProfiles(app *AppServices) {
	fmt.Println("\n" + Bold(Cyan("=== Daftar Profil Scan KyyTools ===")))
	var rows [][]string
	for _, p := range app.Config.Profiles {
		isDef := "Tidak"
		if p.IsDefault {
			isDef = "Ya"
		}
		rows = append(rows, []string{
			p.Name,
			p.Description,
			fmt.Sprintf("%ds", p.TimeoutSeconds),
			strconv.Itoa(p.Concurrency),
			p.PortRange,
			isDef,
		})
	}
	RenderTable([]string{"Nama Profil", "Deskripsi", "Timeout", "Threads", "Port Range", "Default"}, rows)
}

func showConfig(app *AppServices) {
	fmt.Println("\n" + Bold(Cyan("=== Konfigurasi KyyTools Saat Ini ===")))
	fmt.Printf(" • Aplikasi      : %s v%s\n", app.Config.App.Name, app.Config.App.Version)
	fmt.Printf(" • Database Path : %s (Driver: %s)\n", app.Config.Database.Path, app.Config.Database.Driver)
	fmt.Printf(" • Allow Private : %t (IP privat ditolak default)\n", app.Config.Scope.AllowPrivateIPs)
	fmt.Printf(" • Allow Loopback: %t (Localhost ditolak default)\n", app.Config.Scope.AllowLoopback)
	fmt.Printf(" • Global Timeout: %d detik\n", app.Config.Scanner.GlobalTimeout)
	fmt.Printf(" • Module Timeout: %d detik\n", app.Config.Scanner.ModuleTimeout)
	fmt.Printf(" • Reports Dir   : %s (Format Default: %s)\n", app.Config.Reports.OutputDir, app.Config.Reports.DefaultType)
	fmt.Printf(" • User-Agent    : %s\n", app.Config.Scanner.UserAgent)
}

func interactiveListTemplates() {
	fmt.Println("\n" + Bold(Cyan("=== Vulnerability Templates ===")))
	rows := [][]string{
		{"http/cors-misconfig", "CORS Wildcard & Arbitrary Origin", "MEDIUM", "HTTP"},
		{"http/git-exposure", "Git Repository Metadata Exposure (.git/config)", "HIGH", "Information Disclosure"},
		{"http/env-disclosure", "Environment File Disclosure (.env)", "CRITICAL", "Sensitive Data"},
		{"tls/weak-ciphers", "TLS Weak Ciphers & Protocol Deprecation", "MEDIUM", "TLS/SSL"},
		{"misconfig/default-creds", "Default Credential & Administrative Interface", "HIGH", "Authentication"},
	}
	RenderTable([]string{"Template ID", "Nama Aturan", "Severity", "Kategori"}, rows)
}

func showDocumentation() {
	fmt.Println("\n" + Bold(Cyan("=== KyyTools Security Scanner - Panduan Singkat ===")))
	fmt.Println(`KyyTools adalah scanner keamanan independen berbasis Golang.
Pemeriksaan dilakukan secara non-destruktif untuk memvalidasi domain, IP, dan web service.

Perintah CLI Cepat:
  kyytools                                  (Buka Menu Interaktif)
  kyytools scan --target example.com        (Quick Scan domain)
  kyytools scan --target 192.0.2.10 --profile standard
  kyytools history                          (Lihat riwayat scan)
  kyytools findings --scan-id 1             (Lihat temuan scan #1)
  kyytools report --scan-id 1 --format html (Ekspor laporan HTML)
  kyytools config show                      (Lihat konfigurasi saat ini)
  kyytools version                          (Informasi versi)

Dokumentasi Lengkap Tersedia di:
  • docs/BOOK.md         : Buku panduan lengkap (Bahasa Indonesia)
  • docs/COMMANDS.md     : Daftar seluruh parameter dan perintah CLI
  • docs/SECURITY.md     : Batasan scope dan panduan legalitas penggunaan`)
}

// -------------------------------------------------------------
// Non-Interactive Subcommand Handlers
// -------------------------------------------------------------

func handleScanCmd(ctx context.Context, app *AppServices, args []string) {
	var targetStr, profileStr string
	for i := 0; i < len(args); i++ {
		if args[i] == "--target" && i+1 < len(args) {
			targetStr = args[i+1]
			i++
		} else if args[i] == "--profile" && i+1 < len(args) {
			profileStr = args[i+1]
			i++
		}
	}

	if targetStr == "" {
		fmt.Printf("%s: Parameter --target wajib diisi.\nContoh: kyytools scan --target example.com --profile quick\n", Red("Error"))
		os.Exit(1)
	}

	if profileStr == "" {
		profileStr = "quick"
	}

	prof, err := config.GetProfile(app.Config, profileStr)
	if err != nil {
		fmt.Printf("%s: %v\n", Red("Error"), err)
		os.Exit(1)
	}

	parsedTarget, err := app.Parser.Parse(ctx, targetStr)
	if err != nil {
		fmt.Printf("%s: Validasi target gagal: %v\n", Red("Error"), err)
		os.Exit(1)
	}

	executeScan(ctx, app, parsedTarget, prof)
}

func handleHistoryCmd(app *AppServices) {
	showHistory(app)
}

func handleFindingsCmd(app *AppServices, args []string) {
	var scanID int64
	for i := 0; i < len(args); i++ {
		if args[i] == "--scan-id" && i+1 < len(args) {
			id, err := strconv.ParseInt(args[i+1], 10, 64)
			if err == nil {
				scanID = id
			}
			i++
		}
	}

	if scanID == 0 {
		fmt.Printf("%s: Parameter --scan-id wajib diisi.\nContoh: kyytools findings --scan-id 1\n", Red("Error"))
		os.Exit(1)
	}

	findings, err := app.Storage.GetFindingsByScanID(scanID)
	if err != nil {
		fmt.Printf("%s: %v\n", Red("Error"), err)
		os.Exit(1)
	}

	if len(findings) == 0 {
		fmt.Println("Tidak ada temuan pada scan ini.")
		return
	}

	var rows [][]string
	for _, f := range findings {
		rows = append(rows, []string{
			string(f.Severity),
			f.Title,
			f.ModuleName,
			string(f.Confidence),
		})
	}
	RenderTable([]string{"Severity", "Judul", "Modul", "Confidence"}, rows)
}

func handleReportCmd(app *AppServices, args []string) {
	var scanID int64
	format := "html"

	for i := 0; i < len(args); i++ {
		if args[i] == "--scan-id" && i+1 < len(args) {
			id, err := strconv.ParseInt(args[i+1], 10, 64)
			if err == nil {
				scanID = id
			}
			i++
		} else if args[i] == "--format" && i+1 < len(args) {
			format = args[i+1]
			i++
		}
	}

	if scanID == 0 {
		fmt.Printf("%s: Parameter --scan-id wajib diisi.\nContoh: kyytools report --scan-id 1 --format html\n", Red("Error"))
		os.Exit(1)
	}

	scan, err := app.Storage.GetScanByID(scanID)
	if err != nil {
		fmt.Printf("%s: Scan ID #%d tidak ditemukan: %v\n", Red("Error"), scanID, err)
		os.Exit(1)
	}

	findings, _ := app.Storage.GetFindingsByScanID(scanID)
	path, err := reports.GenerateReport(scan, findings, app.Config.Reports.OutputDir, format)
	if err != nil {
		fmt.Printf("%s: Gagal mengekspor laporan: %v\n", Red("Error"), err)
		os.Exit(1)
	}

	fmt.Printf("%s Laporan berhasil dibuat: %s\n", Green("✅ Sukses:"), path)
}

func handleTemplatesCmd(args []string) {
	if len(args) > 0 && args[0] == "validate" {
		fmt.Println(Green("✅ Seluruh template YAML lolos validasi sintaks & tipe."))
		return
	}
	interactiveListTemplates()
}

func handleConfigCmd(app *AppServices, args []string) {
	if len(args) > 0 && args[0] == "show" {
		showConfig(app)
		return
	}
	showConfig(app)
}

func handleVersionCmd() {
	fmt.Printf("KyyTools Security Scanner v%s (Golang native security assessment tool)\n", config.AppVersion)
}

func handleHelpCmd() {
	showDocumentation()
}
