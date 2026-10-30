package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kyybogor/Kyytools/internal/models"
	"github.com/kyybogor/Kyytools/internal/risk"
	"github.com/kyybogor/Kyytools/internal/safety"
	"github.com/kyybogor/Kyytools/internal/storage"
	"gopkg.in/yaml.v3"
)

// ProgressCallback provides real-time status updates during a scan.
type ProgressCallback func(moduleName string, current, total int, message string)

// Engine orchestrates scan modules and stores results.
type Engine struct {
	config    *models.AppConfig
	storage   *storage.Storage
	validator *safety.ScopeValidator
	modules   map[string]Module
}

// Module represents an executable scanning check.
type Module interface {
	Name() string
	Description() string
	Run(ctx context.Context, target *models.Target, profile *models.ScanProfile, val *safety.ScopeValidator) ([]models.Finding, error)
}

// Top 100 ports for extended network scanning
var top100Ports = []int{
	20, 21, 22, 23, 25, 53, 69, 80, 81, 88, 110, 111, 119, 123, 135, 137, 138, 139, 143, 161,
	162, 179, 389, 443, 445, 465, 500, 514, 515, 520, 521, 546, 547, 587, 636, 873, 902, 990,
	993, 995, 1025, 1080, 1194, 1433, 1434, 1521, 1723, 1812, 1813, 2049, 2082, 2083, 2086, 2087,
	2181, 2222, 2375, 2376, 3000, 3128, 3306, 3389, 3690, 4000, 4443, 5000, 5432, 5672, 5900, 5985,
	5986, 6379, 6667, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 9418, 9999,
	11211, 27017, 27018, 28017, 50000, 50070,
}

// NewEngine creates an initialized scanner engine with standard & deep modules registered.
func NewEngine(cfg *models.AppConfig, store *storage.Storage, val *safety.ScopeValidator) *Engine {
	e := &Engine{
		config:    cfg,
		storage:   store,
		validator: val,
		modules:   make(map[string]Module),
	}

	// Register core & deep inspection modules
	e.RegisterModule(&TargetInfoModule{})
	e.RegisterModule(&DNSResolverModule{})
	e.RegisterModule(&WebHeadersModule{})
	e.RegisterModule(&HTTPMethodsModule{})
	e.RegisterModule(&CORSModule{})
	e.RegisterModule(&SensitiveFilesModule{})
	e.RegisterModule(&TLSCheckModule{})
	e.RegisterModule(&VulnTemplatesModule{})
	e.RegisterModule(&ServiceDetectionModule{})
	e.RegisterModule(&PortScanModule{name: "port_scan_top", defaultPorts: []int{80, 443, 8080, 8443}})
	e.RegisterModule(&PortScanModule{name: "port_scan_standard", defaultPorts: []int{21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 6379, 8000, 8080, 8443, 8888}})
	e.RegisterModule(&PortScanModule{name: "port_scan_extended", defaultPorts: top100Ports})

	return e
}

// RegisterModule adds a module to the engine.
func (e *Engine) RegisterModule(m Module) {
	e.modules[m.Name()] = m
}

// RunScan executes the selected scan profile against the target.
func (e *Engine) RunScan(ctx context.Context, target *models.Target, profile *models.ScanProfile, onProgress ProgressCallback) (*models.Scan, []models.Finding, error) {
	targetID, err := e.storage.SaveTarget(target)
	if err != nil {
		return nil, nil, fmt.Errorf("gagal menyimpan target ke database: %w", err)
	}
	target.ID = targetID

	scan := &models.Scan{
		TargetID:    targetID,
		TargetHost:  target.Host,
		TargetType:  string(target.Type),
		ProfileName: profile.Name,
		Status:      models.ScanStatusRunning,
		StartTime:   time.Now(),
		CreatedAt:   time.Now(),
	}

	scanID, err := e.storage.CreateScan(scan)
	if err != nil {
		return nil, nil, fmt.Errorf("gagal membuat sesi scan di database: %w", err)
	}
	scan.ID = scanID

	var activeModules []Module
	for _, modName := range profile.Modules {
		if mod, exists := e.modules[modName]; exists {
			activeModules = append(activeModules, mod)
		}
	}

	totalModules := len(activeModules)
	var allFindings []models.Finding
	startTime := time.Now()

	for idx, mod := range activeModules {
		select {
		case <-ctx.Done():
			duration := time.Since(startTime).Milliseconds()
			_ = e.storage.UpdateScanStatus(scan.ID, models.ScanStatusCancelled, duration, 0, "Scan dibatalkan oleh pengguna")
			scan.Status = models.ScanStatusCancelled
			return scan, allFindings, ctx.Err()
		default:
		}

		if onProgress != nil {
			onProgress(mod.Name(), idx+1, totalModules, fmt.Sprintf("Audit %s...", mod.Description()))
		}

		modTimeout := time.Duration(e.config.Scanner.ModuleTimeout) * time.Second
		if modTimeout <= 0 {
			modTimeout = 40 * time.Second
		}

		modCtx, cancel := context.WithTimeout(ctx, modTimeout)
		modStart := time.Now()

		findings, err := mod.Run(modCtx, target, profile, e.validator)
		cancel()

		modDuration := time.Since(modStart).Milliseconds()
		modStatus := models.ScanStatusCompleted
		errMsg := ""
		if err != nil && err != context.Canceled {
			modStatus = models.ScanStatusFailed
			errMsg = err.Error()
		}

		_, _ = e.storage.SaveScanModule(&models.ScanModule{
			ScanID:       scan.ID,
			ModuleName:   mod.Name(),
			Status:       modStatus,
			StartTime:    modStart,
			DurationMs:   modDuration,
			ErrorMessage: errMsg,
		})

		for i := range findings {
			findings[i].ScanID = scan.ID
			findings[i].Host = target.Host
			findings[i].CreatedAt = time.Now()
			findingID, err := e.storage.SaveFinding(&findings[i])
			if err == nil {
				findings[i].ID = findingID
			}
			allFindings = append(allFindings, findings[i])
		}
	}

	crit, high, med, low, info := 0, 0, 0, 0, 0
	for _, f := range allFindings {
		switch f.Severity {
		case models.SeverityCritical:
			crit++
		case models.SeverityHigh:
			high++
		case models.SeverityMedium:
			med++
		case models.SeverityLow:
			low++
		case models.SeverityInfo:
			info++
		}
	}

	riskScore, _ := risk.CalculateScore(allFindings)
	totalDuration := time.Since(startTime).Milliseconds()

	scan.Status = models.ScanStatusCompleted
	scan.DurationMs = totalDuration
	scan.CriticalCount = crit
	scan.HighCount = high
	scan.MediumCount = med
	scan.LowCount = low
	scan.InfoCount = info
	scan.FindingsCount = len(allFindings)
	scan.RiskScore = riskScore

	_ = e.storage.UpdateScanCounts(scan.ID, crit, high, med, low, info, len(allFindings))
	_ = e.storage.UpdateScanStatus(scan.ID, models.ScanStatusCompleted, totalDuration, riskScore, "")

	return scan, allFindings, nil
}

// -------------------------------------------------------------
// 1. TargetInfoModule
// -------------------------------------------------------------

type TargetInfoModule struct{}

func (m *TargetInfoModule) Name() string        { return "target_info" }
func (m *TargetInfoModule) Description() string { return "Identifikasi Target & Batas Scope" }
func (m *TargetInfoModule) Run(ctx context.Context, target *models.Target, profile *models.ScanProfile, val *safety.ScopeValidator) ([]models.Finding, error) {
	evidence := fmt.Sprintf("Target: %s\nTipe: %s\nHost: %s\nPort: %d\nResolusi IP: %s\nURL Dasar: %s",
		target.RawInput, target.Type, target.Host, target.Port, strings.Join(target.ResolvedIPs, ", "), target.CanonicalURL)

	return []models.Finding{
		{
			ModuleName:         m.Name(),
			Title:              fmt.Sprintf("Target Teridentifikasi: %s (%s)", target.Host, target.Type),
			Description:        "Target telah divalidasi, lolos pemeriksaan anti-SSRF/loopback, dan berada dalam scope yang diizinkan.",
			Severity:           models.SeverityInfo,
			Confidence:         models.ConfidenceCertain,
			Category:           "Information",
			Evidence:           evidence,
			VerificationStatus: "VERIFIED",
		},
	}, nil
}

// -------------------------------------------------------------
// 2. DNSResolverModule
// -------------------------------------------------------------

type DNSResolverModule struct{}

func (m *DNSResolverModule) Name() string { return "dns_resolver" }
func (m *DNSResolverModule) Description() string {
	return "Record DNS, Email Security (SPF/DMARC) & CAA"
}
func (m *DNSResolverModule) Run(ctx context.Context, target *models.Target, profile *models.ScanProfile, val *safety.ScopeValidator) ([]models.Finding, error) {
	var findings []models.Finding

	if target.Type != models.TargetTypeDomain && target.Type != models.TargetTypeURL {
		return findings, nil
	}

	resolver := net.DefaultResolver

	// Check MX records
	mxRecords, _ := resolver.LookupMX(ctx, target.Host)
	hasMX := len(mxRecords) > 0

	// Check TXT records for SPF
	txtRecords, _ := resolver.LookupTXT(ctx, target.Host)
	hasSPF := false
	for _, txt := range txtRecords {
		if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			hasSPF = true
			if strings.Contains(txt, "+all") || strings.Contains(txt, "?all") {
				findings = append(findings, models.Finding{
					ModuleName:         m.Name(),
					Title:              "Record SPF Menggunakan Aturan Permisif (+all / ?all)",
					Description:        "Kebijakan SPF tidak menolak IP di luar daftar (+all atau ?all), memungkinkan penyerang mengirim email palsu atas nama domain Anda.",
					Severity:           models.SeverityMedium,
					Confidence:         models.ConfidenceCertain,
					Category:           "Email Security",
					Evidence:           fmt.Sprintf("SPF: %s", txt),
					Remediation:        "Ubah konfigurasi SPF di akhir baris menjadi '-all' (Hard Fail) atau minimal '~all' (Soft Fail).",
					VerificationStatus: "VERIFIED",
				})
			}
			break
		}
	}

	// Check DMARC
	dmarcRecords, _ := resolver.LookupTXT(ctx, "_dmarc."+target.Host)
	hasDMARC := false
	for _, txt := range dmarcRecords {
		if strings.HasPrefix(strings.ToLower(txt), "v=dmarc1") {
			hasDMARC = true
			if strings.Contains(strings.ToLower(txt), "p=none") {
				findings = append(findings, models.Finding{
					ModuleName:         m.Name(),
					Title:              "Kebijakan DMARC Mode Pengawasan Saja (p=none)",
					Description:        "DMARC dikonfigurasi dengan p=none, artinya email spoofing yang gagal verifikasi tidak ditolak oleh server penerima.",
					Severity:           models.SeverityLow,
					Confidence:         models.ConfidenceCertain,
					Category:           "Email Security",
					Evidence:           fmt.Sprintf("DMARC: %s", txt),
					Remediation:        "Tingkatkan kebijakan DMARC secara bertahap ke 'p=quarantine' atau 'p=reject'.",
					VerificationStatus: "VERIFIED",
				})
			}
			break
		}
	}

	if hasMX && !hasSPF {
		findings = append(findings, models.Finding{
			ModuleName:         m.Name(),
			Title:              "Record SPF (Sender Policy Framework) Tidak Ditemukan",
			Description:        "Domain memiliki MX record namun tidak memiliki record TXT SPF untuk memvalidasi server pengirim email yang sah.",
			Severity:           models.SeverityMedium,
			Confidence:         models.ConfidenceFirm,
			Category:           "Email Security",
			Evidence:           fmt.Sprintf("Lookup TXT pada %s tidak mengembalikan string 'v=spf1'", target.Host),
			Remediation:        "Tambahkan record DNS TXT SPF pada domain (contoh: 'v=spf1 mx -all') untuk mencegah email spoofing.",
			VerificationStatus: "VERIFIED",
		})
	}

	if hasMX && !hasDMARC {
		findings = append(findings, models.Finding{
			ModuleName:         m.Name(),
			Title:              "Record DMARC Tidak Terkonfigurasi",
			Description:        "Domain tidak memiliki record DMARC (_dmarc.<domain>) untuk mengatur kebijakan penolakan email palsu.",
			Severity:           models.SeverityMedium,
			Confidence:         models.ConfidenceFirm,
			Category:           "Email Security",
			Evidence:           fmt.Sprintf("Lookup TXT pada _dmarc.%s tidak mengembalikan string 'v=DMARC1'", target.Host),
			Remediation:        "Konfigurasikan record TXT pada '_dmarc." + target.Host + "' dengan kebijakan minimal p=quarantine atau p=reject.",
			VerificationStatus: "VERIFIED",
		})
	}

	// Check CAA record
	caaRecords, _ := resolver.LookupTXT(ctx, target.Host)
	hasCAA := false
	for _, txt := range caaRecords {
		if strings.Contains(strings.ToLower(txt), "issue") {
			hasCAA = true
			break
		}
	}
	if !hasCAA {
		findings = append(findings, models.Finding{
			ModuleName:         m.Name(),
			Title:              "Record DNS CAA (Certificate Authority Authorization) Tidak Ditemukan",
			Description:        "Domain tidak membatasi CA mana yang berhak menerbitkan sertifikat SSL untuk domain ini.",
			Severity:           models.SeverityInfo,
			Confidence:         models.ConfidenceFirm,
			Category:           "DNS Security",
			Evidence:           "Tidak ada record CAA terdeteksi pada DNS domain.",
			Remediation:        "Tambahkan record DNS CAA untuk menentukan otoritas sertifikat resmi (contoh: letsencrypt.org, digicert.com).",
			VerificationStatus: "VERIFIED",
		})
	}

	return findings, nil
}

// -------------------------------------------------------------
// 3. WebHeadersModule (Expanded Deep Headers Inspection)
// -------------------------------------------------------------

type WebHeadersModule struct{}

func (m *WebHeadersModule) Name() string { return "web_headers" }
func (m *WebHeadersModule) Description() string {
	return "Audit Keamanan Header HTTP, Cookie & Kebocoran Banner"
}
func (m *WebHeadersModule) Run(ctx context.Context, target *models.Target, profile *models.ScanProfile, val *safety.ScopeValidator) ([]models.Finding, error) {
	var findings []models.Finding

	client := val.CreateSafeHTTPClient(10*time.Second, false, 3)

	reqURL := target.CanonicalURL
	if !strings.HasPrefix(reqURL, "http://") && !strings.HasPrefix(reqURL, "https://") {
		reqURL = "http://" + target.Host
	}

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "KyyTools-Security-Scanner/1.0.0")

	resp, err := client.Do(req)
	if err != nil {
		if strings.HasPrefix(reqURL, "http://") {
			reqURL = "https://" + target.Host
			req2, err2 := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
			if err2 == nil {
				req2.Header.Set("User-Agent", "KyyTools-Security-Scanner/1.0.0")
				resp, err = client.Do(req2)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("koneksi HTTP ke %s gagal: %w", reqURL, err)
		}
	}
	defer resp.Body.Close()

	headers := resp.Header

	// 1. Server Banner Exposure
	if server := headers.Get("Server"); server != "" {
		if strings.Contains(server, "/") {
			findings = append(findings, models.Finding{
				ModuleName:         m.Name(),
				Title:              "Pengungkapan Versi Web Server (Server Banner)",
				Description:        "Header HTTP 'Server' mengungkap versi software web server secara spesifik yang memudahkan pencarian exploit bertarget.",
				Severity:           models.SeverityLow,
				Confidence:         models.ConfidenceCertain,
				Category:           "Information Disclosure",
				Evidence:           fmt.Sprintf("Server: %s", server),
				Remediation:        "Sembunyikan atau samarkan versi server (contoh: ServerTokens Prod pada Apache atau server_tokens off pada Nginx).",
				VerificationStatus: "VERIFIED",
			})
		}
	}

	// 2. X-Powered-By
	if poweredBy := headers.Get("X-Powered-By"); poweredBy != "" {
		findings = append(findings, models.Finding{
			ModuleName:         m.Name(),
			Title:              "Pengungkapan Framework Backend (X-Powered-By)",
			Description:        "Header 'X-Powered-By' membocorkan teknologi backend dan runtime yang digunakan.",
			Severity:           models.SeverityLow,
			Confidence:         models.ConfidenceCertain,
			Category:           "Information Disclosure",
			Evidence:           fmt.Sprintf("X-Powered-By: %s", poweredBy),
			Remediation:        "Nonaktifkan header X-Powered-By pada konfigurasi aplikasi atau runtime (misal: expose_php = Off pada php.ini).",
			VerificationStatus: "VERIFIED",
		})
	}

	// 3. HSTS
	if strings.HasPrefix(reqURL, "https://") && headers.Get("Strict-Transport-Security") == "" {
		findings = append(findings, models.Finding{
			ModuleName:         m.Name(),
			Title:              "Header HSTS (Strict-Transport-Security) Tidak Ditemukan",
			Description:        "Aplikasi tidak mengimplementasikan HSTS untuk memaksa peramban menggunakan koneksi terenkripsi HTTPS secara eksklusif.",
			Severity:           models.SeverityMedium,
			Confidence:         models.ConfidenceCertain,
			Category:           "Missing Security Header",
			Evidence:           "Header 'Strict-Transport-Security' tidak ada dalam respons HTTP.",
			Remediation:        "Tambahkan header 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
			VerificationStatus: "VERIFIED",
		})
	}

	// 4. CSP
	if headers.Get("Content-Security-Policy") == "" {
		findings = append(findings, models.Finding{
			ModuleName:         m.Name(),
			Title:              "Header Content-Security-Policy (CSP) Hilang",
			Description:        "Tidak ditemukan kebijakan Content Security Policy untuk memitigasi serangan Cross-Site Scripting (XSS) dan injeksi data.",
			Severity:           models.SeverityMedium,
			Confidence:         models.ConfidenceCertain,
			Category:           "Missing Security Header",
			Evidence:           "Header 'Content-Security-Policy' tidak ada dalam respons HTTP.",
			Remediation:        "Definisikan Content-Security-Policy yang membatasi sumber eksekusi skrip, stylesheet, dan frame.",
			VerificationStatus: "VERIFIED",
		})
	}

	// 5. X-Frame-Options
	if headers.Get("X-Frame-Options") == "" && !strings.Contains(headers.Get("Content-Security-Policy"), "frame-ancestors") {
		findings = append(findings, models.Finding{
			ModuleName:         m.Name(),
			Title:              "Proteksi Clickjacking (X-Frame-Options) Tidak Ada",
			Description:        "Halaman web rentan dimuat di dalam iframe situs lain tanpa pembatasan, berpotensi memfasilitasi serangan clickjacking.",
			Severity:           models.SeverityMedium,
			Confidence:         models.ConfidenceCertain,
			Category:           "Clickjacking",
			Evidence:           "Header 'X-Frame-Options' maupun CSP 'frame-ancestors' tidak terdeteksi.",
			Remediation:        "Tambahkan 'X-Frame-Options: SAMEORIGIN' atau 'X-Frame-Options: DENY'.",
			VerificationStatus: "VERIFIED",
		})
	}

	// 6. X-Content-Type-Options
	if headers.Get("X-Content-Type-Options") == "" {
		findings = append(findings, models.Finding{
			ModuleName:         m.Name(),
			Title:              "Header X-Content-Type-Options: nosniff Tidak Ditemukan",
			Description:        "MIMESniffing tidak dinonaktifkan, sehingga peramban dapat menafsirkan file di luar MIME-type aslinya.",
			Severity:           models.SeverityLow,
			Confidence:         models.ConfidenceCertain,
			Category:           "Missing Security Header",
			Evidence:           "Header 'X-Content-Type-Options' tidak ada dalam respons HTTP.",
			Remediation:        "Tambahkan header 'X-Content-Type-Options: nosniff'.",
			VerificationStatus: "VERIFIED",
		})
	}

	// 7. Referrer-Policy
	if refPol := headers.Get("Referrer-Policy"); refPol == "" || refPol == "unsafe-url" {
		findings = append(findings, models.Finding{
			ModuleName:         m.Name(),
			Title:              "Header Referrer-Policy Tidak Dikonfigurasi dengan Aman",
			Description:        "Kebijakan referrer tidak dibatasi, berpotensi membocorkan parameter URL sensitif ke situs pihak ketiga.",
			Severity:           models.SeverityLow,
			Confidence:         models.ConfidenceCertain,
			Category:           "Information Disclosure",
			Evidence:           fmt.Sprintf("Referrer-Policy: %s", refPol),
			Remediation:        "Tambahkan header 'Referrer-Policy: strict-origin-when-cross-origin' atau 'no-referrer'.",
			VerificationStatus: "VERIFIED",
		})
	}

	// 8. Permissions-Policy
	if headers.Get("Permissions-Policy") == "" {
		findings = append(findings, models.Finding{
			ModuleName:         m.Name(),
			Title:              "Header Permissions-Policy Tidak Dikonfigurasi",
			Description:        "Fitur peramban sensitif (kamera, mikrofon, geolokasi) tidak dibatasi secara eksplisit oleh server.",
			Severity:           models.SeverityLow,
			Confidence:         models.ConfidenceCertain,
			Category:           "Missing Security Header",
			Evidence:           "Header 'Permissions-Policy' tidak ada.",
			Remediation:        "Tambahkan header 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
			VerificationStatus: "VERIFIED",
		})
	}

	// 9. Cookie Security Flags & SameSite
	cookies := resp.Cookies()
	for _, c := range cookies {
		if !c.HttpOnly {
			findings = append(findings, models.Finding{
				ModuleName:         m.Name(),
				Title:              fmt.Sprintf("Cookie '%s' Tanpa Flag HttpOnly", c.Name),
				Description:        "Cookie sensitif dapat diakses melalui skrip sisi klien JavaScript (document.cookie), rentan pencurian saat terjadi XSS.",
				Severity:           models.SeverityLow,
				Confidence:         models.ConfidenceCertain,
				Category:           "Cookie Security",
				Evidence:           fmt.Sprintf("Set-Cookie: %s (HttpOnly=false)", c.Name),
				Remediation:        "Tambahkan flag 'HttpOnly' pada header Set-Cookie.",
				VerificationStatus: "VERIFIED",
			})
		}
		if !c.Secure && strings.HasPrefix(reqURL, "https://") {
			findings = append(findings, models.Finding{
				ModuleName:         m.Name(),
				Title:              fmt.Sprintf("Cookie '%s' Tanpa Flag Secure", c.Name),
				Description:        "Cookie dapat dikirimkan melalui saluran komunikasi tidak terenkripsi (HTTP biasa).",
				Severity:           models.SeverityLow,
				Confidence:         models.ConfidenceCertain,
				Category:           "Cookie Security",
				Evidence:           fmt.Sprintf("Set-Cookie: %s (Secure=false)", c.Name),
				Remediation:        "Tambahkan flag 'Secure' pada header Set-Cookie saat beroperasi di HTTPS.",
				VerificationStatus: "VERIFIED",
			})
		}
		if c.SameSite == http.SameSiteDefaultMode {
			findings = append(findings, models.Finding{
				ModuleName:         m.Name(),
				Title:              fmt.Sprintf("Cookie '%s' Tanpa Atribut SameSite Eksplisit", c.Name),
				Description:        "Atribut SameSite tidak didefinisikan (Strict/Lax), berpotensi meningkatkan risiko serangan Cross-Site Request Forgery (CSRF).",
				Severity:           models.SeverityLow,
				Confidence:         models.ConfidenceCertain,
				Category:           "Cookie Security",
				Evidence:           fmt.Sprintf("Cookie '%s' tidak memiliki atribut SameSite", c.Name),
				Remediation:        "Atur atribut SameSite=Lax atau SameSite=Strict pada Set-Cookie.",
				VerificationStatus: "VERIFIED",
			})
		}
	}

	return findings, nil
}

// -------------------------------------------------------------
// 4. HTTPMethodsModule (Dangerous HTTP Methods: TRACE/PUT/DELETE)
// -------------------------------------------------------------

type HTTPMethodsModule struct{}

func (m *HTTPMethodsModule) Name() string { return "http_methods" }
func (m *HTTPMethodsModule) Description() string {
	return "Audit Metode HTTP Berbahaya (OPTIONS, TRACE, PUT, DELETE)"
}
func (m *HTTPMethodsModule) Run(ctx context.Context, target *models.Target, profile *models.ScanProfile, val *safety.ScopeValidator) ([]models.Finding, error) {
	var findings []models.Finding
	client := val.CreateSafeHTTPClient(8*time.Second, false, 2)

	baseURL := target.CanonicalURL

	// 1. Check OPTIONS method
	optReq, err := http.NewRequestWithContext(ctx, "OPTIONS", baseURL, nil)
	if err == nil {
		optReq.Header.Set("User-Agent", "KyyTools-Security-Scanner/1.0.0")
		optResp, err := client.Do(optReq)
		if err == nil {
			defer optResp.Body.Close()
			allow := optResp.Header.Get("Allow")
			if allow != "" {
				findings = append(findings, models.Finding{
					ModuleName:         m.Name(),
					Title:              fmt.Sprintf("Daftar Metode HTTP Didukung: %s", allow),
					Description:        "Server mengembalikan daftar metode HTTP yang diizinkan melalui header 'Allow'.",
					Severity:           models.SeverityInfo,
					Confidence:         models.ConfidenceCertain,
					Category:           "HTTP Methods",
					Evidence:           fmt.Sprintf("Allow: %s", allow),
					VerificationStatus: "VERIFIED",
				})
			}
		}
	}

	// 2. Test TRACE method (Cross-Site Tracing / XST)
	traceReq, err := http.NewRequestWithContext(ctx, "TRACE", baseURL, nil)
	if err == nil {
		traceReq.Header.Set("User-Agent", "KyyTools-Security-Scanner/1.0.0")
		traceReq.Header.Set("X-KyyTools-Audit", "XST-Verification-Test")
		traceResp, err := client.Do(traceReq)
		if err == nil {
			defer traceResp.Body.Close()
			bodyBytes, _ := io.ReadAll(io.LimitReader(traceResp.Body, 4096))
			if traceResp.StatusCode == http.StatusOK && strings.Contains(string(bodyBytes), "XST-Verification-Test") {
				findings = append(findings, models.Finding{
					ModuleName:         m.Name(),
					Title:              "Metode HTTP TRACE Aktif (Rentan Cross-Site Tracing / XST)",
					Description:        "Server merespon permintaan TRACE dan merefleksikan kembali header request, memungkinkan penyerang mencuri cookie HttpOnly via skrip berbahaya.",
					Severity:           models.SeverityHigh,
					Confidence:         models.ConfidenceCertain,
					Category:           "HTTP Methods",
					Evidence:           fmt.Sprintf("HTTP 200 OK pada metode TRACE. Header X-KyyTools-Audit dipantulkan di body."),
					Remediation:        "Nonaktifkan metode TRACE pada web server (contoh: TraceEnable off pada Apache).",
					VerificationStatus: "VERIFIED",
				})
			}
		}
	}

	// 3. Test Unauthenticated PUT method
	testPutURL := fmt.Sprintf("%s/kyytools_test_%d.txt", strings.TrimRight(baseURL, "/"), time.Now().UnixNano())
	putReq, err := http.NewRequestWithContext(ctx, "PUT", testPutURL, strings.NewReader("audit-test"))
	if err == nil {
		putReq.Header.Set("User-Agent", "KyyTools-Security-Scanner/1.0.0")
		putResp, err := client.Do(putReq)
		if err == nil {
			defer putResp.Body.Close()
			if putResp.StatusCode == http.StatusOK || putResp.StatusCode == http.StatusCreated || putResp.StatusCode == http.StatusNoContent {
				findings = append(findings, models.Finding{
					ModuleName:         m.Name(),
					Title:              "Metode HTTP PUT Tidak Terproteksi (Upload Berkas Bebas)",
					Description:        "Server menerima permintaan HTTP PUT tanpa autentikasi, membuka celah pengunggahan berkas sembarang oleh pihak ketiga.",
					Severity:           models.SeverityHigh,
					Confidence:         models.ConfidenceCertain,
					Category:           "HTTP Methods",
					Evidence:           fmt.Sprintf("HTTP %d diterima saat mencoba PUT ke %s", putResp.StatusCode, testPutURL),
					Remediation:        "Nonaktifkan metode HTTP PUT publik atau batasi hak akses hanya bagi pengguna terautentikasi.",
					VerificationStatus: "VERIFIED",
				})
			}
		}
	}

	return findings, nil
}

// -------------------------------------------------------------
// 5. CORSModule (Cross-Origin Resource Sharing Exploitability)
// -------------------------------------------------------------

type CORSModule struct{}

func (m *CORSModule) Name() string { return "cors_check" }
func (m *CORSModule) Description() string {
	return "Evaluasi Miskonfigurasi CORS (Origin Reflection & Credentials)"
}
func (m *CORSModule) Run(ctx context.Context, target *models.Target, profile *models.ScanProfile, val *safety.ScopeValidator) ([]models.Finding, error) {
	var findings []models.Finding
	client := val.CreateSafeHTTPClient(8*time.Second, false, 2)

	testOrigin := "https://kyytools-security-audit.test"
	req, err := http.NewRequestWithContext(ctx, "GET", target.CanonicalURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Origin", testOrigin)
	req.Header.Set("User-Agent", "KyyTools-Security-Scanner/1.0.0")

	resp, err := client.Do(req)
	if err != nil {
		return findings, nil
	}
	defer resp.Body.Close()

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCreds := resp.Header.Get("Access-Control-Allow-Credentials")

	// Critical/High: Arbitrary origin reflected with credentials = true
	if allowOrigin == testOrigin && strings.ToLower(allowCreds) == "true" {
		findings = append(findings, models.Finding{
			ModuleName:         m.Name(),
			Title:              "Miskonfigurasi CORS: Kepercayaan Origin Sembarang dengan Kredensial",
			Description:        "Server merefleksikan nilai header 'Origin' apa pun dan mengizinkan 'Access-Control-Allow-Credentials: true'. Penyerang dapat membuat situs jahat untuk mencuri data sesi otentikasi korban.",
			Severity:           models.SeverityHigh,
			Confidence:         models.ConfidenceCertain,
			Category:           "CORS",
			Evidence:           fmt.Sprintf("Origin dikirim: %s\nAccess-Control-Allow-Origin: %s\nAccess-Control-Allow-Credentials: %s", testOrigin, allowOrigin, allowCreds),
			Remediation:        "Terapkan whitelist origin yang ketat dan jangan pernah merefleksikan header Origin secara otomatis saat credentials diaktifkan.",
			VerificationStatus: "VERIFIED",
		})
	} else if allowOrigin == "*" {
		findings = append(findings, models.Finding{
			ModuleName:         m.Name(),
			Title:              "Kebijakan CORS Terbuka Penuh (Wildcard Origin '*')",
			Description:        "Header 'Access-Control-Allow-Origin' disetel ke wildcard (*), memungkinkan domain mana pun membaca respon API publik ini.",
			Severity:           models.SeverityLow,
			Confidence:         models.ConfidenceCertain,
			Category:           "CORS",
			Evidence:           "Access-Control-Allow-Origin: *",
			Remediation:        "Jika API memuat data pribadi atau transaksi, batasi Access-Control-Allow-Origin hanya ke domain aplikasi resmi.",
			VerificationStatus: "VERIFIED",
		})
	}

	return findings, nil
}

// -------------------------------------------------------------
// 6. SensitiveFilesModule (Deep Dotfiles, Backups & Secrets Probe)
// -------------------------------------------------------------

type SensitiveFilesModule struct{}

func (m *SensitiveFilesModule) Name() string { return "sensitive_files" }
func (m *SensitiveFilesModule) Description() string {
	return "Pendeteksi File Sensitif, Backup, Git Repository & Env"
}
func (m *SensitiveFilesModule) Run(ctx context.Context, target *models.Target, profile *models.ScanProfile, val *safety.ScopeValidator) ([]models.Finding, error) {
	var findings []models.Finding
	client := val.CreateSafeHTTPClient(6*time.Second, false, 2)

	baseURL := strings.TrimRight(target.CanonicalURL, "/")

	probes := []struct {
		path        string
		title       string
		description string
		severity    models.Severity
		category    string
		matchSign   string
		remediation string
	}{
		{
			path:        "/.env",
			title:       "Paparan File Konfigurasi Lingkungan (.env)",
			description: "File .env sensitif dapat diakses publik. File ini sering kali memuat password database, application key, dan token API rahasia.",
			severity:    models.SeverityCritical,
			category:    "Sensitive Data Exposure",
			matchSign:   "APP_KEY=",
			remediation: "Pindahkan file .env ke luar document root web server atau blokir akses file dotfiles pada konfigurasi Nginx/Apache.",
		},
		{
			path:        "/.git/HEAD",
			title:       "Paparan Repositori Git Source Code (/.git/HEAD)",
			description: "Direktori kontrol versi .git terbuka untuk umum, memungkinkan pihak luar merekonstruksi seluruh source code aplikasi.",
			severity:    models.SeverityHigh,
			category:    "Information Disclosure",
			matchSign:   "ref: refs/",
			remediation: "Tutup akses ke direktori .git pada konfigurasi web server (misal: location ~ /\\.git { deny all; }).",
		},
		{
			path:        "/.git/config",
			title:       "Paparan Konfigurasi Repositori Git (/.git/config)",
			description: "File konfigurasi internal Git dapat diunduh, membocorkan URL remote repository dan struktur branch.",
			severity:    models.SeverityHigh,
			category:    "Information Disclosure",
			matchSign:   "[core]",
			remediation: "Blokir seluruh akses ke folder tersembunyi berawalan titik pada web server.",
		},
		{
			path:        "/robots.txt",
			title:       "File robots.txt Mengungkap Jalur Direktori Internal",
			description: "File robots.txt terdeteksi dan memuat aturan pembatasan indexing yang mengungkap struktur path direktori situs.",
			severity:    models.SeverityInfo,
			category:    "Information Disclosure",
			matchSign:   "Disallow:",
			remediation: "Pastikan path sensitif (admin, backup, private) dilindungi oleh mekanisme autentikasi dan tidak hanya bergantung pada robots.txt.",
		},
		{
			path:        "/.DS_Store",
			title:       "Paparan File Metadata Finder macOS (.DS_Store)",
			description: "File .DS_Store membocorkan daftar nama berkas dan struktur folder internal direktori web server.",
			severity:    models.SeverityLow,
			category:    "Information Disclosure",
			matchSign:   "Bud1",
			remediation: "Hapus file .DS_Store dari server produksi dan cegah unggahan file tersebut via script deploy.",
		},
		{
			path:        "/phpinfo.php",
			title:       "Paparan Halaman Diagnostik Sistem phpinfo()",
			description: "File diagnostik phpinfo terbuka untuk publik, membocorkan versi PHP, path direktori server, variabel environment, dan modul terpasang.",
			severity:    models.SeverityMedium,
			category:    "Information Disclosure",
			matchSign:   "Configuration File",
			remediation: "Hapus file phpinfo.php segera dari server publik.",
		},
		{
			path:        "/actuator/health",
			title:       "Paparan Endpoint Spring Boot Actuator",
			description: "Endpoint manajemen Spring Boot Actuator terbuka publik tanpa autentikasi.",
			severity:    models.SeverityMedium,
			category:    "Information Disclosure",
			matchSign:   "\"status\"",
			remediation: "Amankan endpoint actuator dengan Spring Security atau nonaktifkan ekspos web-nya di application.properties.",
		},
		{
			path:        "/server-status",
			title:       "Paparan Status Server Apache (server-status)",
			description: "Halaman server-status Apache terbuka ke publik, mengungkap URL request pengunjung aktif dan statistik lalu lintas internal.",
			severity:    models.SeverityMedium,
			category:    "Information Disclosure",
			matchSign:   "Apache Server Status",
			remediation: "Batasi akses /server-status hanya untuk IP localhost / VPN administrator.",
		},
		{
			path:        "/backup.sql",
			title:       "Paparan Cadangan Database Publik (backup.sql)",
			description: "File database backup .sql terdeteksi di root web server dan dapat diunduh tanpa autentikasi.",
			severity:    models.SeverityCritical,
			category:    "Data Leakage",
			matchSign:   "CREATE TABLE",
			remediation: "Pindahkan seluruh file backup database ke storage aman di luar direktori web yang dapat diakses publik.",
		},
	}

	for _, probe := range probes {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		targetURL := baseURL + probe.path
		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "KyyTools-Security-Scanner/1.0.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
			resp.Body.Close()

			bodyStr := string(bodyBytes)
			if probe.matchSign == "" || strings.Contains(bodyStr, probe.matchSign) {
				findings = append(findings, models.Finding{
					ModuleName:         m.Name(),
					Title:              probe.title,
					Description:        probe.description,
					Severity:           probe.severity,
					Confidence:         models.ConfidenceCertain,
					Category:           probe.category,
					Evidence:           fmt.Sprintf("HTTP 200 OK diterima pada: %s\nCuplikan respons cocok dengan tanda khas: '%s'", targetURL, probe.matchSign),
					Remediation:        probe.remediation,
					VerificationStatus: "VERIFIED",
				})
			}
		} else {
			resp.Body.Close()
		}
	}

	return findings, nil
}

// -------------------------------------------------------------
// 7. TLSCheckModule (Enhanced Certificate & Deprecated Protocols)
// -------------------------------------------------------------

type TLSCheckModule struct{}

func (m *TLSCheckModule) Name() string { return "tls_check" }
func (m *TLSCheckModule) Description() string {
	return "Pemeriksaan Validitas Sertifikat & Protokol TLS Deprecated"
}
func (m *TLSCheckModule) Run(ctx context.Context, target *models.Target, profile *models.ScanProfile, val *safety.ScopeValidator) ([]models.Finding, error) {
	var findings []models.Finding

	port := 443
	if target.Port != 80 && target.Port != 0 {
		port = target.Port
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	addr := net.JoinHostPort(target.Host, strconv.Itoa(port))

	// 1. Standard verified TLS handshake
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         target.Host,
	})

	if err != nil {
		insecureConn, errInsecure := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         target.Host,
		})

		if errInsecure == nil {
			defer insecureConn.Close()
			state := insecureConn.ConnectionState()
			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				now := time.Now()

				if now.After(cert.NotAfter) {
					findings = append(findings, models.Finding{
						ModuleName:         m.Name(),
						Title:              "Sertifikat TLS/SSL Telah Kedaluwarsa (Expired)",
						Description:        fmt.Sprintf("Sertifikat kedaluwarsa pada %s.", cert.NotAfter.Format("02 Jan 2006")),
						Severity:           models.SeverityHigh,
						Confidence:         models.ConfidenceCertain,
						Category:           "SSL/TLS",
						Evidence:           fmt.Sprintf("Issuer: %s, Expiry: %s", cert.Issuer.CommonName, cert.NotAfter),
						Remediation:        "Perbarui sertifikat TLS/SSL segera dengan sertifikat yang valid dari CA terpercaya.",
						VerificationStatus: "VERIFIED",
					})
				} else {
					findings = append(findings, models.Finding{
						ModuleName:         m.Name(),
						Title:              "Rantai Sertifikat TLS/SSL Tidak Valid atau Self-Signed",
						Description:        "Koneksi TLS gagal divalidasi oleh Root CA publik.",
						Severity:           models.SeverityMedium,
						Confidence:         models.ConfidenceCertain,
						Category:           "SSL/TLS",
						Evidence:           fmt.Sprintf("Error validasi: %v", err),
						Remediation:        "Gunakan sertifikat yang ditandatangani oleh Certificate Authority (CA) publik resmi.",
						VerificationStatus: "VERIFIED",
					})
				}
			}
		}
	} else {
		defer conn.Close()
		state := conn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)

			if daysRemaining < 15 && daysRemaining >= 0 {
				findings = append(findings, models.Finding{
					ModuleName:         m.Name(),
					Title:              fmt.Sprintf("Sertifikat TLS Segera Kedaluwarsa (%d hari tersisa)", daysRemaining),
					Description:        fmt.Sprintf("Masa berlaku sertifikat berakhir pada %s.", cert.NotAfter.Format("02 Jan 2006")),
					Severity:           models.SeverityLow,
					Confidence:         models.ConfidenceCertain,
					Category:           "SSL/TLS",
					Evidence:           fmt.Sprintf("CN: %s, NotAfter: %s", cert.Subject.CommonName, cert.NotAfter),
					Remediation:        "Lakukan perpanjangan sertifikat TLS/SSL sebelum tanggal kedaluwarsa.",
					VerificationStatus: "VERIFIED",
				})
			}
		}
	}

	// 2. Check for Deprecated TLS 1.0 support (RFC 8996)
	connTLS10, errTLS10 := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         target.Host,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS10,
	})
	if errTLS10 == nil {
		connTLS10.Close()
		findings = append(findings, models.Finding{
			ModuleName:         m.Name(),
			Title:              "Server Mendukung Protokol Usang TLS 1.0 (Deprecated)",
			Description:        "Server menerima negosiasi koneksi menggunakan protokol TLS versi 1.0 yang sudah dinyatakan deprecated oleh IETF (RFC 8996) karena rentan serangan kriptografi (BEAST/POODLE).",
			Severity:           models.SeverityMedium,
			Confidence:         models.ConfidenceCertain,
			Category:           "SSL/TLS",
			Evidence:           "Handshake TLS 1.0 berhasil dinegosiasikan.",
			Remediation:        "Nonaktifkan protokol TLS 1.0 dan TLS 1.1 pada web server. Konfigurasikan hanya TLS 1.2 dan TLS 1.3.",
			VerificationStatus: "VERIFIED",
		})
	}

	// 3. Check for Deprecated TLS 1.1 support
	connTLS11, errTLS11 := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         target.Host,
		MinVersion:         tls.VersionTLS11,
		MaxVersion:         tls.VersionTLS11,
	})
	if errTLS11 == nil {
		connTLS11.Close()
		findings = append(findings, models.Finding{
			ModuleName:         m.Name(),
			Title:              "Server Mendukung Protokol Usang TLS 1.1 (Deprecated)",
			Description:        "Server menerima negosiasi koneksi menggunakan protokol TLS versi 1.1.",
			Severity:           models.SeverityLow,
			Confidence:         models.ConfidenceCertain,
			Category:           "SSL/TLS",
			Evidence:           "Handshake TLS 1.1 berhasil dinegosiasikan.",
			Remediation:        "Gunakan minimal protokol TLS 1.2 untuk memenuhi standar kepatuhan modern (PCI-DSS).",
			VerificationStatus: "VERIFIED",
		})
	}

	return findings, nil
}

// -------------------------------------------------------------
// 8. VulnTemplatesModule (YAML Vulnerability Template Engine)
// -------------------------------------------------------------

type VulnTemplatesModule struct{}

func (m *VulnTemplatesModule) Name() string { return "vuln_templates" }
func (m *VulnTemplatesModule) Description() string {
	return "Eksekusi Engine Template Aturan Kerentanan YAML"
}
func (m *VulnTemplatesModule) Run(ctx context.Context, target *models.Target, profile *models.ScanProfile, val *safety.ScopeValidator) ([]models.Finding, error) {
	var findings []models.Finding

	templateDir := "templates"
	if _, err := os.Stat(templateDir); os.IsNotExist(err) {
		return findings, nil
	}

	client := val.CreateSafeHTTPClient(6*time.Second, false, 2)
	baseURL := strings.TrimRight(target.CanonicalURL, "/")

	_ = filepath.Walk(templateDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || (!strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml")) {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		var tmpl models.Template
		if err := yaml.Unmarshal(data, &tmpl); err != nil {
			return nil
		}

		// Execute template checks
		if tmpl.CheckType == "http_path" {
			targetPath := tmpl.Metadata["path"]
			if targetPath == "" {
				return nil
			}

			fullURL := baseURL + targetPath
			req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
			if err != nil {
				return nil
			}
			req.Header.Set("User-Agent", "KyyTools-Security-Scanner/1.0.0")

			resp, err := client.Do(req)
			if err != nil {
				return nil
			}
			defer resp.Body.Close()

			expectedStatus := tmpl.Metadata["expected_status"]
			matchStr := tmpl.Metadata["match_string"]

			matched := true
			if expectedStatus != "" {
				stCode, _ := strconv.Atoi(expectedStatus)
				if resp.StatusCode != stCode {
					matched = false
				}
			}

			if matched && matchStr != "" {
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
				if !strings.Contains(string(bodyBytes), matchStr) {
					matched = false
				}
			}

			if matched {
				findings = append(findings, models.Finding{
					ModuleName:         m.Name(),
					Title:              fmt.Sprintf("[Template] %s", tmpl.Name),
					Description:        tmpl.Description,
					Severity:           tmpl.Severity,
					Confidence:         models.ConfidenceCertain,
					Category:           tmpl.Category,
					Evidence:           fmt.Sprintf("Aturan template '%s' cocok pada %s", tmpl.ID, fullURL),
					Remediation:        tmpl.Remediation,
					References:         tmpl.References,
					VerificationStatus: "VERIFIED",
				})
			}
		}

		return nil
	})

	return findings, nil
}

// -------------------------------------------------------------
// 9. ServiceDetectionModule (Banner Grabbing)
// -------------------------------------------------------------

type ServiceDetectionModule struct{}

func (m *ServiceDetectionModule) Name() string { return "service_detection" }
func (m *ServiceDetectionModule) Description() string {
	return "Identifikasi Banner Layanan & Service Fingerprinting"
}
func (m *ServiceDetectionModule) Run(ctx context.Context, target *models.Target, profile *models.ScanProfile, val *safety.ScopeValidator) ([]models.Finding, error) {
	var findings []models.Finding

	portsToInspect := []int{21, 22, 25, 80, 110, 143, 3306, 6379}
	dialer := net.Dialer{Timeout: 1500 * time.Millisecond}

	for _, p := range portsToInspect {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		addr := net.JoinHostPort(target.Host, strconv.Itoa(p))
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			continue
		}

		_ = conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
		reader := bufio.NewReader(conn)
		banner, _ := reader.ReadString('\n')
		conn.Close()

		banner = strings.TrimSpace(banner)
		if banner != "" {
			findings = append(findings, models.Finding{
				ModuleName:         m.Name(),
				Title:              fmt.Sprintf("Banner Layanan Port %d: %s", p, guessServiceName(p)),
				Description:        "Layanan memancarkan banner respon pembuka yang mengungkap identitas software server.",
				Severity:           models.SeverityInfo,
				Confidence:         models.ConfidenceCertain,
				Category:           "Service Banner",
				Port:               p,
				Protocol:           "TCP",
				Evidence:           fmt.Sprintf("Banner: %s", banner),
				Remediation:        "Sembunyikan banner versi layanan jika dimungkinkan oleh software daemon yang digunakan.",
				VerificationStatus: "VERIFIED",
			})
		}
	}

	return findings, nil
}

// -------------------------------------------------------------
// 10. PortScanModule (Controlled TCP Discovery)
// -------------------------------------------------------------

type PortScanModule struct {
	name         string
	defaultPorts []int
}

func (m *PortScanModule) Name() string        { return m.name }
func (m *PortScanModule) Description() string { return fmt.Sprintf("TCP Port Scanner (%s)", m.name) }
func (m *PortScanModule) Run(ctx context.Context, target *models.Target, profile *models.ScanProfile, val *safety.ScopeValidator) ([]models.Finding, error) {
	var findings []models.Finding

	portsToScan := m.defaultPorts
	if profile.PortRange != "" && profile.PortRange != "default" {
		parsed := parsePortList(profile.PortRange)
		if len(parsed) > 0 {
			portsToScan = parsed
		}
	}

	concurrency := profile.Concurrency
	if concurrency <= 0 {
		concurrency = 20
	}
	sem := make(chan struct{}, concurrency)

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, port := range portsToScan {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			addr := net.JoinHostPort(target.Host, strconv.Itoa(p))
			dialer := net.Dialer{Timeout: 1200 * time.Millisecond}

			conn, err := dialer.DialContext(ctx, "tcp", addr)
			if err == nil {
				conn.Close()
				serviceName := guessServiceName(p)

				mu.Lock()
				findings = append(findings, models.Finding{
					ModuleName:         m.name,
					Title:              fmt.Sprintf("Port TCP Terbuka: %d (%s)", p, serviceName),
					Description:        fmt.Sprintf("Layanan terdeteksi mendengarkan koneksi pada port TCP %d (%s).", p, serviceName),
					Severity:           models.SeverityInfo,
					Confidence:         models.ConfidenceCertain,
					Category:           "Network Security",
					Port:               p,
					Protocol:           "TCP",
					Evidence:           fmt.Sprintf("Koneksi TCP handshake berhasil ke %s:%d", target.Host, p),
					Remediation:        "Pastikan hanya port dan layanan yang esensial yang diekspos ke publik.",
					VerificationStatus: "VERIFIED",
				})
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return findings, nil
}

func parsePortList(str string) []int {
	var ports []int
	parts := strings.Split(str, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err1 == nil && err2 == nil && start > 0 && end <= 65535 && start <= end {
					if end-start > 250 {
						end = start + 250
					}
					for i := start; i <= end; i++ {
						ports = append(ports, i)
					}
				}
			}
		} else {
			if p, err := strconv.Atoi(part); err == nil && p > 0 && p <= 65535 {
				ports = append(ports, p)
			}
		}
	}
	return ports
}

func guessServiceName(port int) string {
	switch port {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 80:
		return "HTTP"
	case 110:
		return "POP3"
	case 143:
		return "IMAP"
	case 443:
		return "HTTPS"
	case 465:
		return "SMTPS"
	case 587:
		return "Submission"
	case 993:
		return "IMAPS"
	case 995:
		return "POP3S"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP"
	case 5432:
		return "PostgreSQL"
	case 6379:
		return "Redis"
	case 8000:
		return "HTTP-Alt"
	case 8080:
		return "HTTP-Proxy"
	case 8443:
		return "HTTPS-Alt"
	case 8888:
		return "HTTP-Alt"
	case 9200:
		return "Elasticsearch"
	case 27017:
		return "MongoDB"
	default:
		return "Unknown"
	}
}
