package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kyybogor/Kyytools/internal/models"
	"github.com/kyybogor/Kyytools/internal/risk"
	"github.com/kyybogor/Kyytools/internal/safety"
	"github.com/kyybogor/Kyytools/internal/storage"
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

// NewEngine creates an initialized scanner engine with standard modules registered.
func NewEngine(cfg *models.AppConfig, store *storage.Storage, val *safety.ScopeValidator) *Engine {
	e := &Engine{
		config:    cfg,
		storage:   store,
		validator: val,
		modules:   make(map[string]Module),
	}

	// Register core Phase 1 & 2 modules
	e.RegisterModule(&TargetInfoModule{})
	e.RegisterModule(&DNSResolverModule{})
	e.RegisterModule(&WebHeadersModule{})
	e.RegisterModule(&TLSCheckModule{})
	e.RegisterModule(&PortScanModule{name: "port_scan_top", defaultPorts: []int{80, 443, 8080, 8443}})
	e.RegisterModule(&PortScanModule{name: "port_scan_standard", defaultPorts: []int{21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 6379, 8000, 8080, 8443, 8888}})

	return e
}

// RegisterModule adds a module to the engine.
func (e *Engine) RegisterModule(m Module) {
	e.modules[m.Name()] = m
}

// RunScan executes the selected scan profile against the target.
func (e *Engine) RunScan(ctx context.Context, target *models.Target, profile *models.ScanProfile, onProgress ProgressCallback) (*models.Scan, []models.Finding, error) {
	// 1. Create target record in DB
	targetID, err := e.storage.SaveTarget(target)
	if err != nil {
		return nil, nil, fmt.Errorf("gagal menyimpan target ke database: %w", err)
	}
	target.ID = targetID

	// 2. Initialize scan record
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

	// Determine modules to execute
	var activeModules []Module
	for _, modName := range profile.Modules {
		if mod, exists := e.modules[modName]; exists {
			activeModules = append(activeModules, mod)
		}
	}

	totalModules := len(activeModules)
	var allFindings []models.Finding
	startTime := time.Now()

	// Execute modules sequentially or bounded with per-module timeout
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
			onProgress(mod.Name(), idx+1, totalModules, fmt.Sprintf("Menjalankan %s...", mod.Description()))
		}

		modTimeout := time.Duration(e.config.Scanner.ModuleTimeout) * time.Second
		if modTimeout <= 0 {
			modTimeout = 30 * time.Second
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

		// Save module run
		_, _ = e.storage.SaveScanModule(&models.ScanModule{
			ScanID:       scan.ID,
			ModuleName:   mod.Name(),
			Status:       modStatus,
			StartTime:    modStart,
			DurationMs:   modDuration,
			ErrorMessage: errMsg,
		})

		// Save findings
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

	// Calculate counts & risk score
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
// Core Built-in Modules
// -------------------------------------------------------------

// TargetInfoModule produces baseline target classification finding.
type TargetInfoModule struct{}

func (m *TargetInfoModule) Name() string        { return "target_info" }
func (m *TargetInfoModule) Description() string { return "Identifikasi & Verifikasi Target" }
func (m *TargetInfoModule) Run(ctx context.Context, target *models.Target, profile *models.ScanProfile, val *safety.ScopeValidator) ([]models.Finding, error) {
	evidence := fmt.Sprintf("Target: %s\nType: %s\nHost: %s\nPort: %d\nResolved IPs: %s\nCanonical: %s",
		target.RawInput, target.Type, target.Host, target.Port, strings.Join(target.ResolvedIPs, ", "), target.CanonicalURL)

	return []models.Finding{
		{
			ModuleName:         m.Name(),
			Title:              fmt.Sprintf("Target Teridentifikasi: %s (%s)", target.Host, target.Type),
			Description:        "Target telah berhasil diverifikasi dan berada dalam scope pengujian yang diizinkan.",
			Severity:           models.SeverityInfo,
			Confidence:         models.ConfidenceCertain,
			Category:           "Information",
			Evidence:           evidence,
			VerificationStatus: "VERIFIED",
		},
	}, nil
}

// DNSResolverModule inspects DNS records (A, AAAA, MX, TXT) and checks SPF/DMARC.
type DNSResolverModule struct{}

func (m *DNSResolverModule) Name() string        { return "dns_resolver" }
func (m *DNSResolverModule) Description() string { return "Pemeriksaan Record DNS & Email Security" }
func (m *DNSResolverModule) Run(ctx context.Context, target *models.Target, profile *models.ScanProfile, val *safety.ScopeValidator) ([]models.Finding, error) {
	var findings []models.Finding

	// Only applicable to domain targets
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
			break
		}
	}

	// Check DMARC
	dmarcRecords, _ := resolver.LookupTXT(ctx, "_dmarc."+target.Host)
	hasDMARC := false
	for _, txt := range dmarcRecords {
		if strings.HasPrefix(strings.ToLower(txt), "v=dmarc1") {
			hasDMARC = true
			break
		}
	}

	// If domain handles mail or is an enterprise domain without SPF
	if hasMX && !hasSPF {
		findings = append(findings, models.Finding{
			ModuleName:         m.Name(),
			Title:              "Record SPF (Sender Policy Framework) Tidak Ditemukan",
			Description:        "Domain memiliki MX record namun tidak memiliki record TXT SPF untuk memvalidasi server pengirim email yang sah.",
			Severity:           models.SeverityLow,
			Confidence:         models.ConfidenceFirm,
			Category:           "Email Security",
			Evidence:           fmt.Sprintf("Lookup TXT pada %s tidak mengembalikan string 'v=spf1'", target.Host),
			Remediation:        "Tambahkan record DNS TXT SPF pada domain (contoh: 'v=spf1 mx -all') untuk mencegah email spoofing.",
			VerificationStatus: "VERIFIED",
		})
	}

	// If domain handles mail without DMARC
	if hasMX && !hasDMARC {
		findings = append(findings, models.Finding{
			ModuleName:         m.Name(),
			Title:              "Record DMARC Tidak Terkonfigurasi",
			Description:        "Domain tidak memiliki record DMARC (_dmarc.<domain>) untuk mengatur kebijakan penolakan email palsu.",
			Severity:           models.SeverityLow,
			Confidence:         models.ConfidenceFirm,
			Category:           "Email Security",
			Evidence:           fmt.Sprintf("Lookup TXT pada _dmarc.%s tidak mengembalikan string 'v=DMARC1'", target.Host),
			Remediation:        "Konfigurasikan record TXT pada '_dmarc." + target.Host + "' dengan kebijakan minimal p=none atau p=reject.",
			VerificationStatus: "VERIFIED",
		})
	}

	return findings, nil
}

// WebHeadersModule analyzes HTTP response headers and security postures.
type WebHeadersModule struct{}

func (m *WebHeadersModule) Name() string { return "web_headers" }
func (m *WebHeadersModule) Description() string {
	return "Analisis Header Keamanan HTTP & Server Banner"
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
		// Try fallback to https if http failed or vice versa
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

	// 1. Check Server Banner Information Disclosure
	if server := headers.Get("Server"); server != "" {
		if strings.Contains(server, "/") { // Contains version e.g. Apache/2.4.41 or nginx/1.18.0
			findings = append(findings, models.Finding{
				ModuleName:         m.Name(),
				Title:              "Pengungkapan Versi Web Server (Server Banner)",
				Description:        "Header HTTP 'Server' mengungkap versi software web server yang beroperasi.",
				Severity:           models.SeverityLow,
				Confidence:         models.ConfidenceCertain,
				Category:           "Information Disclosure",
				Evidence:           fmt.Sprintf("Server: %s", server),
				Remediation:        "Sembunyikan atau samarkan versi server (contoh: ServerTokens Prod pada Apache atau server_tokens off pada Nginx).",
				VerificationStatus: "VERIFIED",
			})
		}
	}

	// 2. Check X-Powered-By
	if poweredBy := headers.Get("X-Powered-By"); poweredBy != "" {
		findings = append(findings, models.Finding{
			ModuleName:         m.Name(),
			Title:              "Pengungkapan Framework Backend (X-Powered-By)",
			Description:        "Header 'X-Powered-By' membocorkan teknologi backend yang digunakan.",
			Severity:           models.SeverityLow,
			Confidence:         models.ConfidenceCertain,
			Category:           "Information Disclosure",
			Evidence:           fmt.Sprintf("X-Powered-By: %s", poweredBy),
			Remediation:        "Nonaktifkan header X-Powered-By pada konfigurasi aplikasi atau server (contoh: expose_php = Off pada php.ini).",
			VerificationStatus: "VERIFIED",
		})
	}

	// 3. Check Strict-Transport-Security (HSTS) on HTTPS
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

	// 4. Check Content-Security-Policy (CSP)
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

	// 5. Check X-Frame-Options (Clickjacking)
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

	// 6. Check X-Content-Type-Options
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

	// 7. Check Cookie Security Flags
	cookies := resp.Cookies()
	for _, c := range cookies {
		if !c.HttpOnly {
			findings = append(findings, models.Finding{
				ModuleName:         m.Name(),
				Title:              fmt.Sprintf("Cookie '%s' Tanpa Flag HttpOnly", c.Name),
				Description:        "Cookie sensitif dapat diakses melalui skrip sisi klien JavaScript (document.cookie).",
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
	}

	return findings, nil
}

// TLSCheckModule checks TLS certificate validity, expiration, and cipher negotiation.
type TLSCheckModule struct{}

func (m *TLSCheckModule) Name() string        { return "tls_check" }
func (m *TLSCheckModule) Description() string { return "Pemeriksaan Validitas Sertifikat TLS/SSL" }
func (m *TLSCheckModule) Run(ctx context.Context, target *models.Target, profile *models.ScanProfile, val *safety.ScopeValidator) ([]models.Finding, error) {
	var findings []models.Finding

	port := 443
	if target.Port != 80 && target.Port != 0 {
		port = target.Port
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(target.Host, strconv.Itoa(port)), &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         target.Host,
	})

	if err != nil {
		// Check if it's a self-signed or expired certificate
		insecureConn, errInsecure := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(target.Host, strconv.Itoa(port)), &tls.Config{
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
			return findings, nil
		}
		// If TLS dial failed completely, likely not a TLS port
		return findings, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)

		if daysRemaining < 15 {
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

	return findings, nil
}

// PortScanModule executes controlled, non-destructive TCP port discovery.
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

	// Concurrency limiter
	concurrency := profile.Concurrency
	if concurrency <= 0 {
		concurrency = 15
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
					Remediation:        "Pastikan hanya port dan layanan yang esensial yang diekspos ke jaringan publik.",
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
					// Limit range to prevent accidental massive flood
					if end-start > 200 {
						end = start + 200
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
	default:
		return "Unknown"
	}
}
