package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/kyybogor/Kyytools/internal/models"
	"github.com/kyybogor/Kyytools/internal/safety"
	"github.com/kyybogor/Kyytools/internal/scanner"
)

func TestWebHeadersModule_LocalServer(t *testing.T) {
	// Setup local test server with deliberate misconfigurations
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		// Missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    "test12345",
			HttpOnly: false, // Insecure cookie
		})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello Secure World"))
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("URL mock server tidak valid: %v", err)
	}

	port, _ := strconv.Atoi(u.Port())

	// For local test, allow loopback in scope config
	scopeCfg := models.ScopeConfig{
		AllowLoopback:   true,
		AllowPrivateIPs: true,
	}
	validator := safety.NewScopeValidator(scopeCfg)

	target := &models.Target{
		RawInput:     ts.URL,
		Type:         models.TargetTypeURL,
		Host:         u.Hostname(),
		Port:         port,
		Scheme:       u.Scheme,
		CanonicalURL: ts.URL,
	}

	mod := &scanner.WebHeadersModule{}
	profile := &models.ScanProfile{Name: "web"}

	findings, err := mod.Run(context.Background(), target, profile, validator)
	if err != nil {
		t.Fatalf("WebHeadersModule gagal dijalankan: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("diharapkan temuan keamanan terdeteksi dari mock server, namun hasil kosong")
	}

	// Verify specific findings were detected
	foundServerBanner := false
	foundPoweredBy := false
	foundCookieInsecure := false

	for _, f := range findings {
		if strings.Contains(f.Title, "Pengungkapan Versi Web Server") || strings.Contains(f.Title, "Server Banner") {
			foundServerBanner = true
		}
		if (strings.Contains(f.Title, "Pengungkapan Versi PHP") || strings.Contains(f.Title, "X-Powered-By")) && f.Severity == models.SeverityCritical {
			foundPoweredBy = true
		}
		if f.Category == "Cookie Security" {
			foundCookieInsecure = true
		}
	}

	if !foundServerBanner {
		t.Errorf("Server banner version disclosure tidak terdeteksi")
	}
	if !foundPoweredBy {
		t.Errorf("X-Powered-By PHP version disclosure (Critical) tidak terdeteksi")
	}
	if !foundCookieInsecure {
		t.Errorf("Cookie insecure flag tidak terdeteksi")
	}
}

func TestSensitiveFilesModule_LocalServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("APP_NAME=Laravel\nAPP_KEY=base64:testsecretkey=\nDB_PASSWORD=secret123\n"))
		case "/.git/HEAD":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ref: refs/heads/main\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	port, _ := strconv.Atoi(u.Port())

	scopeCfg := models.ScopeConfig{AllowLoopback: true, AllowPrivateIPs: true}
	validator := safety.NewScopeValidator(scopeCfg)

	target := &models.Target{
		RawInput:     ts.URL,
		Type:         models.TargetTypeURL,
		Host:         u.Hostname(),
		Port:         port,
		Scheme:       u.Scheme,
		CanonicalURL: ts.URL,
	}

	mod := &scanner.SensitiveFilesModule{}
	profile := &models.ScanProfile{Name: "web"}

	findings, err := mod.Run(context.Background(), target, profile, validator)
	if err != nil {
		t.Fatalf("SensitiveFilesModule gagal: %v", err)
	}

	foundEnv := false
	foundGit := false
	for _, f := range findings {
		if f.Severity == models.SeverityCritical && f.Title == "Paparan File Konfigurasi Lingkungan (.env)" {
			foundEnv = true
		}
		if f.Severity == models.SeverityHigh && f.Title == "Paparan Repositori Git Source Code (/.git/HEAD)" {
			foundGit = true
		}
	}

	if !foundEnv {
		t.Errorf("file .env sensitif tidak terdeteksi")
	}
	if !foundGit {
		t.Errorf("file .git/HEAD tidak terdeteksi")
	}
}

func TestCORSModule_LocalServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	port, _ := strconv.Atoi(u.Port())

	scopeCfg := models.ScopeConfig{AllowLoopback: true, AllowPrivateIPs: true}
	validator := safety.NewScopeValidator(scopeCfg)

	target := &models.Target{
		RawInput:     ts.URL,
		Type:         models.TargetTypeURL,
		Host:         u.Hostname(),
		Port:         port,
		Scheme:       u.Scheme,
		CanonicalURL: ts.URL,
	}

	mod := &scanner.CORSModule{}
	profile := &models.ScanProfile{Name: "web"}

	findings, err := mod.Run(context.Background(), target, profile, validator)
	if err != nil {
		t.Fatalf("CORSModule gagal: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("diharapkan celah CORS terdeteksi dari mock server")
	}

	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("severity CORS reflection dengan kredensial diharapkan HIGH, didapat: %s", findings[0].Severity)
	}
}
