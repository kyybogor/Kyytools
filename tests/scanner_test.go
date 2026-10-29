package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/kyytools/kyytools/internal/models"
	"github.com/kyytools/kyytools/internal/safety"
	"github.com/kyytools/kyytools/internal/scanner"
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
		if f.Title == "Pengungkapan Versi Web Server (Server Banner)" {
			foundServerBanner = true
		}
		if f.Title == "Pengungkapan Framework Backend (X-Powered-By)" {
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
		t.Errorf("X-Powered-By disclosure tidak terdeteksi")
	}
	if !foundCookieInsecure {
		t.Errorf("Cookie insecure flag tidak terdeteksi")
	}
}
