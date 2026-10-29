package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kyytools/kyytools/internal/models"
	"github.com/kyytools/kyytools/internal/reports"
)

func TestReports_Generation(t *testing.T) {
	tempDir := t.TempDir()

	scan := &models.Scan{
		ID:            101,
		TargetHost:    "scan-me.test",
		TargetType:    "DOMAIN",
		ProfileName:   "quick",
		Status:        models.ScanStatusCompleted,
		DurationMs:    820,
		RiskScore:     5.5,
		FindingsCount: 1,
		MediumCount:   1,
		CreatedAt:     time.Now(),
	}

	findings := []models.Finding{
		{
			ID:                 1,
			ScanID:             101,
			ModuleName:         "web_headers",
			Title:              "Header HSTS Hilang",
			Description:        "Strict-Transport-Security tidak diimplementasikan.",
			Severity:           models.SeverityMedium,
			Confidence:         models.ConfidenceCertain,
			Host:               "scan-me.test",
			Port:               443,
			Evidence:           "Header tidak ditemukan",
			Remediation:        "Tambahkan header HSTS",
			VerificationStatus: "VERIFIED",
			CreatedAt:          time.Now(),
		},
	}

	// 1. JSON Report
	jsonPath, err := reports.GenerateReport(scan, findings, tempDir, "json")
	if err != nil {
		t.Fatalf("gagal membuat laporan JSON: %v", err)
	}
	contentJSON, err := os.ReadFile(jsonPath)
	if err != nil || !strings.Contains(string(contentJSON), "Header HSTS Hilang") {
		t.Errorf("konten laporan JSON tidak valid: %s", string(contentJSON))
	}

	// 2. CSV Report
	csvPath, err := reports.GenerateReport(scan, findings, tempDir, "csv")
	if err != nil {
		t.Fatalf("gagal membuat laporan CSV: %v", err)
	}
	contentCSV, err := os.ReadFile(csvPath)
	if err != nil || !strings.Contains(string(contentCSV), "Header HSTS Hilang") {
		t.Errorf("konten laporan CSV tidak valid: %s", string(contentCSV))
	}

	// 3. HTML Report
	htmlPath, err := reports.GenerateReport(scan, findings, tempDir, "html")
	if err != nil {
		t.Fatalf("gagal membuat laporan HTML: %v", err)
	}
	contentHTML, err := os.ReadFile(htmlPath)
	if err != nil || !strings.Contains(string(contentHTML), "KyyTools Security Scanner") {
		t.Errorf("konten laporan HTML tidak valid: %s", filepath.Base(htmlPath))
	}
}
