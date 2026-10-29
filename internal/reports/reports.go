package reports

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/kyytools/kyytools/internal/models"
)

// ReportData provides structured input for report templates.
type ReportData struct {
	Scan        *models.Scan
	Findings    []models.Finding
	GeneratedAt time.Time
	Version     string
}

// GenerateReport exports scan results into the requested format (html, json, csv).
func GenerateReport(scan *models.Scan, findings []models.Finding, outputDir, format string) (string, error) {
	if outputDir == "" {
		outputDir = "reports"
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("gagal membuat direktori laporan %s: %w", outputDir, err)
	}

	fileName := fmt.Sprintf("scan-%03d.%s", scan.ID, format)
	fullPath := filepath.Join(outputDir, fileName)

	switch format {
	case "json":
		if err := ExportJSON(scan, findings, fullPath); err != nil {
			return "", err
		}
	case "csv":
		if err := ExportCSV(scan, findings, fullPath); err != nil {
			return "", err
		}
	case "html":
		if err := ExportHTML(scan, findings, fullPath); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("format laporan tidak didukung: %s (gunakan: html, json, atau csv)", format)
	}

	return fullPath, nil
}

// ExportJSON exports scan data to formatted JSON.
func ExportJSON(scan *models.Scan, findings []models.Finding, filePath string) error {
	data := ReportData{
		Scan:        scan,
		Findings:    findings,
		GeneratedAt: time.Now().UTC(),
		Version:     "1.0.0",
	}

	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("gagal serialisasi JSON: %w", err)
	}

	return os.WriteFile(filePath, bytes, 0644)
}

// ExportCSV exports findings to standard CSV.
func ExportCSV(scan *models.Scan, findings []models.Finding, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("gagal membuat file CSV: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Header row
	header := []string{
		"Scan ID", "Target", "Severity", "Confidence", "Module",
		"Title", "Description", "Host", "Port", "Remediation", "Created At",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, f := range findings {
		portStr := ""
		if f.Port > 0 {
			portStr = strconv.Itoa(f.Port)
		}
		row := []string{
			strconv.FormatInt(scan.ID, 10),
			scan.TargetHost,
			string(f.Severity),
			string(f.Confidence),
			f.ModuleName,
			f.Title,
			f.Description,
			f.Host,
			portStr,
			f.Remediation,
			f.CreatedAt.Format(time.RFC3339),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// ExportHTML exports a polished, secure HTML security assessment report.
func ExportHTML(scan *models.Scan, findings []models.Finding, filePath string) error {
	tmpl, err := template.New("report").Parse(htmlReportTemplate)
	if err != nil {
		return fmt.Errorf("gagal mem-parsing template HTML: %w", err)
	}

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("gagal membuat file HTML: %w", err)
	}
	defer file.Close()

	data := ReportData{
		Scan:        scan,
		Findings:    findings,
		GeneratedAt: time.Now(),
		Version:     "1.0.0",
	}

	return tmpl.Execute(file, data)
}

const htmlReportTemplate = `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Laporan Keamanan KyyTools - {{.Scan.TargetHost}}</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #111827;
      --border: #1f2937;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --primary: #3b82f6;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #f59e0b;
      --low: #10b981;
      --info: #06b6d4;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2rem 1rem;
    }
    .container { max-width: 1100px; margin: 0 auto; }
    .header {
      background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 100%);
      border: 1px solid #312e81;
      border-radius: 12px;
      padding: 2rem;
      margin-bottom: 2rem;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
    }
    .badge {
      display: inline-block;
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.85rem;
      font-weight: 700;
      text-transform: uppercase;
    }
    .badge-critical { background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }
    .badge-high { background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }
    .badge-medium { background: rgba(245, 158, 11, 0.2); color: var(--medium); border: 1px solid var(--medium); }
    .badge-low { background: rgba(16, 185, 129, 0.2); color: var(--low); border: 1px solid var(--low); }
    .badge-info { background: rgba(6, 182, 212, 0.2); color: var(--info); border: 1px solid var(--info); }
    
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .stat-card {
      background-color: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.25rem;
      text-align: center;
    }
    .stat-val { font-size: 2rem; font-weight: 800; margin-top: 0.25rem; }
    
    .card {
      background-color: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }
    .card-title { font-size: 1.2rem; font-weight: 700; margin-bottom: 1rem; color: #fff; }
    
    .finding-item {
      background: #161e2e;
      border-left: 4px solid var(--border);
      border-radius: 6px;
      padding: 1.25rem;
      margin-bottom: 1rem;
    }
    .finding-critical { border-left-color: var(--critical); }
    .finding-high { border-left-color: var(--high); }
    .finding-medium { border-left-color: var(--medium); }
    .finding-low { border-left-color: var(--low); }
    .finding-info { border-left-color: var(--info); }
    
    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.5rem;
    }
    .finding-title { font-size: 1.05rem; font-weight: 700; color: #fff; }
    .finding-meta { font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.75rem; }
    .finding-field { margin-bottom: 0.5rem; font-size: 0.95rem; }
    .finding-label { font-weight: 600; color: #d1d5db; }
    .code-box {
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 0.75rem;
      font-family: monospace;
      font-size: 0.85rem;
      white-space: pre-wrap;
      word-break: break-all;
      color: #79c0ff;
      margin-top: 0.25rem;
    }
    .footer {
      text-align: center;
      margin-top: 3rem;
      padding: 1.5rem;
      color: var(--text-muted);
      font-size: 0.85rem;
      border-top: 1px solid var(--border);
    }
    @media print {
      body { background: #fff; color: #000; }
      .header, .card, .stat-card, .finding-item { border: 1px solid #ccc; background: #fff; color: #000; box-shadow: none; }
      .finding-title, .card-title { color: #000; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 1rem;">
        <div>
          <h1 style="font-size: 1.8rem; font-weight: 800; color: #fff; margin-bottom: 0.5rem;">
            🛡️ KyyTools Security Scanner
          </h1>
          <p style="color: #94a3b8; font-size: 0.95rem;">Laporan Resmi Penilaian Keamanan Sistem</p>
        </div>
        <div style="text-align: right;">
          <div style="font-size: 0.9rem; color: #cbd5e1;">Scan ID: #{{.Scan.ID}}</div>
          <div style="font-size: 0.85rem; color: #94a3b8;">{{.GeneratedAt.Format "02 Jan 2006 15:04:05 MST"}}</div>
        </div>
      </div>
    </div>

    <!-- Metadata Grid -->
    <div class="card">
      <h2 class="card-title">Ringkasan Target & Sesi Scan</h2>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; font-size: 0.95rem;">
        <div><strong>Target:</strong> {{.Scan.TargetHost}}</div>
        <div><strong>Tipe:</strong> {{.Scan.TargetType}}</div>
        <div><strong>Profil:</strong> {{.Scan.ProfileName}}</div>
        <div><strong>Status:</strong> <span class="badge" style="background:#1e293b; color:#38bdf8;">{{.Scan.Status}}</span></div>
        <div><strong>Durasi:</strong> {{.Scan.DurationMs}} ms</div>
        <div><strong>Skor Risiko:</strong> <span style="font-weight:700; color:#fbbf24;">{{printf "%.1f" .Scan.RiskScore}} / 10.0</span></div>
      </div>
    </div>

    <!-- Stats Breakdown -->
    <div class="stats-grid">
      <div class="stat-card" style="border-top: 3px solid var(--critical);">
        <div style="color: var(--critical); font-weight: 600;">Critical</div>
        <div class="stat-val" style="color: var(--critical);">{{.Scan.CriticalCount}}</div>
      </div>
      <div class="stat-card" style="border-top: 3px solid var(--high);">
        <div style="color: var(--high); font-weight: 600;">High</div>
        <div class="stat-val" style="color: var(--high);">{{.Scan.HighCount}}</div>
      </div>
      <div class="stat-card" style="border-top: 3px solid var(--medium);">
        <div style="color: var(--medium); font-weight: 600;">Medium</div>
        <div class="stat-val" style="color: var(--medium);">{{.Scan.MediumCount}}</div>
      </div>
      <div class="stat-card" style="border-top: 3px solid var(--low);">
        <div style="color: var(--low); font-weight: 600;">Low</div>
        <div class="stat-val" style="color: var(--low);">{{.Scan.LowCount}}</div>
      </div>
      <div class="stat-card" style="border-top: 3px solid var(--info);">
        <div style="color: var(--info); font-weight: 600;">Info</div>
        <div class="stat-val" style="color: var(--info);">{{.Scan.InfoCount}}</div>
      </div>
    </div>

    <!-- Findings Section -->
    <div class="card">
      <h2 class="card-title">Daftar Temuan Keamanan ({{len .Findings}})</h2>
      {{if not .Findings}}
        <p style="color: var(--low); padding: 1rem 0;">✅ Tidak ditemukan kerentanan atau masalah konfigurasi pada target ini.</p>
      {{else}}
        {{range .Findings}}
        <div class="finding-item finding-{{.Severity}}">
          <div class="finding-header">
            <span class="finding-title">{{.Title}}</span>
            <span class="badge badge-{{.Severity}}">{{.Severity}}</span>
          </div>
          <div class="finding-meta">
            Modul: <strong>{{.ModuleName}}</strong> | Host: {{.Host}}{{if .Port}}:{{.Port}}{{end}} | Confidence: {{.Confidence}}
          </div>
          <div class="finding-field">
            <span class="finding-label">Deskripsi:</span> {{.Description}}
          </div>
          {{if .Evidence}}
          <div class="finding-field">
            <span class="finding-label">Bukti (Evidence):</span>
            <div class="code-box">{{.Evidence}}</div>
          </div>
          {{end}}
          {{if .Remediation}}
          <div class="finding-field" style="margin-top: 0.5rem;">
            <span class="finding-label">Rekomendasi Perbaikan:</span>
            <p style="color: #86efac; margin-top: 0.2rem;">{{.Remediation}}</p>
          </div>
          {{end}}
        </div>
        {{end}}
      {{end}}
    </div>

    <div class="footer">
      Dibuat secara otomatis oleh <strong>KyyTools Security Scanner v{{.Version}}</strong>.<br>
      Penilaian ini dibuat hanya untuk target yang memiliki izin otorisasi resmi.
    </div>
  </div>
</body>
</html>
`
