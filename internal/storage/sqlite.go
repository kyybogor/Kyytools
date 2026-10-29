package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kyybogor/Kyytools/internal/models"
	_ "modernc.org/sqlite"
)

// Storage manages persistent SQLite database operations for KyyTools.
type Storage struct {
	db *sql.DB
	mu sync.RWMutex
}

// NewStorage opens or creates the SQLite database and runs migrations.
func NewStorage(dbPath string) (*Storage, error) {
	if dbPath == "" {
		dbPath = "kyytools.db"
	}

	dir := filepath.Dir(dbPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("gagal membuat direktori database %s: %w", dir, err)
		}
	}

	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("gagal membuka database SQLite: %w", err)
	}

	db.SetMaxOpenConns(1) // SQLite single writer optimization

	s := &Storage{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrasi database gagal: %w", err)
	}

	return s, nil
}

// Close gracefully closes the database handle.
func (s *Storage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// migrate creates required tables and indexes.
func (s *Storage) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS targets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		raw_input TEXT NOT NULL,
		type TEXT NOT NULL,
		host TEXT NOT NULL,
		port INTEGER NOT NULL,
		scheme TEXT NOT NULL,
		resolved_ips TEXT,
		canonical_url TEXT,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target_id INTEGER NOT NULL,
		target_host TEXT NOT NULL,
		target_type TEXT NOT NULL,
		profile_name TEXT NOT NULL,
		status TEXT NOT NULL,
		start_time DATETIME NOT NULL,
		end_time DATETIME,
		duration_ms INTEGER DEFAULT 0,
		findings_count INTEGER DEFAULT 0,
		critical_count INTEGER DEFAULT 0,
		high_count INTEGER DEFAULT 0,
		medium_count INTEGER DEFAULT 0,
		low_count INTEGER DEFAULT 0,
		info_count INTEGER DEFAULT 0,
		risk_score REAL DEFAULT 0.0,
		error_message TEXT,
		created_at DATETIME NOT NULL,
		FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS scan_modules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL,
		module_name TEXT NOT NULL,
		status TEXT NOT NULL,
		start_time DATETIME NOT NULL,
		end_time DATETIME,
		duration_ms INTEGER DEFAULT 0,
		error_message TEXT,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS findings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL,
		module_name TEXT NOT NULL,
		title TEXT NOT NULL,
		description TEXT NOT NULL,
		severity TEXT NOT NULL,
		confidence TEXT NOT NULL,
		category TEXT,
		host TEXT NOT NULL,
		port INTEGER,
		protocol TEXT,
		evidence TEXT,
		remediation TEXT,
		ref_links TEXT,
		verification_status TEXT,
		raw_data TEXT,
		created_at DATETIME NOT NULL,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS discovered_subdomains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL,
		domain TEXT NOT NULL,
		subdomain TEXT NOT NULL,
		resolved_ips TEXT,
		status_code INTEGER,
		source TEXT,
		discovered_at DATETIME NOT NULL,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS open_ports (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL,
		host TEXT NOT NULL,
		port INTEGER NOT NULL,
		protocol TEXT NOT NULL,
		state TEXT NOT NULL,
		service_name TEXT,
		banner TEXT,
		discovered_at DATETIME NOT NULL,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS templates (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		severity TEXT NOT NULL,
		category TEXT,
		target_type TEXT,
		check_type TEXT,
		content TEXT NOT NULL,
		updated_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS scan_profiles (
		name TEXT PRIMARY KEY,
		description TEXT,
		modules TEXT NOT NULL,
		timeout_seconds INTEGER NOT NULL,
		concurrency INTEGER NOT NULL,
		rate_limit INTEGER NOT NULL,
		port_range TEXT,
		is_default INTEGER DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id, severity);
	CREATE INDEX IF NOT EXISTS idx_ports_scan ON open_ports(scan_id);
	CREATE INDEX IF NOT EXISTS idx_subdomains_scan ON discovered_subdomains(scan_id);
	`

	_, err := s.db.Exec(schema)
	return err
}

// SaveTarget stores a validated target and returns its database ID.
func (s *Storage) SaveTarget(t *models.Target) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ipsJSON, _ := json.Marshal(t.ResolvedIPs)

	res, err := s.db.Exec(`
		INSERT INTO targets (raw_input, type, host, port, scheme, resolved_ips, canonical_url, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, t.RawInput, string(t.Type), t.Host, t.Port, t.Scheme, string(ipsJSON), t.CanonicalURL, t.CreatedAt.UTC())
	if err != nil {
		return 0, err
	}

	id, err := res.LastInsertId()
	if err == nil {
		t.ID = id
	}
	return id, err
}

// CreateScan initializes a new scan record.
func (s *Storage) CreateScan(scan *models.Scan) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(`
		INSERT INTO scans (target_id, target_host, target_type, profile_name, status, start_time, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, scan.TargetID, scan.TargetHost, scan.TargetType, scan.ProfileName, string(scan.Status), scan.StartTime.UTC(), scan.CreatedAt.UTC())
	if err != nil {
		return 0, err
	}

	id, err := res.LastInsertId()
	if err == nil {
		scan.ID = id
	}
	return id, err
}

// UpdateScanStatus updates the terminal state of a scan.
func (s *Storage) UpdateScanStatus(scanID int64, status models.ScanStatus, durationMs int64, riskScore float64, errMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	_, err := s.db.Exec(`
		UPDATE scans
		SET status = ?, end_time = ?, duration_ms = ?, risk_score = ?, error_message = ?
		WHERE id = ?
	`, string(status), now, durationMs, riskScore, errMsg, scanID)
	return err
}

// UpdateScanCounts updates aggregated finding counts in the scan row.
func (s *Storage) UpdateScanCounts(scanID int64, crit, high, med, low, info, total int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		UPDATE scans
		SET critical_count = ?, high_count = ?, medium_count = ?, low_count = ?, info_count = ?, findings_count = ?
		WHERE id = ?
	`, crit, high, med, low, info, total, scanID)
	return err
}

// SaveFinding inserts a single finding record.
func (s *Storage) SaveFinding(f *models.Finding) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	refsJSON, _ := json.Marshal(f.References)

	res, err := s.db.Exec(`
		INSERT INTO findings (scan_id, module_name, title, description, severity, confidence, category, host, port, protocol, evidence, remediation, ref_links, verification_status, raw_data, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, f.ScanID, f.ModuleName, f.Title, f.Description, string(f.Severity), string(f.Confidence), f.Category, f.Host, f.Port, f.Protocol, f.Evidence, f.Remediation, string(refsJSON), f.VerificationStatus, f.RawData, f.CreatedAt.UTC())
	if err != nil {
		return 0, err
	}

	id, err := res.LastInsertId()
	if err == nil {
		f.ID = id
	}
	return id, err
}

// GetScanByID retrieves a scan by its primary key ID.
func (s *Storage) GetScanByID(scanID int64) (*models.Scan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`
		SELECT id, target_id, target_host, target_type, profile_name, status, start_time, end_time, duration_ms,
		       findings_count, critical_count, high_count, medium_count, low_count, info_count, risk_score, error_message, created_at
		FROM scans
		WHERE id = ?
	`, scanID)

	var scan models.Scan
	var statusStr string
	var endTime sql.NullTime
	var errMsg sql.NullString

	err := row.Scan(
		&scan.ID, &scan.TargetID, &scan.TargetHost, &scan.TargetType, &scan.ProfileName,
		&statusStr, &scan.StartTime, &endTime, &scan.DurationMs,
		&scan.FindingsCount, &scan.CriticalCount, &scan.HighCount, &scan.MediumCount, &scan.LowCount, &scan.InfoCount,
		&scan.RiskScore, &errMsg, &scan.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	scan.Status = models.ScanStatus(statusStr)
	if endTime.Valid {
		scan.EndTime = &endTime.Time
	}
	if errMsg.Valid {
		scan.ErrorMessage = errMsg.String
	}

	return &scan, nil
}

// ListScans returns recent scans ordered by start time descending.
func (s *Storage) ListScans(limit int) ([]models.Scan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 {
		limit = 50
	}

	rows, err := s.db.Query(`
		SELECT id, target_id, target_host, target_type, profile_name, status, start_time, end_time, duration_ms,
		       findings_count, critical_count, high_count, medium_count, low_count, info_count, risk_score, error_message, created_at
		FROM scans
		ORDER BY id DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []models.Scan
	for rows.Next() {
		var scan models.Scan
		var statusStr string
		var endTime sql.NullTime
		var errMsg sql.NullString

		if err := rows.Scan(
			&scan.ID, &scan.TargetID, &scan.TargetHost, &scan.TargetType, &scan.ProfileName,
			&statusStr, &scan.StartTime, &endTime, &scan.DurationMs,
			&scan.FindingsCount, &scan.CriticalCount, &scan.HighCount, &scan.MediumCount, &scan.LowCount, &scan.InfoCount,
			&scan.RiskScore, &errMsg, &scan.CreatedAt,
		); err != nil {
			return nil, err
		}

		scan.Status = models.ScanStatus(statusStr)
		if endTime.Valid {
			scan.EndTime = &endTime.Time
		}
		if errMsg.Valid {
			scan.ErrorMessage = errMsg.String
		}

		result = append(result, scan)
	}

	return result, nil
}

// GetFindingsByScanID retrieves all findings linked to a specific scan.
func (s *Storage) GetFindingsByScanID(scanID int64) ([]models.Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT id, scan_id, module_name, title, description, severity, confidence, category,
		       host, port, protocol, evidence, remediation, ref_links, verification_status, raw_data, created_at
		FROM findings
		WHERE scan_id = ?
		ORDER BY 
			CASE severity
				WHEN 'CRITICAL' THEN 1
				WHEN 'HIGH' THEN 2
				WHEN 'MEDIUM' THEN 3
				WHEN 'LOW' THEN 4
				ELSE 5
			END ASC, id ASC
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []models.Finding
	for rows.Next() {
		var f models.Finding
		var sevStr, confStr, refsStr, catStr, protoStr, evidStr, remedStr, rawStr string
		var portVal sql.NullInt64

		if err := rows.Scan(
			&f.ID, &f.ScanID, &f.ModuleName, &f.Title, &f.Description, &sevStr, &confStr, &catStr,
			&f.Host, &portVal, &protoStr, &evidStr, &remedStr, &refsStr, &f.VerificationStatus, &rawStr, &f.CreatedAt,
		); err != nil {
			return nil, err
		}

		f.Severity = models.Severity(sevStr)
		f.Confidence = models.Confidence(confStr)
		f.Category = catStr
		f.Protocol = protoStr
		f.Evidence = evidStr
		f.Remediation = remedStr
		f.RawData = rawStr
		if portVal.Valid {
			f.Port = int(portVal.Int64)
		}

		if refsStr != "" {
			_ = json.Unmarshal([]byte(refsStr), &f.References)
		}

		findings = append(findings, f)
	}

	return findings, nil
}

// SaveOpenPort records an identified open port.
func (s *Storage) SaveOpenPort(p *models.OpenPort) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT INTO open_ports (scan_id, host, port, protocol, state, service_name, banner, discovered_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, p.ScanID, p.Host, p.Port, p.Protocol, p.State, p.ServiceName, p.Banner, p.DiscoveredAt.UTC())
	return err
}

// GetOpenPortsByScanID gets all open ports for a scan.
func (s *Storage) GetOpenPortsByScanID(scanID int64) ([]models.OpenPort, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT id, scan_id, host, port, protocol, state, service_name, banner, discovered_at
		FROM open_ports
		WHERE scan_id = ?
		ORDER BY port ASC
	`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ports []models.OpenPort
	for rows.Next() {
		var p models.OpenPort
		var svcStr, bannerStr sql.NullString
		if err := rows.Scan(&p.ID, &p.ScanID, &p.Host, &p.Port, &p.Protocol, &p.State, &svcStr, &bannerStr, &p.DiscoveredAt); err != nil {
			return nil, err
		}
		if svcStr.Valid {
			p.ServiceName = svcStr.String
		}
		if bannerStr.Valid {
			p.Banner = bannerStr.String
		}
		ports = append(ports, p)
	}
	return ports, nil
}

// SaveScanModule saves module execution details for a scan.
func (s *Storage) SaveScanModule(m *models.ScanModule) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(`
		INSERT INTO scan_modules (scan_id, module_name, status, start_time, duration_ms, error_message)
		VALUES (?, ?, ?, ?, ?, ?)
	`, m.ScanID, m.ModuleName, string(m.Status), m.StartTime.UTC(), m.DurationMs, m.ErrorMessage)
	if err != nil {
		return 0, err
	}

	id, err := res.LastInsertId()
	if err == nil {
		m.ID = id
	}
	return id, err
}

// SaveDiscoveredSubdomain records a discovered subdomain.
func (s *Storage) SaveDiscoveredSubdomain(d *models.DiscoveredSubdomain) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ipsJSON, _ := json.Marshal(d.ResolvedIPs)
	_, err := s.db.Exec(`
		INSERT INTO discovered_subdomains (scan_id, domain, subdomain, resolved_ips, status_code, source, discovered_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, d.ScanID, d.Domain, d.Subdomain, string(ipsJSON), d.StatusCode, d.Source, d.DiscoveredAt.UTC())
	return err
}

// DeleteScan removes a scan and cascade records.
func (s *Storage) DeleteScan(scanID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`DELETE FROM scans WHERE id = ?`, scanID)
	return err
}

// SetSetting saves key-value pair.
func (s *Storage) SetSetting(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT INTO settings (key, value, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
	`, key, value, time.Now().UTC())
	return err
}

// GetSetting gets value by key.
func (s *Storage) GetSetting(key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var val string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&val)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return "", nil
		}
		return "", err
	}
	return val, nil
}
