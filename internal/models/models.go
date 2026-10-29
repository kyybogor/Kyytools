package models

import (
	"time"
)

// TargetType represents the classification of a scan target.
type TargetType string

const (
	TargetTypeDomain TargetType = "DOMAIN"
	TargetTypeIPv4   TargetType = "IPV4"
	TargetTypeIPv6   TargetType = "IPV6"
	TargetTypeURL    TargetType = "URL"
)

// Target holds normalized information about the scan target.
type Target struct {
	ID           int64      `json:"id"`
	RawInput     string     `json:"raw_input"`
	Type         TargetType `json:"type"`
	Host         string     `json:"host"`
	Port         int        `json:"port"`
	Scheme       string     `json:"scheme"`
	ResolvedIPs  []string   `json:"resolved_ips"`
	CanonicalURL string     `json:"canonical_url"`
	CreatedAt    time.Time  `json:"created_at"`
}

// ScanStatus represents the lifecycle state of a scan.
type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "PENDING"
	ScanStatusRunning   ScanStatus = "RUNNING"
	ScanStatusCompleted ScanStatus = "COMPLETED"
	ScanStatusCancelled ScanStatus = "CANCELLED"
	ScanStatusFailed    ScanStatus = "FAILED"
)

// Severity represents vulnerability or finding severity level.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Confidence indicates certainty of a finding.
type Confidence string

const (
	ConfidenceCertain   Confidence = "CERTAIN"
	ConfidenceFirm      Confidence = "FIRM"
	ConfidenceTentative Confidence = "TENTATIVE"
)

// Scan represents a complete scanning session.
type Scan struct {
	ID            int64      `json:"id"`
	TargetID      int64      `json:"target_id"`
	TargetHost    string     `json:"target_host"`
	TargetType    string     `json:"target_type"`
	ProfileName   string     `json:"profile_name"`
	Status        ScanStatus `json:"status"`
	StartTime     time.Time  `json:"start_time"`
	EndTime       *time.Time `json:"end_time,omitempty"`
	DurationMs    int64      `json:"duration_ms"`
	FindingsCount int        `json:"findings_count"`
	CriticalCount int        `json:"critical_count"`
	HighCount     int        `json:"high_count"`
	MediumCount   int        `json:"medium_count"`
	LowCount      int        `json:"low_count"`
	InfoCount     int        `json:"info_count"`
	RiskScore     float64    `json:"risk_score"`
	ErrorMessage  string     `json:"error_message,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// ScanModule tracks individual module execution inside a scan.
type ScanModule struct {
	ID           int64      `json:"id"`
	ScanID       int64      `json:"scan_id"`
	ModuleName   string     `json:"module_name"`
	Status       ScanStatus `json:"status"`
	StartTime    time.Time  `json:"start_time"`
	EndTime      *time.Time `json:"end_time,omitempty"`
	DurationMs   int64      `json:"duration_ms"`
	ErrorMessage string     `json:"error_message,omitempty"`
}

// Finding represents an identified security issue, observation, or configuration.
type Finding struct {
	ID                 int64      `json:"id"`
	ScanID             int64      `json:"scan_id"`
	ModuleName         string     `json:"module_name"`
	Title              string     `json:"title"`
	Description        string     `json:"description"`
	Severity           Severity   `json:"severity"`
	Confidence         Confidence `json:"confidence"`
	Category           string     `json:"category"`
	Host               string     `json:"host"`
	Port               int        `json:"port,omitempty"`
	Protocol           string     `json:"protocol,omitempty"`
	Evidence           string     `json:"evidence,omitempty"`
	Remediation        string     `json:"remediation,omitempty"`
	References         []string   `json:"references,omitempty"`
	VerificationStatus string     `json:"verification_status"`
	RawData            string     `json:"raw_data,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
}

// DiscoveredSubdomain records subdomains found during discovery.
type DiscoveredSubdomain struct {
	ID           int64     `json:"id"`
	ScanID       int64     `json:"scan_id"`
	Domain       string    `json:"domain"`
	Subdomain    string    `json:"subdomain"`
	ResolvedIPs  []string  `json:"resolved_ips"`
	StatusCode   int       `json:"status_code,omitempty"`
	Source       string    `json:"source"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// OpenPort records identified TCP ports and service banners.
type OpenPort struct {
	ID           int64     `json:"id"`
	ScanID       int64     `json:"scan_id"`
	Host         string    `json:"host"`
	Port         int       `json:"port"`
	Protocol     string    `json:"protocol"`
	State        string    `json:"state"`
	ServiceName  string    `json:"service_name,omitempty"`
	Banner       string    `json:"banner,omitempty"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// ScanProfile configures which modules run and their parameters.
type ScanProfile struct {
	Name           string   `json:"name" yaml:"name"`
	Description    string   `json:"description" yaml:"description"`
	Modules        []string `json:"modules" yaml:"modules"`
	TimeoutSeconds int      `json:"timeout_seconds" yaml:"timeout_seconds"`
	Concurrency    int      `json:"concurrency" yaml:"concurrency"`
	RateLimit      int      `json:"rate_limit" yaml:"rate_limit"`
	PortRange      string   `json:"port_range" yaml:"port_range"`
	IsDefault      bool     `json:"is_default" yaml:"is_default"`
}

// Template represents a declarative YAML vulnerability rule.
type Template struct {
	ID          string            `json:"id" yaml:"id"`
	Name        string            `json:"name" yaml:"name"`
	Description string            `json:"description" yaml:"description"`
	Severity    Severity          `json:"severity" yaml:"severity"`
	Category    string            `json:"category" yaml:"category"`
	TargetType  string            `json:"target_type" yaml:"target_type"`
	CheckType   string            `json:"check_type" yaml:"check_type"`
	Evidence    string            `json:"evidence" yaml:"evidence"`
	Remediation string            `json:"remediation" yaml:"remediation"`
	References  []string          `json:"references" yaml:"references"`
	Tags        []string          `json:"tags" yaml:"tags"`
	Metadata    map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// AppConfig defines global application configuration.
type AppConfig struct {
	App      AppMetaConfig  `yaml:"app"`
	Scope    ScopeConfig    `yaml:"scope"`
	Scanner  ScannerConfig  `yaml:"scanner"`
	Database DatabaseConfig `yaml:"database"`
	Reports  ReportsConfig  `yaml:"reports"`
	Profiles []ScanProfile  `yaml:"profiles"`
}

type AppMetaConfig struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Environment string `yaml:"environment"`
	LogLevel    string `yaml:"log_level"`
	NoColor     bool   `yaml:"no_color"`
}

type ScopeConfig struct {
	AllowPrivateIPs bool     `yaml:"allow_private_ips"`
	AllowLoopback   bool     `yaml:"allow_loopback"`
	AllowedDomains  []string `yaml:"allowed_domains"`
	AllowedCIDRs    []string `yaml:"allowed_cidrs"`
	BlockedDomains  []string `yaml:"blocked_domains"`
	BlockedCIDRs    []string `yaml:"blocked_cidrs"`
}

type ScannerConfig struct {
	DefaultProfile string `yaml:"default_profile"`
	GlobalTimeout  int    `yaml:"global_timeout"`
	ModuleTimeout  int    `yaml:"module_timeout"`
	MaxConcurrency int    `yaml:"max_concurrency"`
	RateLimitRPS   int    `yaml:"rate_limit_rps"`
	FollowRedirect bool   `yaml:"follow_redirect"`
	MaxRedirects   int    `yaml:"max_redirects"`
	UserAgent      string `yaml:"user_agent"`
}

type DatabaseConfig struct {
	Driver string `yaml:"driver"`
	Path   string `yaml:"path"`
}

type ReportsConfig struct {
	OutputDir   string `yaml:"output_dir"`
	AutoExport  bool   `yaml:"auto_export"`
	DefaultType string `yaml:"default_type"`
}
