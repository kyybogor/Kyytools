package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/kyybogor/Kyytools/internal/models"
	"gopkg.in/yaml.v3"
)

const (
	AppName    = "KyyTools Security Scanner"
	AppVersion = "1.0.0"
	DefaultDB  = "kyytools.db"
)

// DefaultProfiles returns predefined scan profiles.
func DefaultProfiles() []models.ScanProfile {
	return []models.ScanProfile{
		{
			Name:           "quick",
			Description:    "Pemeriksaan kilat: validasi respon target, DNS dasar, header web utama, dan 4 port krusial",
			Modules:        []string{"target_info", "dns_resolver", "web_headers", "port_scan_top"},
			TimeoutSeconds: 60,
			Concurrency:    10,
			RateLimit:      20,
			PortRange:      "80,443,8080,8443",
			IsDefault:      true,
		},
		{
			Name:           "standard",
			Description:    "Pemeriksaan seimbang: DNS, SSL/TLS, Security Headers, metode HTTP, CORS, dan 20 port umum",
			Modules:        []string{"target_info", "dns_resolver", "tls_check", "web_headers", "http_methods", "cors_check", "port_scan_standard"},
			TimeoutSeconds: 180,
			Concurrency:    25,
			RateLimit:      30,
			PortRange:      "21,22,25,53,80,110,143,443,465,587,993,995,3306,3389,5432,6379,8000,8080,8443,8888",
			IsDefault:      false,
		},
		{
			Name:           "web",
			Description:    "Audit mendalam aplikasi web: headers, cookie flags, CORS exploitability, metode HTTP (TRACE/PUT), paparan file sensitif (.env, .git, backup), dan engine template YAML",
			Modules:        []string{"target_info", "dns_resolver", "tls_check", "web_headers", "http_methods", "cors_check", "sensitive_files", "vuln_templates"},
			TimeoutSeconds: 300,
			Concurrency:    15,
			RateLimit:      25,
			PortRange:      "80,443,8000,8080,8443",
			IsDefault:      false,
		},
		{
			Name:           "network",
			Description:    "Pemeriksaan jaringan: resolusi host, port scan diperluas (100 port penting), dan service banner grabbing",
			Modules:        []string{"target_info", "dns_resolver", "port_scan_extended", "service_detection"},
			TimeoutSeconds: 300,
			Concurrency:    50,
			RateLimit:      50,
			PortRange:      "1-1024",
			IsDefault:      false,
		},
		{
			Name:           "custom",
			Description:    "Profil kustom fleksibel yang dapat disesuaikan pengguna",
			Modules:        []string{"target_info", "dns_resolver", "tls_check", "web_headers", "sensitive_files"},
			TimeoutSeconds: 120,
			Concurrency:    20,
			RateLimit:      25,
			PortRange:      "80,443",
			IsDefault:      false,
		},
	}
}

// DefaultConfig provides secure, out-of-the-box configuration.
func DefaultConfig() *models.AppConfig {
	return &models.AppConfig{
		App: models.AppMetaConfig{
			Name:        AppName,
			Version:     AppVersion,
			Environment: "production",
			LogLevel:    "info",
			NoColor:     false,
		},
		Scope: models.ScopeConfig{
			AllowPrivateIPs: false, // Default aman: tolak IP privat & loopback
			AllowLoopback:   false,
			AllowedDomains:  []string{},
			AllowedCIDRs:    []string{},
			BlockedDomains:  []string{"localhost"},
			BlockedCIDRs:    []string{"127.0.0.0/8", "169.254.0.0/16", "::1/128"},
		},
		Scanner: models.ScannerConfig{
			DefaultProfile: "quick",
			GlobalTimeout:  300,
			ModuleTimeout:  30,
			MaxConcurrency: 50,
			RateLimitRPS:   30,
			FollowRedirect: false, // Aman dari SSRF redirect
			MaxRedirects:   3,
			UserAgent:      "KyyTools-Security-Scanner/1.0.0 (+https://github.com/kyybogor/Kyytools)",
		},
		Database: models.DatabaseConfig{
			Driver: "sqlite",
			Path:   DefaultDB,
		},
		Reports: models.ReportsConfig{
			OutputDir:   "reports",
			AutoExport:  true,
			DefaultType: "html",
		},
		Profiles: DefaultProfiles(),
	}
}

// LoadConfig reads configuration from file or generates default if missing.
func LoadConfig(configPath string) (*models.AppConfig, error) {
	cfg := DefaultConfig()

	if configPath == "" {
		configPath = filepath.Join("configs", "config.yaml")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Write default configuration file
			if err := SaveConfig(configPath, cfg); err != nil {
				return cfg, fmt.Errorf("gagal membuat config default di %s: %w", configPath, err)
			}
			return cfg, nil
		}
		return nil, fmt.Errorf("gagal membaca file config %s: %w", configPath, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("format YAML config tidak valid di %s: %w", configPath, err)
	}

	// Ensure default profiles are populated if empty
	if len(cfg.Profiles) == 0 {
		cfg.Profiles = DefaultProfiles()
	}

	return cfg, nil
}

// SaveConfig persists the current configuration to disk.
func SaveConfig(configPath string, cfg *models.AppConfig) error {
	dir := filepath.Dir(configPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0644)
}

// GetProfile finds a profile by name.
func GetProfile(cfg *models.AppConfig, name string) (*models.ScanProfile, error) {
	for i := range cfg.Profiles {
		if cfg.Profiles[i].Name == name {
			return &cfg.Profiles[i], nil
		}
	}
	return nil, fmt.Errorf("profil scan '%s' tidak ditemukan", name)
}
