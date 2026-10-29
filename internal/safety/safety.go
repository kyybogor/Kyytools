package safety

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kyytools/kyytools/internal/models"
)

var (
	ErrLoopbackRejected = errors.New("target mengarah ke alamat loopback (localhost) yang ditolak secara default demi keamanan")
	ErrPrivateRejected  = errors.New("target mengarah ke alamat IP privat/internal (RFC 1918/ULA) yang ditolak secara default")
	ErrReservedRejected = errors.New("target mengarah ke alamat khusus/reserved IP (link-local, cloud metadata, multicast)")
	ErrOutOfScope       = errors.New("target berada di luar scope allowlist yang dikonfigurasi")
	ErrBlockedExplicit  = errors.New("target secara eksplisit diblokir dalam konfigurasi scope")
	ErrEmptyTarget      = errors.New("target tidak boleh kosong")
	ErrInvalidPort      = errors.New("port target berada di luar rentang valid (1-65535)")
	ErrSSRFRedirect     = errors.New("redirect dicegah: upaya redirect mengarah ke alamat di luar scope atau IP privat")
)

var reservedCIDRs = []struct {
	cidr *net.IPNet
	name string
}{
	{parseCIDR("127.0.0.0/8"), "IPv4 Loopback"},
	{parseCIDR("::1/128"), "IPv6 Loopback"},
	{parseCIDR("10.0.0.0/8"), "IPv4 Private RFC 1918"},
	{parseCIDR("172.16.0.0/12"), "IPv4 Private RFC 1918"},
	{parseCIDR("192.168.0.0/16"), "IPv4 Private RFC 1918"},
	{parseCIDR("fc00::/7"), "IPv6 Unique Local (ULA)"},
	{parseCIDR("169.254.0.0/16"), "IPv4 Link-Local / Cloud Metadata"},
	{parseCIDR("fe80::/10"), "IPv6 Link-Local"},
	{parseCIDR("224.0.0.0/4"), "IPv4 Multicast"},
	{parseCIDR("ff00::/8"), "IPv6 Multicast"},
	{parseCIDR("0.0.0.0/8"), "IPv4 Current Network / Broadcast"},
	{parseCIDR("100.64.0.0/10"), "IPv4 Carrier-Grade NAT"},
}

func parseCIDR(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(fmt.Sprintf("invalid static CIDR %s: %v", s, err))
	}
	return ipnet
}

// ScopeValidator enforces security guardrails and scope boundaries.
type ScopeValidator struct {
	config models.ScopeConfig
}

// NewScopeValidator creates a validator with the given scope config.
func NewScopeValidator(cfg models.ScopeConfig) *ScopeValidator {
	return &ScopeValidator{config: cfg}
}

// CheckIPClassification checks if an IP is loopback, private, or reserved.
func CheckIPClassification(ip net.IP) (isLoopback bool, isPrivate bool, isReserved bool, label string) {
	if ip == nil {
		return false, false, false, "Invalid"
	}

	if ip.IsLoopback() {
		return true, false, false, "Loopback"
	}

	for _, item := range reservedCIDRs {
		if item.cidr.Contains(ip) {
			if strings.Contains(item.name, "Loopback") {
				return true, false, false, item.name
			}
			if strings.Contains(item.name, "Private") {
				return false, true, false, item.name
			}
			return false, false, true, item.name
		}
	}

	return false, false, false, "Public"
}

// ValidateIP verifies if a single IP satisfies the configured scope policies.
func (v *ScopeValidator) ValidateIP(ip net.IP) error {
	if ip == nil {
		return errors.New("IP tidak valid")
	}

	isLoopback, isPrivate, isReserved, label := CheckIPClassification(ip)

	// Blocked explicitly
	for _, blockedCIDR := range v.config.BlockedCIDRs {
		_, ipnet, err := net.ParseCIDR(blockedCIDR)
		if err == nil && ipnet.Contains(ip) {
			return fmt.Errorf("%w: IP %s cocok dengan daftar blokir %s", ErrBlockedExplicit, ip.String(), blockedCIDR)
		}
	}

	// Loopback validation
	if isLoopback && !v.config.AllowLoopback {
		return fmt.Errorf("%w: %s (%s)", ErrLoopbackRejected, ip.String(), label)
	}

	// Private IP validation
	if isPrivate && !v.config.AllowPrivateIPs {
		return fmt.Errorf("%w: %s (%s)", ErrPrivateRejected, ip.String(), label)
	}

	// Reserved IP validation (always blocked unless loopback/private explicitly allowed)
	if isReserved && !v.config.AllowPrivateIPs {
		return fmt.Errorf("%w: %s (%s)", ErrReservedRejected, ip.String(), label)
	}

	// Allowed CIDR check (if allowlist provided, IP must match at least one)
	if len(v.config.AllowedCIDRs) > 0 {
		matched := false
		for _, allowedCIDR := range v.config.AllowedCIDRs {
			_, ipnet, err := net.ParseCIDR(allowedCIDR)
			if err == nil && ipnet.Contains(ip) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%w: IP %s tidak berada dalam daftar CIDR yang diizinkan", ErrOutOfScope, ip.String())
		}
	}

	return nil
}

// ValidateResolvedIPs ensures ALL resolved DNS IP addresses pass scope checks (Anti-DNS Rebinding / SSRF).
func (v *ScopeValidator) ValidateResolvedIPs(ips []net.IP) error {
	if len(ips) == 0 {
		return errors.New("tidak ada alamat IP yang berhasil diresolusi")
	}

	for _, ip := range ips {
		if err := v.ValidateIP(ip); err != nil {
			return fmt.Errorf("resolusi DNS mengandung IP terlarang: %w", err)
		}
	}

	return nil
}

// ValidateHostname checks hostnames against allowed and blocked domain rules.
func (v *ScopeValidator) ValidateHostname(hostname string) error {
	cleanHost := strings.ToLower(strings.TrimSpace(hostname))
	if cleanHost == "" {
		return ErrEmptyTarget
	}

	// Check blocked domains
	for _, blocked := range v.config.BlockedDomains {
		b := strings.ToLower(strings.TrimSpace(blocked))
		if cleanHost == b || strings.HasSuffix(cleanHost, "."+b) {
			return fmt.Errorf("%w: %s terdaftar di blocked_domains", ErrBlockedExplicit, cleanHost)
		}
	}

	// Check allowed domains (if specified)
	if len(v.config.AllowedDomains) > 0 {
		matched := false
		for _, allowed := range v.config.AllowedDomains {
			a := strings.ToLower(strings.TrimSpace(allowed))
			if strings.HasPrefix(a, "*.") {
				root := strings.TrimPrefix(a, "*.")
				if cleanHost == root || strings.HasSuffix(cleanHost, "."+root) {
					matched = true
					break
				}
			} else if cleanHost == a || strings.HasSuffix(cleanHost, "."+a) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%w: domain %s tidak termasuk dalam allowed_domains", ErrOutOfScope, cleanHost)
		}
	}

	return nil
}

// CreateSafeHTTPClient builds an http.Client bound to pre-validated IP checks with SSRF & redirect protection.
func (v *ScopeValidator) CreateSafeHTTPClient(timeout time.Duration, followRedirect bool, maxRedirects int) *http.Client {
	if maxRedirects <= 0 {
		maxRedirects = 3
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			// Validate IP or resolve and validate all IPs
			if ip := net.ParseIP(host); ip != nil {
				if err := v.ValidateIP(ip); err != nil {
					return nil, err
				}
			} else {
				ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
				if err != nil {
					return nil, fmt.Errorf("resolusi DNS gagal: %w", err)
				}
				if err := v.ValidateResolvedIPs(ips); err != nil {
					return nil, err
				}
				// Bind to the first valid IP
				addr = net.JoinHostPort(ips[0].String(), port)
			}

			return dialer.DialContext(ctx, network, addr)
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	if !followRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("batas redirect (%d) tercapai", maxRedirects)
			}

			// Validate target domain and IP of redirect
			host := req.URL.Hostname()
			if ip := net.ParseIP(host); ip != nil {
				if err := v.ValidateIP(ip); err != nil {
					return fmt.Errorf("%w: redirect ke IP %s ditolak: %v", ErrSSRFRedirect, ip.String(), err)
				}
			} else {
				if err := v.ValidateHostname(host); err != nil {
					return fmt.Errorf("%w: redirect ke host %s ditolak: %v", ErrSSRFRedirect, host, err)
				}
			}

			return nil
		}
	}

	return client
}
