package target

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kyybogor/Kyytools/internal/models"
	"github.com/kyybogor/Kyytools/internal/safety"
)

// Parser parses and validates scan targets.
type Parser struct {
	validator *safety.ScopeValidator
}

// NewParser creates a new Target Parser.
func NewParser(validator *safety.ScopeValidator) *Parser {
	return &Parser{validator: validator}
}

// Parse extracts, normalizes, validates, and classifies a target string.
func (p *Parser) Parse(ctx context.Context, input string) (*models.Target, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return nil, errors.New("input target tidak boleh kosong")
	}

	target := &models.Target{
		RawInput:  raw,
		CreatedAt: time.Now(),
	}

	var host string
	var port int
	var scheme string
	var isURL bool

	// Check if input starts with a scheme
	if strings.HasPrefix(strings.ToLower(raw), "http://") || strings.HasPrefix(strings.ToLower(raw), "https://") {
		isURL = true
		parsedURL, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("URL tidak valid: %w", err)
		}

		scheme = strings.ToLower(parsedURL.Scheme)
		host = parsedURL.Hostname()
		portStr := parsedURL.Port()

		if portStr != "" {
			pVal, err := strconv.Atoi(portStr)
			if err != nil || pVal < 1 || pVal > 65535 {
				return nil, fmt.Errorf("port URL '%s' tidak valid", portStr)
			}
			port = pVal
		} else {
			if scheme == "https" {
				port = 443
			} else {
				port = 80
			}
		}

		target.Type = models.TargetTypeURL
		target.CanonicalURL = fmt.Sprintf("%s://%s", scheme, parsedURL.Host)
		if parsedURL.Path != "" && parsedURL.Path != "/" {
			target.CanonicalURL += parsedURL.Path
		}
	} else {
		// Might be host:port or pure host/IP
		if strings.Contains(raw, ":") && !strings.Contains(raw, "::") {
			// IPv4 with port or hostname with port
			h, pStr, err := net.SplitHostPort(raw)
			if err == nil {
				host = h
				pVal, err := strconv.Atoi(pStr)
				if err != nil || pVal < 1 || pVal > 65535 {
					return nil, fmt.Errorf("port '%s' tidak valid", pStr)
				}
				port = pVal
			} else {
				// Might be IPv6 without brackets
				host = raw
			}
		} else {
			host = raw
		}
	}

	// Classify host as IPv4, IPv6, or Domain
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() != nil {
			if !isURL {
				target.Type = models.TargetTypeIPv4
			}
		} else {
			if !isURL {
				target.Type = models.TargetTypeIPv6
			}
		}
	} else {
		if !isURL {
			target.Type = models.TargetTypeDomain
		}
	}

	// Scope validation on Hostname
	if err := p.validator.ValidateHostname(host); err != nil {
		return nil, err
	}

	// Resolve IPs if domain, or validate single IP
	var resolvedIPStrs []string
	if ip != nil {
		if err := p.validator.ValidateIP(ip); err != nil {
			return nil, err
		}
		resolvedIPStrs = append(resolvedIPStrs, ip.String())
	} else {
		// Resolve domain DNS
		dnsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		ips, err := net.DefaultResolver.LookupIP(dnsCtx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("gagal meresolusi domain '%s': %w", host, err)
		}

		if len(ips) == 0 {
			return nil, fmt.Errorf("domain '%s' tidak memiliki record DNS IP", host)
		}

		// Validate ALL resolved IPs against scope policies (SSRF / DNS rebinding defense)
		if err := p.validator.ValidateResolvedIPs(ips); err != nil {
			return nil, err
		}

		for _, item := range ips {
			resolvedIPStrs = append(resolvedIPStrs, item.String())
		}
	}

	// Assign defaults if port not specified
	if port == 0 {
		if scheme == "https" {
			port = 443
		} else if scheme == "http" {
			port = 80
		} else {
			port = 80 // Default to standard web port for general targets
		}
	}

	if scheme == "" {
		if port == 443 || port == 8443 {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	if target.CanonicalURL == "" {
		if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
			target.CanonicalURL = fmt.Sprintf("%s://%s", scheme, host)
		} else {
			target.CanonicalURL = fmt.Sprintf("%s://%s:%d", scheme, host, port)
		}
	}

	target.Host = host
	target.Port = port
	target.Scheme = scheme
	target.ResolvedIPs = resolvedIPStrs

	return target, nil
}
