package tests

import (
	"net"
	"testing"

	"github.com/kyytools/kyytools/internal/models"
	"github.com/kyytools/kyytools/internal/safety"
)

func TestScopeValidator_Rejections(t *testing.T) {
	cfg := models.ScopeConfig{
		AllowPrivateIPs: false,
		AllowLoopback:   false,
		BlockedDomains:  []string{"localhost", "internal.corp"},
		BlockedCIDRs:    []string{"127.0.0.0/8", "169.254.0.0/16"},
	}

	val := safety.NewScopeValidator(cfg)

	// 1. Loopback IP test
	ipLoopback := net.ParseIP("127.0.0.1")
	if err := val.ValidateIP(ipLoopback); err == nil {
		t.Errorf("diharapkan loopback 127.0.0.1 ditolak, tetapi lolos")
	}

	// 2. Private IP test
	ipPrivate := net.ParseIP("192.168.1.100")
	if err := val.ValidateIP(ipPrivate); err == nil {
		t.Errorf("diharapkan IP privat 192.168.1.100 ditolak, tetapi lolos")
	}

	ipPrivate10 := net.ParseIP("10.0.0.1")
	if err := val.ValidateIP(ipPrivate10); err == nil {
		t.Errorf("diharapkan IP privat 10.0.0.1 ditolak, tetapi lolos")
	}

	// 3. Link-local / Cloud metadata test
	ipMetadata := net.ParseIP("169.254.169.254")
	if err := val.ValidateIP(ipMetadata); err == nil {
		t.Errorf("diharapkan link-local/cloud metadata ditolak, tetapi lolos")
	}

	// 4. Blocked hostname test
	if err := val.ValidateHostname("localhost"); err == nil {
		t.Errorf("diharapkan hostname 'localhost' ditolak, tetapi lolos")
	}

	if err := val.ValidateHostname("sub.internal.corp"); err == nil {
		t.Errorf("diharapkan domain 'sub.internal.corp' ditolak, tetapi lolos")
	}

	// 5. Public IP test
	ipPublic := net.ParseIP("93.184.216.34")
	if err := val.ValidateIP(ipPublic); err != nil {
		t.Errorf("diharapkan IP publik 93.184.216.34 diizinkan, tetapi error: %v", err)
	}
}

func TestScopeValidator_Allowlist(t *testing.T) {
	cfg := models.ScopeConfig{
		AllowPrivateIPs: false,
		AllowLoopback:   false,
		AllowedDomains:  []string{"*.example.com", "mycompany.org"},
		AllowedCIDRs:    []string{"203.0.113.0/24"},
	}

	val := safety.NewScopeValidator(cfg)

	// In-scope domain
	if err := val.ValidateHostname("app.example.com"); err != nil {
		t.Errorf("diharapkan app.example.com diizinkan, namun error: %v", err)
	}

	// Out-of-scope domain
	if err := val.ValidateHostname("attacker.com"); err == nil {
		t.Errorf("diharapkan attacker.com ditolak karena tidak ada di allowlist")
	}

	// In-scope CIDR
	if err := val.ValidateIP(net.ParseIP("203.0.113.45")); err != nil {
		t.Errorf("diharapkan 203.0.113.45 diizinkan, namun error: %v", err)
	}

	// Out-of-scope CIDR
	if err := val.ValidateIP(net.ParseIP("198.51.100.1")); err == nil {
		t.Errorf("diharapkan 198.51.100.1 ditolak karena di luar allowed CIDRs")
	}
}
