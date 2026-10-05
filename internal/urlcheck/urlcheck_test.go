package urlcheck

import (
	"context"
	"errors"
	"net"
	"testing"
)

func fakeLookup(m map[string][]string) Lookup {
	return func(_ context.Context, host string) ([]net.IP, error) {
		addrs, ok := m[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		var ips []net.IP
		for _, a := range addrs {
			ips = append(ips, net.ParseIP(a))
		}
		return ips, nil
	}
}

func TestCheck(t *testing.T) {
	lookup := fakeLookup(map[string][]string{
		"server":         {"172.18.0.2"},
		"lab.internal":   {"10.1.2.3", "fd00::5"},
		"mixed.example":  {"10.0.0.1", "93.184.216.34"},
		"public.example": {"93.184.216.34"},
		"v6.public":      {"2001:db8::1"},
		"empty.example":  {},
	})
	cases := []struct {
		url       string
		ok        bool
		rule      bool // expected failure is a RuleError (permanent)
		normalize string
	}{
		{"https://routini.example.com", true, false, "https://routini.example.com"},
		{"https://routini.example.com/", true, false, "https://routini.example.com"},
		{"https://example.com/routini/", true, false, "https://example.com/routini"},
		{"HTTPS://example.com", true, false, "https://example.com"},
		{"wss://public.example", true, false, "wss://public.example"},
		{"https://unresolvable.example", true, false, "https://unresolvable.example"}, // no DNS needed for TLS
		{"http://localhost:3001", true, false, ""},
		{"http://LOCALHOST", true, false, ""},
		{"http://127.0.0.1:3001", true, false, ""},
		{"http://127.9.9.9", true, false, ""},
		{"http://10.0.0.5", true, false, ""},
		{"http://172.16.0.1", true, false, ""},
		{"http://172.31.255.255", true, false, ""},
		{"http://192.168.1.10:8080", true, false, ""},
		{"http://[::1]:3001", true, false, ""},
		{"http://[fd12:3456::1]", true, false, ""},
		{"http://[fe80::1]", true, false, ""},
		{"ws://10.0.0.5", true, false, ""},
		{"http://server:3001", true, false, ""},
		{"http://lab.internal", true, false, ""},
		{"http://172.32.0.1", false, true, ""},
		{"http://172.15.255.255", false, true, ""},
		{"http://8.8.8.8", false, true, ""},
		{"http://[2001:db8::1]", false, true, ""},
		{"http://[::ffff:8.8.8.8]", false, true, ""},
		{"http://public.example", false, true, ""},
		{"http://mixed.example", false, true, ""},
		{"http://v6.public", false, true, ""},
		{"ws://public.example", false, true, ""},
		{"http://unresolvable.example", false, false, ""},
		{"http://empty.example", false, false, ""},
		{"ftp://example.com", false, true, ""},
		{"example.com", false, true, ""},
		{"", false, true, ""},
		{"https://user:pass@example.com", false, true, ""},
		{"https://example.com/?x=1", false, true, ""},
		{"https://", false, true, ""},
	}
	for _, tc := range cases {
		u, err := CheckWith(context.Background(), tc.url, lookup)
		if tc.ok {
			if err != nil {
				t.Errorf("%q: unexpected error: %v", tc.url, err)
				continue
			}
			if tc.normalize != "" && u.String() != tc.normalize {
				t.Errorf("%q: normalised to %q, want %q", tc.url, u.String(), tc.normalize)
			}
			continue
		}
		if err == nil {
			t.Errorf("%q: expected an error", tc.url)
			continue
		}
		if IsRuleError(err) != tc.rule {
			t.Errorf("%q: IsRuleError=%v, want %v (err: %v)", tc.url, IsRuleError(err), tc.rule, err)
		}
	}
}

func TestDeriveURLs(t *testing.T) {
	cases := []struct{ base, ws, http string }{
		{"https://routini.example.com", "wss://routini.example.com/api/runner/connect", "https://routini.example.com/api/runner/enroll"},
		{"http://server:3001", "ws://server:3001/api/runner/connect", "http://server:3001/api/runner/enroll"},
		{"https://example.com/routini/", "wss://example.com/routini/api/runner/connect", "https://example.com/routini/api/runner/enroll"},
		{"wss://example.com/r", "wss://example.com/r/api/runner/connect", "https://example.com/r/api/runner/enroll"},
		{"ws://10.0.0.1:80", "ws://10.0.0.1:80/api/runner/connect", "http://10.0.0.1:80/api/runner/enroll"},
	}
	for _, tc := range cases {
		u, err := Parse(tc.base)
		if err != nil {
			t.Fatalf("%q: %v", tc.base, err)
		}
		if got := WSURL(u, "/api/runner/connect"); got != tc.ws {
			t.Errorf("WSURL(%q) = %q, want %q", tc.base, got, tc.ws)
		}
		if got := HTTPURL(u, "/api/runner/enroll"); got != tc.http {
			t.Errorf("HTTPURL(%q) = %q, want %q", tc.base, got, tc.http)
		}
		if u.String() != tc.base && u.String()+"/" != tc.base {
			t.Errorf("Parse(%q) changed the base to %q", tc.base, u.String())
		}
	}
}

func TestGuardedDialRefusesPublic(t *testing.T) {
	dial := GuardedDialContext(&net.Dialer{}, fakeLookup(map[string][]string{"public.example": {"93.184.216.34"}}))
	_, err := dial(context.Background(), "tcp", "public.example:80")
	if !IsRuleError(err) {
		t.Fatalf("expected a rule error, got %v", err)
	}
	_, err = dial(context.Background(), "tcp", "8.8.8.8:80")
	if !IsRuleError(err) {
		t.Fatalf("expected a rule error for a public IP literal, got %v", err)
	}
}

func TestIsPrivateIP(t *testing.T) {
	for _, s := range []string{"10.0.0.1", "172.16.5.4", "192.168.0.1", "127.0.0.1", "::1", "fc00::1", "fdff::1", "fe80::1", "::ffff:10.0.0.1"} {
		if !IsPrivateIP(net.ParseIP(s)) {
			t.Errorf("%s should be private", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "100.64.0.1", "169.254.1.1", "2001:db8::1", "fec0::1", "0.0.0.0"} {
		if IsPrivateIP(net.ParseIP(s)) {
			t.Errorf("%s should not be private", s)
		}
	}
}
