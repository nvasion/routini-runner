// Package urlcheck enforces the runner's transport rule for the Routini URL.
//
// https and wss are always allowed. http and ws are allowed only when the
// host is "localhost", a loopback or private IP literal, or a host name that
// resolves only to loopback or private addresses (for example a Docker
// service name such as http://server:3001).
package urlcheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// RuleError reports a URL that violates the transport rule or is malformed.
// It is permanent: retrying will not help.
type RuleError struct{ Msg string }

func (e *RuleError) Error() string { return e.Msg }

func ruleErr(format string, args ...any) error {
	return &RuleError{Msg: fmt.Sprintf(format, args...)}
}

// IsRuleError reports whether err (or an error it wraps) is a RuleError.
func IsRuleError(err error) bool {
	var re *RuleError
	return errors.As(err, &re)
}

// Lookup resolves a host name to its IP addresses.
type Lookup func(ctx context.Context, host string) ([]net.IP, error)

// DefaultLookup resolves with net.DefaultResolver.
func DefaultLookup(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

var privateNets = func() []*net.IPNet {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}()

// IsPrivateIP reports whether ip is loopback or private per the runner rule:
// 10/8, 172.16/12, 192.168/16, 127/8, ::1, fc00::/7 and fe80::/10.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// IsPlaintext reports whether the URL uses an unencrypted scheme (http or ws).
func IsPlaintext(u *url.URL) bool {
	return u.Scheme == "http" || u.Scheme == "ws"
}

func isLocalhostName(host string) bool {
	return strings.EqualFold(strings.TrimSuffix(host, "."), "localhost")
}

// Parse validates the base URL's syntax and returns it normalised: lower-case
// scheme and no trailing slash on the path. It does not apply the
// plaintext rule; use Check for that.
func Parse(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ruleErr("URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, ruleErr("invalid URL %q: %v", raw, err)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	switch u.Scheme {
	case "http", "https", "ws", "wss":
	default:
		return nil, ruleErr("invalid URL %q: scheme must be https (or http for private addresses)", raw)
	}
	if u.Hostname() == "" {
		return nil, ruleErr("invalid URL %q: missing host", raw)
	}
	if u.User != nil {
		return nil, ruleErr("invalid URL: it must not contain a user name or password")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, ruleErr("invalid URL %q: it must not contain a query or fragment", raw)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = strings.TrimRight(u.RawPath, "/")
	return u, nil
}

// Check parses raw and enforces the transport rule, resolving host names
// with the system resolver.
func Check(ctx context.Context, raw string) (*url.URL, error) {
	return CheckWith(ctx, raw, DefaultLookup)
}

// CheckWith is Check with an explicit resolver. A rule violation is returned
// as a *RuleError; a failed lookup is returned as an ordinary error.
func CheckWith(ctx context.Context, raw string, lookup Lookup) (*url.URL, error) {
	u, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	if !IsPlaintext(u) {
		return u, nil
	}
	if err := checkPlainHost(ctx, u.Hostname(), lookup); err != nil {
		return nil, err
	}
	return u, nil
}

func checkPlainHost(ctx context.Context, host string, lookup Lookup) error {
	if isLocalhostName(host) {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if IsPrivateIP(ip) {
			return nil
		}
		return ruleErr("refusing plain http/ws to public address %s: use https, or a loopback/private address", host)
	}
	ips, err := lookup(ctx, host)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("resolve %s: no addresses", host)
	}
	for _, ip := range ips {
		if !IsPrivateIP(ip) {
			return ruleErr("refusing plain http/ws to %s: it resolves to public address %s; use https", host, ip)
		}
	}
	return nil
}

// GuardedDialContext returns a DialContext for plaintext URLs that resolves
// the host itself and only connects to loopback or private addresses. It
// closes the gap between Check and the actual connection (DNS can change).
func GuardedDialContext(d *net.Dialer, lookup Lookup) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if lookup == nil {
		lookup = DefaultLookup
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if isLocalhostName(host) {
			return d.DialContext(ctx, network, addr)
		}
		var ips []net.IP
		if ip := net.ParseIP(host); ip != nil {
			ips = []net.IP{ip}
		} else {
			ips, err = lookup(ctx, host)
			if err != nil {
				return nil, err
			}
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("resolve %s: no addresses", host)
		}
		for _, ip := range ips {
			if !IsPrivateIP(ip) {
				return nil, ruleErr("refusing plain http/ws to %s: it resolves to public address %s; use https", host, ip)
			}
		}
		var lastErr error
		for _, ip := range ips {
			c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return c, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

// Join returns base with path appended to its (possibly empty) path prefix,
// keeping the scheme.
func Join(base *url.URL, path string) *url.URL {
	u := *base
	u.Path = strings.TrimRight(base.Path, "/") + path
	if base.RawPath != "" {
		u.RawPath = strings.TrimRight(base.RawPath, "/") + path
	}
	return &u
}

// HTTPURL returns the http(s) form of base joined with path
// (ws becomes http, wss becomes https).
func HTTPURL(base *url.URL, path string) string {
	u := Join(base, path)
	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	}
	return u.String()
}

// WSURL returns the ws(s) form of base joined with path
// (http becomes ws, https becomes wss).
func WSURL(base *url.URL, path string) string {
	u := Join(base, path)
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	}
	return u.String()
}
