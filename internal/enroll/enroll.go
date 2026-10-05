// Package enroll exchanges a single-use enrollment token for a runner
// credential (PROTOCOL.md section 1).
package enroll

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nvasion/routini-runner/internal/urlcheck"
)

// TokenPrefix is the prefix of every enrollment token.
const TokenPrefix = "rre_"

// Path is the enrollment endpoint, relative to the base URL.
const Path = "/api/runner/enroll"

// Request is the enrollment request body.
type Request struct {
	Token    string `json:"token"`
	Name     string `json:"name,omitempty"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Version  string `json:"version"`
}

// Response is the 201 response body.
type Response struct {
	RunnerID   string `json:"runnerId"`
	Credential string `json:"credential"`
	HostID     string `json:"hostId"`
	Name       string `json:"name"`
	Org        string `json:"org"`
}

// ErrTokenRejected is returned (wrapped) when the server answers 401.
var ErrTokenRejected = errors.New("enrollment token rejected: it is unknown, expired or already used")

// NewHTTPClient returns a client for base that verifies TLS with tlsCfg,
// never follows redirects (so the token is only sent to the configured URL)
// and, for plaintext URLs, connects only to loopback or private addresses.
func NewHTTPClient(base *url.URL, tlsCfg *tls.Config, lookup urlcheck.Lookup) *http.Client {
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		TLSClientConfig:     tlsCfg,
		DialContext:         dialer.DialContext,
		TLSHandshakeTimeout: 15 * time.Second,
		ForceAttemptHTTP2:   true,
		Proxy:               http.ProxyFromEnvironment,
	}
	if urlcheck.IsPlaintext(base) {
		tr.Proxy = nil
		tr.DialContext = urlcheck.GuardedDialContext(dialer, lookup)
	}
	return &http.Client{
		Transport: tr,
		Timeout:   60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Enroll posts req to {base}/api/runner/enroll and returns the server's answer.
func Enroll(ctx context.Context, client *http.Client, base *url.URL, req Request) (*Response, error) {
	if !strings.HasPrefix(req.Token, TokenPrefix) {
		return nil, fmt.Errorf("enrollment token must start with %q", TokenPrefix)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	endpoint := urlcheck.HTTPURL(base, Path)
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("Accept", "application/json")

	resp, err := client.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch {
	case resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK:
		var out Response
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("enroll: invalid response from server: %w", err)
		}
		if out.Credential == "" || out.RunnerID == "" {
			return nil, errors.New("enroll: server response is missing runnerId or credential")
		}
		return &out, nil
	case resp.StatusCode == http.StatusUnauthorized:
		if msg := serverError(raw); msg != "" {
			return nil, fmt.Errorf("%w (server said: %s)", ErrTokenRejected, msg)
		}
		return nil, ErrTokenRejected
	case resp.StatusCode == http.StatusBadRequest:
		return nil, fmt.Errorf("enroll: server rejected the request (400): %s", orStatus(serverError(raw), resp.Status))
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return nil, fmt.Errorf("enroll: server answered %s with a redirect to %q; redirects are not followed, check the URL", resp.Status, resp.Header.Get("Location"))
	default:
		return nil, fmt.Errorf("enroll: unexpected response %s: %s", resp.Status, orStatus(serverError(raw), "no details"))
	}
}

// serverError extracts {"error": "..."} from a response body, sanitised to
// one short line.
func serverError(raw []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &e) != nil || e.Error == "" {
		return ""
	}
	return OneLine(e.Error, 200)
}

func orStatus(msg, fallback string) string {
	if msg == "" {
		return fallback
	}
	return msg
}

// OneLine collapses whitespace (including newlines) and truncates s to max runes.
func OneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) > max {
		return string(r[:max]) + "..."
	}
	return s
}
