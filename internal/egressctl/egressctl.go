// Package egressctl talks to the routini-egress container's control API: it
// opens and closes the per-task or per-environment egress session and reads
// the proxy's CA certificate (PROTOCOL.md sections 2.6 and 2.8, step 3).
//
// Every call is authenticated with the egress secret shared between the
// runner and that one container. Neither the secret nor the session token
// ever reaches an error message: the token is the password the agent or
// environment container uses on the proxy.
package egressctl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Paths of the egress control API.
const (
	SessionsPath = "/sessions/"
	CAPath       = "/ca"

	// DefaultTimeout bounds one call to the control API, which is a local
	// process reached over loopback.
	DefaultTimeout = 10 * time.Second

	// maxBody bounds how much of a control response is read. The CA PEM is
	// the largest of them by far.
	maxBody = 1 << 20
)

// Stats are the session counters the egress proxy reports when the session
// is closed.
type Stats struct {
	Requests    int      `json:"requests"`
	Intercepted int      `json:"intercepted"`
	Blocked     []string `json:"blocked"`
}

// Client talks to one routini-egress container's control API.
type Client struct {
	base   string
	secret string
	client *http.Client
}

// New validates the control URL EnsureEgress reported. dockerx binds that API
// to loopback only, so any other host means the container has been tampered
// with and no session is opened on it. A nil client defaults to
// DefaultHTTPClient.
func New(rawURL, secret string, client *http.Client) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("egress control URL is not a URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("egress control URL has scheme %q, want http or https", u.Scheme)
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("egress control URL host %q is not a loopback address", u.Hostname())
	}
	if secret == "" {
		return nil, errors.New("egress secret is missing")
	}
	if client == nil {
		client = DefaultHTTPClient()
	}
	return &Client{base: strings.TrimRight(rawURL, "/"), secret: secret, client: client}, nil
}

// DefaultHTTPClient returns the client used when no client is given to New.
// Redirects are refused: the control API is local, and following one
// elsewhere would hand the egress secret to another host.
func DefaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: DefaultTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("the egress control API must not redirect")
		},
	}
}

// OpenSession registers the session with the proxy, which is what gives the
// token its meaning. session is forwarded untouched.
func (c *Client) OpenSession(ctx context.Context, token string, session json.RawMessage) error {
	return c.do(ctx, http.MethodPut, SessionsPath+token, session, nil, "open egress session")
}

// CA returns the proxy's CA in PEM form, which the agent or environment
// container needs to trust the intercepted TLS connections.
func (c *Client) CA(ctx context.Context) (string, error) {
	var out struct {
		PEM string `json:"pem"`
	}
	if err := c.do(ctx, http.MethodGet, CAPath, nil, &out, "read egress CA"); err != nil {
		return "", err
	}
	if out.PEM == "" {
		return "", errors.New("read egress CA: the egress control server returned no pem")
	}
	return out.PEM, nil
}

// CloseSession drops the session, and with it the real credentials in the
// proxy's memory, and returns the counters it reports.
func (c *Client) CloseSession(ctx context.Context, token string) (*Stats, error) {
	var out Stats
	if err := c.do(ctx, http.MethodDelete, SessionsPath+token, nil, &out, "close egress session"); err != nil {
		return nil, err
	}
	return &out, nil
}

// do performs one control API call. what names the step in errors, which
// never include the request URL, the request body or the response body: all
// three can carry a secret.
func (c *Client) do(ctx context.Context, method, path string, body []byte, out any, what string) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return fmt.Errorf("%s: %w", what, redactURL(err))
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", what, redactURL(err))
	}
	defer func() {
		// Draining lets the connection be reused for the next call.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s: the egress control server answered %s", what, resp.Status)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(out); err != nil {
		return fmt.Errorf("%s: decode the egress control server's answer: %w", what, redactURL(err))
	}
	return nil
}

// redactURL strips the request URL from an *url.Error, because the path of a
// session call carries the session token.
func redactURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", strings.ToLower(ue.Op), ue.Err)
	}
	return err
}
