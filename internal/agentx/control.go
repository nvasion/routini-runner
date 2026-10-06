package agentx

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

// Paths of the egress control API (PROTOCOL.md 2.6 step 3).
const (
	sessionsPath = "/sessions/"
	caPath       = "/ca"

	// DefaultControlTimeout bounds one call to the control API, which is a
	// local process reached over loopback.
	DefaultControlTimeout = 10 * time.Second

	// maxControlBody bounds how much of a control response is read. The CA
	// PEM is the largest of them by far.
	maxControlBody = 1 << 20
)

// control talks to the routini-egress container's control API. Every call is
// authenticated with the egress secret, and neither the secret nor the
// session token ever reaches an error message: the token is the password the
// agent container uses on the proxy.
type control struct {
	base   string
	secret string
	client *http.Client
}

// newControl validates the control URL EnsureEgress reported. dockerx binds
// that API to loopback only, so any other host means the container has been
// tampered with and no session is opened on it.
func newControl(rawURL, secret string, client *http.Client) (*control, error) {
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
		client = defaultHTTPClient()
	}
	return &control{base: strings.TrimRight(rawURL, "/"), secret: secret, client: client}, nil
}

// defaultHTTPClient returns the client used when Options.HTTPClient is nil.
// Redirects are refused: the control API is local, and following one
// elsewhere would hand the egress secret to another host.
func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: DefaultControlTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("the egress control API must not redirect")
		},
	}
}

// openSession registers the session with the proxy, which is what gives the
// token its meaning. session is forwarded untouched.
func (c *control) openSession(ctx context.Context, token string, session json.RawMessage) error {
	return c.do(ctx, http.MethodPut, sessionsPath+token, session, nil, "open egress session")
}

// certificateAuthority returns the proxy's CA in PEM form, which the agent
// container needs to trust the intercepted TLS connections.
func (c *control) certificateAuthority(ctx context.Context) (string, error) {
	var out struct {
		PEM string `json:"pem"`
	}
	if err := c.do(ctx, http.MethodGet, caPath, nil, &out, "read egress CA"); err != nil {
		return "", err
	}
	if out.PEM == "" {
		return "", errors.New("read egress CA: the egress control server returned no pem")
	}
	return out.PEM, nil
}

// closeSession drops the session, and with it the real credentials in the
// proxy's memory, and returns the counters it reports.
func (c *control) closeSession(ctx context.Context, token string) (*EgressStats, error) {
	var out EgressStats
	if err := c.do(ctx, http.MethodDelete, sessionsPath+token, nil, &out, "close egress session"); err != nil {
		return nil, err
	}
	return &out, nil
}

// do performs one control API call. what names the step in errors, which
// never include the request URL, the request body or the response body: all
// three can carry a secret.
func (c *control) do(ctx context.Context, method, path string, body []byte, out any, what string) error {
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
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxControlBody))
		resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s: the egress control server answered %s", what, resp.Status)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxControlBody)).Decode(out); err != nil {
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
