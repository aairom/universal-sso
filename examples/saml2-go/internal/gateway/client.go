package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// maxBody bounds every response body read from the gateway.
const maxBody = 1 << 20

// User is the normalized profile returned by the gateway callback.
type User struct {
	ID            string   `json:"id"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Username      string   `json:"username,omitempty"`
	DisplayName   string   `json:"display_name,omitempty"`
	Roles         []string `json:"roles,omitempty"`
	Groups        []string `json:"groups,omitempty"`
}

// Profile is the body of a successful callback.
type Profile struct {
	ProviderID string `json:"provider_id"`
	User       User   `json:"user"`
}

// APIError is the gateway's structured error body {"code","message"}.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("gateway error %d [%s]: %s", e.Status, e.Code, e.Message)
}

// Client talks to the gateway. It never follows redirects automatically, so
// every hop can be checked against the policy.
type Client struct {
	cfg  Config
	http *http.Client
	log  *slog.Logger
}

// NewClient builds a Client. A nil logger discards logs.
func NewClient(cfg Config, log *slog.Logger) *Client {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Client{
		cfg: cfg,
		log: log,
		http: &http.Client{
			Timeout:       cfg.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (c *Client) endpoint(path string) string { return c.cfg.GatewayURL.String() + path }

func (c *Client) get(ctx context.Context, rawURL string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return resp, body, err
}

func apiError(resp *http.Response, body []byte) error {
	var e struct{ Code, Message string }
	_ = json.Unmarshal(body, &e)
	if e.Code == "" {
		e.Code, e.Message = "UNKNOWN", strings.TrimSpace(string(body))
		if len(e.Message) > 200 {
			e.Message = e.Message[:200]
		}
	}
	return &APIError{Status: resp.StatusCode, Code: e.Code, Message: e.Message}
}

// Health returns nil when the gateway reports {"status":"ok"}.
func (c *Client) Health(ctx context.Context) error {
	resp, body, err := c.get(ctx, c.endpoint("/healthz"))
	if err != nil {
		return err
	}
	var h struct{ Status string }
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &h) != nil || h.Status != "ok" {
		return fmt.Errorf("gateway not healthy: HTTP %d", resp.StatusCode)
	}
	return nil
}

// Providers lists the provider ids registered in the gateway.
func (c *Client) Providers(ctx context.Context) ([]string, error) {
	resp, body, err := c.get(ctx, c.endpoint("/providers"))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, apiError(resp, body)
	}
	var p struct {
		Providers []string `json:"providers"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("decode providers: %w", err)
	}
	return p.Providers, nil
}

// Login is a started sign-in.
type Login struct {
	// AuthorizeURL is where the user's browser must go. It passed CheckAuthorizeURL.
	AuthorizeURL *url.URL
	// State is the signed state the gateway issued for this attempt.
	State string
}

// StartLogin asks the gateway to begin a sign-in and validates the redirect.
// It returns *APIError when the gateway refuses (for example 404
// PROVIDER_NOT_FOUND for a provider that is not registered).
func (c *Client) StartLogin(ctx context.Context) (*Login, error) {
	resp, body, err := c.get(ctx, c.endpoint("/auth/"+url.PathEscape(c.cfg.Provider)+"/login"))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		return nil, apiError(resp, body)
	}
	loc, err := resp.Location()
	if err != nil {
		return nil, fmt.Errorf("gateway redirect has no usable Location: %w", err)
	}
	state, err := CheckAuthorizeURL(loc, c.cfg.GatewayURL, c.cfg.ExpectedIdPHost)
	if err != nil {
		return nil, err
	}
	c.log.Info("login started", "provider", c.cfg.Provider, "idp_host", loc.Host)
	return &Login{AuthorizeURL: loc, State: state}, nil
}

// maxHops bounds FollowLocal.
const maxHops = 5

// ErrLeavesGateway is returned by FollowLocal when the flow needs a browser.
var ErrLeavesGateway = errors.New("redirect leaves the gateway host: open the URL in a browser")

// FollowLocal completes a sign-in without a browser, but only while every
// redirect stays on the gateway's own host. That is the case for the mock
// provider, which is why it is used for tests and demos. Real identity
// providers need a user at a browser, and FollowLocal returns ErrLeavesGateway.
func (c *Client) FollowLocal(ctx context.Context, l *Login) (*Profile, error) {
	next := l.AuthorizeURL
	if next.Host != c.cfg.GatewayURL.Host {
		return nil, ErrLeavesGateway
	}
	for hop := 0; hop < maxHops; hop++ {
		resp, body, err := c.get(ctx, next.String())
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusOK {
			var p Profile
			if err := json.Unmarshal(body, &p); err != nil || p.User.ID == "" {
				return nil, errors.New("callback response is not a profile")
			}
			c.log.Info("login completed", "provider", p.ProviderID)
			return &p, nil
		}
		if resp.StatusCode != http.StatusFound {
			return nil, apiError(resp, body)
		}
		loc, err := resp.Location()
		if err != nil {
			return nil, err
		}
		if loc.Host != c.cfg.GatewayURL.Host {
			return nil, ErrLeavesGateway
		}
		next = loc
	}
	return nil, errors.New("too many redirects")
}
