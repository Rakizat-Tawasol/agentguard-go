// Package agentguard is the Go SDK for the AgentGuard OS enforcement gateway.
//
//	g := agentguard.New("", agentguard.StaticToken(os.Getenv("AGENTGUARD_AGENT_TOKEN")))
//	d, err := g.Enforce(ctx, "payments.refund", map[string]any{"amount": 120, "currency": "USD"})
//	if errors.Is(err, agentguard.ErrApprovalRequired) { ... d.ApprovalID ... }
//
// An empty URL means AGENTGUARD_GATEWAY_URL, or the hosted gateway
// (DefaultGatewayURL) when that is not set. Pass "http://127.0.0.1:8181" to
// use a sidecar gateway.
//
// The SDK fails closed: transport errors return ErrGatewayUnavailable and the
// caller must not execute the action.
package agentguard

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Errors returned by Enforce.
var (
	ErrDenied             = errors.New("agentguard: action denied")
	ErrApprovalRequired   = errors.New("agentguard: human approval required")
	ErrGatewayUnavailable = errors.New("agentguard: gateway unavailable")
)

// Decision is the gateway response.
type Decision struct {
	DecisionID    string         `json:"decision_id"`
	Decision      string         `json:"decision"`
	Allowed       bool           `json:"allowed"`
	Reason        string         `json:"reason"`
	Fingerprint   string         `json:"fingerprint"`
	ApprovalID    string         `json:"approval_id"`
	Risk          string         `json:"risk"`
	SanitizedArgs map[string]any `json:"sanitized_args"`
	Signals       map[string]any `json:"signals"`
	Replayed      bool           `json:"replayed"`
	LatencyMicros int64          `json:"latency_us"`
	Obligations   *Obligations   `json:"obligations,omitempty"`
	GrantID       string         `json:"grant_id,omitempty"`
}

// Obligations are execution constraints returned with an allowed decision.
type Obligations struct {
	LeaseID        string `json:"lease_id"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	MaxRetries     int    `json:"max_retries"`
	RetryBackoffMs int    `json:"retry_backoff_ms"`
	FallbackModel  string `json:"fallback_model"`
}

// Options are per-call options.
type Options struct {
	Action          string
	Context         map[string]any
	UntrustedInputs []string
	Delegation      []string
	ApprovalID      string
	IdempotencyKey  string
	TraceParent     string
	SessionID       string // defaults to Client.SessionID
	TaskID          string
	// Retry applies the policy's retry obligations in Guard.
	Retry bool
}

// TokenSource returns the current agent token.
type TokenSource func(ctx context.Context) (string, error)

// StaticToken returns a fixed token.
func StaticToken(t string) TokenSource {
	return func(context.Context) (string, error) { return t, nil }
}

// Client calls the gateway.
type Client struct {
	URL   string
	Token TokenSource
	HTTP  *http.Client
	// SessionID groups decisions for session replay (one per run).
	SessionID string
	TaskID    string
}

// DefaultGatewayURL is the hosted enforcement gateway, used when no URL is
// given and AGENTGUARD_GATEWAY_URL is not set.
const DefaultGatewayURL = "https://agentguard-gateway.rakizattawasol.com"

// ResolveGatewayURL returns url, else AGENTGUARD_GATEWAY_URL, else
// DefaultGatewayURL, without trailing slashes.
func ResolveGatewayURL(url string) string {
	if u := strings.TrimSpace(url); u != "" {
		return strings.TrimRight(u, "/")
	}
	if u := strings.TrimSpace(os.Getenv("AGENTGUARD_GATEWAY_URL")); u != "" {
		return strings.TrimRight(u, "/")
	}
	return DefaultGatewayURL
}

// New creates a client with a fresh session id. An empty url is resolved
// with ResolveGatewayURL.
func New(url string, tok TokenSource) *Client {
	return &Client{URL: ResolveGatewayURL(url), Token: tok, HTTP: &http.Client{Timeout: 5 * time.Second}, SessionID: "ses_" + randomKey()}
}

func randomKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (c *Client) post(ctx context.Context, path string, body any, out any) error {
	tok, err := c.Token(ctx)
	if err != nil {
		return fmt.Errorf("%w: token: %v", ErrGatewayUnavailable, err)
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrGatewayUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 || resp.StatusCode == 401 {
		return fmt.Errorf("%w: HTTP %d", ErrGatewayUnavailable, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Decide asks the gateway for a decision without interpreting it.
func (c *Client) Decide(ctx context.Context, tool string, args map[string]any, o Options) (Decision, error) {
	if args == nil {
		args = map[string]any{}
	}
	body := map[string]any{"tool": tool, "args": args}
	set := func(k string, v any, ok bool) {
		if ok {
			body[k] = v
		}
	}
	set("action", o.Action, o.Action != "")
	set("context", o.Context, o.Context != nil)
	set("untrusted_inputs", o.UntrustedInputs, len(o.UntrustedInputs) > 0)
	set("delegation", o.Delegation, len(o.Delegation) > 0)
	set("approval_id", o.ApprovalID, o.ApprovalID != "")
	set("idempotency_key", o.IdempotencyKey, o.IdempotencyKey != "")
	set("trace_id", o.TraceParent, o.TraceParent != "")
	sid := o.SessionID
	if sid == "" {
		sid = c.SessionID
	}
	set("session_id", sid, sid != "")
	tid := o.TaskID
	if tid == "" {
		tid = c.TaskID
	}
	set("task_id", tid, tid != "")
	var d Decision
	err := c.post(ctx, "/v1/decide", body, &d)
	return d, err
}

// Enforce returns nil only when the action may execute (allow or sanitize;
// use d.SanitizedArgs when non-nil).
func (c *Client) Enforce(ctx context.Context, tool string, args map[string]any, opts ...Options) (Decision, error) {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	if o.IdempotencyKey == "" {
		o.IdempotencyKey = randomKey()
	}
	d, err := c.Decide(ctx, tool, args, o)
	if err != nil {
		return d, err
	}
	switch {
	case d.Decision == "require_approval":
		return d, fmt.Errorf("%w: %s (approval %s)", ErrApprovalRequired, d.Reason, d.ApprovalID)
	case !d.Allowed:
		return d, fmt.Errorf("%w: %s", ErrDenied, d.Reason)
	}
	return d, nil
}

// Guard runs fn only after an allow/sanitize decision, passing the
// effective (possibly sanitized) arguments.
// It enforces the policy timeout via the context, applies retry obligations
// when Options.Retry is set, and reports the outcome to the gateway.
func Guard[R any](ctx context.Context, c *Client, tool string, args map[string]any, fn func(args map[string]any) (R, error), opts ...Options) (R, error) {
	var zero R
	d, err := c.Enforce(ctx, tool, args, opts...)
	if err != nil {
		return zero, err
	}
	if d.Decision == "sanitize" && d.SanitizedArgs != nil {
		args = d.SanitizedArgs
	}
	ob := Obligations{}
	if d.Obligations != nil {
		ob = *d.Obligations
	}
	attempts := 1
	if len(opts) > 0 && opts[0].Retry {
		attempts += ob.MaxRetries
	}
	run := ctx
	if ob.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		run, cancel = context.WithTimeout(ctx, time.Duration(ob.TimeoutSeconds)*time.Second)
		defer cancel()
	}
	start := time.Now()
	var out R
	for i := 0; i < attempts; i++ {
		out, err = fn(args)
		if err == nil || run.Err() != nil {
			break
		}
		if i+1 < attempts {
			time.Sleep(time.Duration(ob.RetryBackoffMs<<i) * time.Millisecond)
		}
	}
	status := "ok"
	switch {
	case run.Err() != nil:
		status = "timeout"
	case err != nil:
		status = "error"
	}
	c.Complete(context.WithoutCancel(ctx), d, status, err, time.Since(start))
	return out, err
}

// Complete reports an execution outcome (releases the lease, feeds circuit
// breakers). It never fails the caller.
func (c *Client) Complete(ctx context.Context, d Decision, status string, execErr error, took time.Duration) {
	if d.Obligations == nil || d.Obligations.LeaseID == "" {
		return
	}
	msg := ""
	if execErr != nil {
		msg = execErr.Error()
	}
	var out map[string]any
	_ = c.post(ctx, "/v1/complete", map[string]any{"decision_id": d.Obligations.LeaseID, "status": status, "error": msg, "duration_ms": took.Milliseconds()}, &out)
}

// BrokerURL is the URL of a credential-broker route.
func (c *Client) BrokerURL(route, path string) string {
	return c.URL + "/broker/" + route + "/" + strings.TrimLeft(path, "/")
}

// Usage is model consumption to meter against budgets.
type Usage struct {
	Model        string  `json:"model"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	CostUSD      float64 `json:"cost_usd,omitempty"`
	TaskID       string  `json:"task_id,omitempty"`
	SessionID    string  `json:"session_id,omitempty"`
}

// ReportUsage meters usage; the response reports today's spend.
func (c *Client) ReportUsage(ctx context.Context, u Usage) (map[string]any, error) {
	if u.SessionID == "" {
		u.SessionID = c.SessionID
	}
	if u.TaskID == "" {
		u.TaskID = c.TaskID
	}
	out := map[string]any{}
	err := c.post(ctx, "/v1/usage", u, &out)
	return out, err
}
