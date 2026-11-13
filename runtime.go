package agentguard

import (
	"context"
	"errors"
	"fmt"
	"net/url"
)

// NewSession starts a new session (one per conversation or job run) and
// returns its id. An empty id generates one.
func (c *Client) NewSession(id string) string {
	if id == "" {
		id = "ses_" + randomKey()
	}
	c.SessionID = id
	return id
}

// denied turns a gateway answer that carries no result into ErrDenied with
// the gateway's reason.
func denied(out map[string]any, fallback string) error {
	reason, _ := out["reason"].(string)
	if reason == "" {
		reason, _ = out["error"].(string)
	}
	if reason == "" {
		reason = fallback
	}
	return fmt.Errorf("%w: %s", ErrDenied, reason)
}

// DeclareIntent declares the session's goal (the user's request). The first
// declaration cannot be changed; later actions are scored against it, which
// detects goal hijacking. An empty sessionID uses the client's session.
func (c *Client) DeclareIntent(ctx context.Context, goal, sessionID string) (map[string]any, error) {
	if sessionID == "" {
		sessionID = c.SessionID
	}
	if sessionID == "" {
		return nil, errors.New("agentguard: DeclareIntent needs a session id")
	}
	out := map[string]any{}
	if err := c.post(ctx, "/v1/intent", map[string]any{"session_id": sessionID, "goal": goal}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// MemoryWrite stores a memory item through policy and returns its signed
// provenance record. sourceType says where the value came from (for example
// "user", "tool" or "web"); sourceRef is an optional reference.
func (c *Client) MemoryWrite(ctx context.Context, key string, value any, sourceType, sourceRef string) (map[string]any, error) {
	out := map[string]any{}
	body := map[string]any{"key": key, "value": value, "source": map[string]string{"type": sourceType, "ref": sourceRef}, "session_id": c.SessionID}
	if err := c.post(ctx, "/v1/memory/write", body, &out); err != nil {
		return nil, err
	}
	rec, ok := out["record"].(map[string]any)
	if !ok {
		return nil, denied(out, "memory_write_denied")
	}
	return rec, nil
}

// MemoryItem is a recalled value with the record MemoryWrite returned for it.
type MemoryItem struct {
	Record map[string]any `json:"record"`
	Value  any            `json:"value"`
}

// MemoryVerify checks recalled memory before the agent trusts it. Each
// result has the item's id, status and trust level.
func (c *Client) MemoryVerify(ctx context.Context, items []MemoryItem) ([]map[string]any, error) {
	var out struct {
		Results []map[string]any `json:"results"`
	}
	if err := c.post(ctx, "/v1/memory/verify", map[string]any{"items": items}, &out); err != nil {
		return nil, err
	}
	return out.Results, nil
}

// FilterDocuments is permission-aware retrieval: it keeps only the
// documents the on-behalf-of person may open. Each document needs "source"
// and "doc_id".
func (c *Client) FilterDocuments(ctx context.Context, documents []map[string]any, query string) ([]map[string]any, error) {
	out := map[string]any{}
	if err := c.post(ctx, "/v1/rag/filter", map[string]any{"documents": documents, "query": query, "session_id": c.SessionID}, &out); err != nil {
		return nil, err
	}
	raw, ok := out["documents"].([]any)
	if !ok {
		return nil, denied(out, "rag_filter_failed")
	}
	docs := make([]map[string]any, 0, len(raw))
	for _, d := range raw {
		if m, ok := d.(map[string]any); ok {
			docs = append(docs, m)
		}
	}
	return docs, nil
}

// RAGPrincipals returns the identities to filter a vector store by at query
// time (ACL metadata).
func (c *Client) RAGPrincipals(ctx context.Context) ([]string, error) {
	var out struct {
		Principals []string `json:"principals"`
	}
	if err := c.post(ctx, "/v1/rag/principals", map[string]any{}, &out); err != nil {
		return nil, err
	}
	return out.Principals, nil
}

// A2AEnvelope authorizes and signs a message to another agent. A zero
// ttlSeconds uses 120 seconds.
func (c *Client) A2AEnvelope(ctx context.Context, toAgent string, payload any, ttlSeconds int, delegation ...string) (map[string]any, error) {
	if ttlSeconds <= 0 {
		ttlSeconds = 120
	}
	body := map[string]any{"to": toAgent, "payload": payload, "ttl_seconds": ttlSeconds, "session_id": c.SessionID}
	if len(delegation) > 0 {
		body["delegation"] = delegation
	}
	out := map[string]any{}
	if err := c.post(ctx, "/v1/a2a/envelope", body, &out); err != nil {
		return nil, err
	}
	env, ok := out["envelope"].(map[string]any)
	if !ok {
		return nil, denied(out, "a2a_denied")
	}
	return env, nil
}

// A2AVerify verifies a received envelope. It returns ErrDenied when the
// envelope is invalid, expired or replayed.
func (c *Client) A2AVerify(ctx context.Context, envelope map[string]any, payload any) (map[string]any, error) {
	out := map[string]any{}
	if err := c.post(ctx, "/v1/a2a/verify", map[string]any{"envelope": envelope, "payload": payload}, &out); err != nil {
		return nil, err
	}
	if valid, _ := out["valid"].(bool); !valid {
		return nil, denied(out, "a2a_invalid")
	}
	return out, nil
}

// ProxyURL returns the egress proxy URL with this agent's token, for
// http.Transport.Proxy or HTTPS_PROXY (for example
// "http://agentguard-gateway:3128"). The URL holds the token: do not log it.
func (c *Client) ProxyURL(ctx context.Context, egressURL string) (*url.URL, error) {
	u, err := url.Parse(egressURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("agentguard: invalid egress proxy URL")
	}
	tok, err := c.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: token: %v", ErrGatewayUnavailable, err)
	}
	u.User = url.UserPassword("agent", tok)
	return u, nil
}
