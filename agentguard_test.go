package agentguard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnforce(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		if r.Header.Get("Authorization") != "Bearer tok" || req["idempotency_key"] == "" {
			w.WriteHeader(401)
			return
		}
		switch req["tool"] {
		case "ok":
			_ = json.NewEncoder(w).Encode(Decision{Decision: "allow", Allowed: true})
		case "san":
			_ = json.NewEncoder(w).Encode(Decision{Decision: "sanitize", Allowed: true, SanitizedArgs: map[string]any{"x": "[REDACTED]"}})
		case "appr":
			w.WriteHeader(202)
			_ = json.NewEncoder(w).Encode(Decision{Decision: "require_approval", ApprovalID: "apr_1"})
		default:
			w.WriteHeader(403)
			_ = json.NewEncoder(w).Encode(Decision{Decision: "deny", Reason: "tool_not_allowed"})
		}
	}))
	defer srv.Close()
	c := New(srv.URL, StaticToken("tok"))
	ctx := context.Background()
	if _, err := c.Enforce(ctx, "ok", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Enforce(ctx, "nope", nil); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	if d, err := c.Enforce(ctx, "appr", nil); !errors.Is(err, ErrApprovalRequired) || d.ApprovalID != "apr_1" {
		t.Fatal(err)
	}
	out, err := Guard(ctx, c, "san", map[string]any{"x": "secret"}, func(a map[string]any) (string, error) { return a["x"].(string), nil })
	if err != nil || out != "[REDACTED]" {
		t.Fatal(out, err)
	}
	ran := false
	_, err = Guard(ctx, New("http://127.0.0.1:1", StaticToken("tok")), "ok", nil, func(map[string]any) (int, error) { ran = true; return 0, nil })
	if !errors.Is(err, ErrGatewayUnavailable) || ran {
		t.Fatal("did not fail closed")
	}
}

func TestGuardReportsCompletionWithSession(t *testing.T) {
	var paths []string
	var session string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/v1/decide" {
			session, _ = body["session_id"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"decision_id": "d1", "decision": "allow", "allowed": true,
				"obligations": map[string]any{"lease_id": "d1", "max_retries": 1}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "recorded"})
	}))
	defer srv.Close()
	c := New(srv.URL, StaticToken("t"))
	c.SessionID = "ses_go"
	n := 0
	out, err := Guard(context.Background(), c, "crm.read", map[string]any{"id": 1}, func(map[string]any) (string, error) {
		n++
		if n == 1 {
			return "", errors.New("transient")
		}
		return "ok", nil
	}, Options{Retry: true})
	if err != nil || out != "ok" || n != 2 {
		t.Fatalf("guard: %v %q attempts=%d", err, out, n)
	}
	if session != "ses_go" || len(paths) != 2 || paths[1] != "/v1/complete" {
		t.Fatalf("session=%q paths=%v", session, paths)
	}
}

func TestResolveGatewayURL(t *testing.T) {
	t.Setenv("AGENTGUARD_GATEWAY_URL", "https://gw.example.com/")
	if got := ResolveGatewayURL("http://127.0.0.1:8181/"); got != "http://127.0.0.1:8181" {
		t.Errorf("explicit: %q", got)
	}
	if got := New("", StaticToken("t")).URL; got != "https://gw.example.com" {
		t.Errorf("env: %q", got)
	}
	t.Setenv("AGENTGUARD_GATEWAY_URL", "")
	if got := ResolveGatewayURL(""); got != "https://agentguard-gateway.rakizattawasol.com" {
		t.Errorf("default: %q", got)
	}
}
