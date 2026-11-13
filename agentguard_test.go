package agentguard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestRuntimeCalls(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		reply := func(code int, v any) { w.WriteHeader(code); _ = json.NewEncoder(w).Encode(v) }
		switch r.URL.Path {
		case "/v1/intent":
			if req["goal"] == "again" {
				reply(409, map[string]any{"session_id": req["session_id"], "goal": "first"})
				return
			}
			reply(200, map[string]any{"session_id": req["session_id"], "goal": req["goal"]})
		case "/v1/memory/write":
			if req["key"] == "blocked" {
				reply(403, map[string]any{"decision": "deny", "reason": "memory_poisoning"})
				return
			}
			reply(200, map[string]any{"record": map[string]any{"id": "mem_1", "source": req["source"]}})
		case "/v1/memory/verify":
			reply(200, map[string]any{"results": []any{map[string]any{"id": "mem_1", "status": "valid"}}})
		case "/v1/rag/filter":
			docs := req["documents"].([]any)
			reply(200, map[string]any{"documents": docs[:1]})
		case "/v1/rag/principals":
			reply(200, map[string]any{"principals": []string{"user:lina", "group:finance"}})
		case "/v1/a2a/envelope":
			reply(200, map[string]any{"envelope": map[string]any{"to": req["to"], "ttl": req["ttl_seconds"]}})
		case "/v1/a2a/verify":
			reply(200, map[string]any{"valid": false, "reason": "replayed"})
		}
	}))
	defer srv.Close()
	c := New(srv.URL, StaticToken("tok"))
	ctx := context.Background()
	if id := c.NewSession(""); !strings.HasPrefix(id, "ses_") || c.SessionID != id || c.NewSession("ses_x") != "ses_x" {
		t.Fatal("NewSession")
	}
	if out, err := c.DeclareIntent(ctx, "refund order 7", ""); err != nil || out["goal"] != "refund order 7" || out["session_id"] != "ses_x" {
		t.Fatal(out, err)
	}
	if out, err := c.DeclareIntent(ctx, "again", ""); err != nil || out["goal"] != "first" {
		t.Fatal("a second declaration returns the first goal", out, err)
	}
	if rec, err := c.MemoryWrite(ctx, "pref", "dark", "user", "chat"); err != nil || rec["id"] != "mem_1" {
		t.Fatal(rec, err)
	}
	if _, err := c.MemoryWrite(ctx, "blocked", "x", "web", ""); !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "memory_poisoning") {
		t.Fatal(err)
	}
	if res, err := c.MemoryVerify(ctx, []MemoryItem{{Record: map[string]any{"id": "mem_1"}, Value: "dark"}}); err != nil || len(res) != 1 || res[0]["status"] != "valid" {
		t.Fatal(res, err)
	}
	docs := []map[string]any{{"source": "drive", "doc_id": "1"}, {"source": "drive", "doc_id": "2"}}
	if kept, err := c.FilterDocuments(ctx, docs, "q"); err != nil || len(kept) != 1 || kept[0]["doc_id"] != "1" {
		t.Fatal(kept, err)
	}
	if ps, err := c.RAGPrincipals(ctx); err != nil || len(ps) != 2 {
		t.Fatal(ps, err)
	}
	if env, err := c.A2AEnvelope(ctx, "agt_b", map[string]any{"x": 1}, 0); err != nil || env["to"] != "agt_b" || env["ttl"] != float64(120) {
		t.Fatal(env, err)
	}
	if _, err := c.A2AVerify(ctx, map[string]any{}, nil); !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "replayed") {
		t.Fatal(err)
	}
	if u, err := c.ProxyURL(ctx, "http://agentguard-gateway:3128"); err != nil || u.String() != "http://agent:tok@agentguard-gateway:3128" {
		t.Fatal(u, err)
	}
	if _, err := c.ProxyURL(ctx, "not a url"); err == nil {
		t.Fatal("invalid proxy URL accepted")
	}
}
