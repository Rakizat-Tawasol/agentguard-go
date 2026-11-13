# AgentGuard Go SDK

Go client for the [AgentGuard OS](https://agentguard.rakizattawasol.com/site/en/developers.html) enforcement gateway. Every protected action is decided by the gateway before it runs, and the SDK fails closed: if the gateway cannot be reached, the action must not run.

```bash
go get github.com/rakizat-tawasol/agentguard-go
```

```go
import (
	"context"
	"errors"
	"log"
	"os"

	agentguard "github.com/rakizat-tawasol/agentguard-go"
)

func refund(ctx context.Context) error {
	// An empty URL uses AGENTGUARD_GATEWAY_URL, or the hosted gateway.
	g := agentguard.New("", agentguard.StaticToken(os.Getenv("AGENTGUARD_AGENT_TOKEN")))
	d, err := g.Enforce(ctx, "payments.refund", map[string]any{"amount": 120, "currency": "USD"})
	if errors.Is(err, agentguard.ErrApprovalRequired) {
		log.Printf("approval needed: %s", d.ApprovalID)
		return err
	}
	if err != nil {
		return err // denied, or the gateway is unavailable: do not run the action
	}
	// Allowed: run the refund here.
	return nil
}
```

## Sessions, memory, retrieval and agent-to-agent calls

```go
g.NewSession("")                                             // one session per conversation or job run
g.DeclareIntent(ctx, "refund order 7", "")                   // later actions are scored against the goal
rec, err := g.MemoryWrite(ctx, "pref", "dark", "user", "")   // signed provenance record
res, err := g.MemoryVerify(ctx, []agentguard.MemoryItem{{Record: rec, Value: "dark"}})
docs, err := g.FilterDocuments(ctx, candidates, query)       // only what the on-behalf-of person may open
ids, err := g.RAGPrincipals(ctx)                             // identities for vector-store ACL filters
env, err := g.A2AEnvelope(ctx, "agt_billing", payload, 0)    // sign a message to another agent
_, err = g.A2AVerify(ctx, env, payload)                      // ErrDenied when invalid or replayed
proxy, err := g.ProxyURL(ctx, "http://agentguard-gateway:3128") // egress proxy; holds the token, do not log
```

## Gateway URL

The URL passed to `New` is used first. If it is empty, the SDK reads `AGENTGUARD_GATEWAY_URL`. If that is not set either, it uses the hosted gateway `https://agentguard-gateway.rakizattawasol.com`.

To keep decisions inside your network, run the gateway as a sidecar and pass `http://127.0.0.1:8181`.

## Requirements

- Go 1.21 or later. No dependencies outside the standard library.
- An AgentGuard OS account and an agent token from the console at `https://agentguard.rakizattawasol.com`.

## Support

- Questions and security reports: info@rakizattawasol.com
- This repository is published from the AgentGuard OS source tree. Issues are welcome; pull requests are reviewed and applied upstream.

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). This licence covers the SDK only; the AgentGuard OS platform is proprietary and needs an account or licence from Rakizat Tawasol Software and Systems Development.
