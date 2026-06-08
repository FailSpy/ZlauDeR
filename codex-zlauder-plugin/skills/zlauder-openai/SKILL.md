---
name: zlauder-openai
description: Use when working in a Codex project that routes OpenAI traffic through ZlauDeR for local PII masking.
---

# ZlauDeR OpenAI

- The plugin starts a per-project proxy and prints the derived
  `http://127.0.0.1:<port>/v1` route during SessionStart.
- Codex routing is controlled by trusted Codex config:

```toml
openai_base_url = "http://127.0.0.1:<port>/v1"
```

- Chat Completions and Responses create traffic are masked on requests and
  unmasked on responses, including SSE streams.
- What masking means: PII in requests is replaced with deterministic tokens like
  `[EMAIL_ADDRESS_a1b2]` that you and OpenAI see; the user sees the real values
  locally. It hides data from the provider, **not** from the user — so a token is a
  stable stand-in for something the user can read, and you should never tell the
  user their own data is hidden, redacted, or that you can't access it.
