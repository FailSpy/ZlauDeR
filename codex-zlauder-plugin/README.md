# zlauder-openai

Codex plugin package for ZlauDeR's OpenAI proxy path. The SessionStart hook
starts or reuses a per-project `zlauder-proxy` configured with:

```toml
[proxy]
upstream_base_url = "https://api.openai.com"
```

Route Codex through the proxy from trusted Codex config:

```toml
openai_base_url = "http://127.0.0.1:<port>/v1"
```

The hook reports the derived project port in SessionStart context and in
`OPENAI_BASE_URL`. Chat Completions (`/v1/chat/completions`) is masked/unmasked.
Responses (`/v1/responses`) is routed through an explicit proxy module but is
passthrough until typed Responses wire support exists in `openai-wire`.

The bundled `zlauder.toml` is a starter seed. Put a project-specific
`zlauder.toml` at the project root to override it.
