<p align="center">
  <img src=".github/barbacana-logo-square.png" alt="Barbacana" width="120" />
</p>

<p align="center">
  Open-source WAF and API security gateway built on Caddy · Coraza · OWASP CRS v4
</p>

# Barbacana

A WAF secure by default and simple by design.

A Web Application Firewall [WAF](https://en.wikipedia.org/wiki/Web_application_firewall) sits between the internet and your application. It inspects every HTTP request for known attack patterns — SQL injection, cross-site scripting, command injection, path traversal, and hundreds more — and blocks malicious requests before they reach your code.

Barbacana is an open-source WAF and API security gateway. It wraps [Caddy](https://caddyserver.com), [Coraza](https://coraza.io), and [OWASP CRS v4](https://coreruleset.org) into a single container image with a simple YAML config. Every protection is on by default. You disable what you don't need — not the other way around.

## Quickstart

```yaml
# waf.yaml
version: v1alpha1

routes:
  - upstream: http://your-app:8000
```

```bash
barbacana serve --config waf.yaml
```

SQL injection, XSS, remote code execution, path traversal, protocol attacks, security headers — all active, all blocking. Your app is behind a WAF.

Add a real hostname and Barbacana automatically provisions a TLS certificate via Let's Encrypt — zero TLS configuration:

```yaml
version: v1alpha1

routes:
  - match:
      hosts: [api.example.com]
    upstream: http://api:8000
```

HTTPS on port 443, HTTP-to-HTTPS redirect, certificate renewal — all handled automatically by Caddy under the hood.

## Why Barbacana?

If you want a WAF today, your options are: learn CRS rule syntax and configure Coraza yourself, set up a full platform like BunkerWeb or SafeLine, pay for a cloud WAF with vendor lock-in, or go without.

Barbacana fills the gap. You write YAML, not rule syntax. You see human-readable protection names, not numeric rule IDs. You disable `sql-injection-auth` on a route that has false positives — not `SecRuleRemoveById 942100`.

## Configuration

```yaml
version: v1alpha1

routes:
  - id: api
    match:
      paths: ["/api/*"]
    upstream: http://api:8000
    accept:
      content_types: [application/json]
      methods: [GET, POST]
    rewrite:
      strip_prefix: /api
    openapi:
      spec: /specs/api.yaml
    disable:
      - sql-injection-union    # false positive on our search field

  - id: uploads
    match:
      paths: ["/upload/*"]
    upstream: http://uploads:8000
    accept:
      content_types: [multipart/form-data]
    multipart:
      file_limit: 20
      allowed_types: [image/png, image/jpeg, application/pdf]

  - id: everything-else
    upstream: http://app:8000
```

**`accept`** declares what the route handles. A JSON-only route never runs the XML parser — no wasted CPU, no XML bombs.

**`disable`** uses human-readable names. `sql-injection` disables the entire category. `sql-injection-union` disables only that technique.

**`rewrite`** translates paths between external URLs and your backend. OpenAPI validation runs against the rewritten path.

**`detect_only: true`** on any route logs attacks without blocking, for tuning.

The full protection list, config reference, and architecture are in [`docs/design/`](docs/design/).

## Built on

- [Caddy](https://caddyserver.com) — HTTP server, TLS, HTTP/2, HTTP/3, reverse proxy
- [Coraza](https://coraza.io) — WAF engine (pure Go, no CGO)
- [OWASP CRS v4](https://coreruleset.org) — attack detection rules

Barbacana wraps all three so you don't have to learn any of them.

## License

Apache 2.0