<p align="center">
  <img src=".github/barbacana-logo-square.png" alt="Barbacana" width="120" />
</p>

<p align="center">
  Barcana secure by default and simple by design.
</p>

# Barbacana

Barbacana is an open-source WAF and API security gateway, which means it protects your web applications and APIs with ease.

A Web Application Firewall ([WAF](https://en.wikipedia.org/wiki/Web_application_firewall)) sits between the internet and your application. It inspects every HTTP request for known attack patterns — SQL injection, cross-site scripting, command injection, path traversal, and hundreds more — and blocks malicious requests before they reach your code.

## Quickstart

Protect your app in minutes with a simple YAML config:

```yaml
# waf.yaml
version: v1alpha1

routes:
  - upstream: http://your-app:8000
```

```bash
barbacana serve --config waf.yaml
```

SQL injection, XSS, remote code execution, path traversal, protocol attacks, security headers active, etc. all blocked. 

External requests hit Barcana, it checks them agains a comprehensive set of security rules based on the [OWASP](https://coreruleset.org/) (over 250 rules), and only safe requests get forwarded to your app. You can tune protections per route, disable false positives, and add custom rules as needed. Your app is behind a WAF.

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

Most WAFs require either deep security expertise to configure, a full platform to operate, or a cloud subscription to access. Barbacana gives you production-grade protection with just a YAML file — human-readable names instead of rule IDs, secure defaults instead of manual tuning, and a single binary instead of a platform to manage.

Barbacana fills the gap. You write YAML, not rule syntax. You see human-readable protection names, not numeric rule IDs. You disable `sql-injection-auth` on a route that has false positives — not `SecRuleRemoveById 942100`.

## Configuration

A minimal deployment is one Barbacana instance in front of one backend application, with a real public hostname so automatic HTTPS kicks in:

```yaml
# waf.yaml
version: v1alpha1
host: api.example.com            # single host, auto-TLS on :443 and :80→:443 redirect

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

Setting a top-level `host` switches Barbacana into auto-TLS mode: Caddy binds `:443` and `:80`, redirects HTTP to HTTPS, and provisions a certificate for the configured hostname via Let's Encrypt. Omit `host` and set `port` instead (or leave both unset to default `port` to `8080`) to run plain HTTP behind a TLS-terminating load balancer.

Prometheus metrics and health endpoints are **opt-in**: `metrics_port` and `health_port` default to `0` (disabled) so a home user forwarding `:443` doesn't accidentally expose operational data to the internet. Enable them explicitly in production — the Helm chart and [`configs/example-production.yaml`](configs/example-production.yaml) set `metrics_port: 9090` and `health_port: 8081`. Structured JSON audit logs to stdout are always on and cover blocked/detected requests by themselves.

Run it alongside your backend with Docker Compose:

```bash
docker run -p 443:443 -p 80:80 \
  -v ./waf.yaml:/etc/barbacana/waf.yaml \
  -v barbacana-data:/data/barbacana \
  ghcr.io/barbacana-waf/barbacana:latest
```

```yaml
# compose.yaml
services:
  barbacana:
    image: ghcr.io/barbacana-waf/barbacana:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./waf.yaml:/etc/barbacana/waf.yaml:ro
      - barbacana-data:/data/barbacana
    depends_on:
      - app

  app:
    image: your-application:latest
    expose:
      - "8080"

volumes:
  barbacana-data:
```

Then `docker compose up -d` and point `api.example.com` at the host.

### Persist the data volume or your certificates will be re-issued on every restart

The `barbacana-data` named volume (mounted at `/data/barbacana`) is where Caddy keeps issued TLS certificates, ACME account keys, and OCSP staples. **If this volume is not persistent, every container restart asks Let's Encrypt for new certificates.** Let's Encrypt applies [rate limits](https://letsencrypt.org/docs/rate-limits/) — 50 certificates per registered domain per week, 5 duplicate certificates per week, and 300 new orders per account per 3 hours. Frequent restarts without persistent storage will exhaust the quota, after which **Let's Encrypt refuses to issue new certificates for up to a week**. This is a Let's Encrypt policy, not a Barbacana limitation — the fix is to mount a real volume for `/data/barbacana` so existing certificates survive restarts.

A working [`compose.yaml`](compose.yaml) is included at the repo root.

The full protection list, config reference, and architecture are in [`docs/design/`](docs/design/).

## Built on

- [Caddy](https://caddyserver.com) — HTTP server, TLS, HTTP/2, HTTP/3, reverse proxy
- [Coraza](https://coraza.io) — WAF engine (pure Go, no CGO)
- [OWASP CRS v4](https://coreruleset.org) — attack detection rules

Barbacana wraps all three so you don't have to learn any of them by abstracting away the complexity. 


## License

Apache 2.0