# Barbacana Grafana dashboard

Operator-facing Grafana dashboard for Barbacana WAF — one JSON, one
import, one URL to bookmark. Designed around the SRE Four Golden
Signals so the at-a-glance row reads in under five seconds.

## What this dashboard shows

`barbacana.json` (UID `barbacana`, title "Barbacana") ships a single
dashboard with six rows, top to bottom:

1. **Four Golden Signals** — Latency, Traffic, Errors, Saturation as
   four single-stats. Kiosk-friendly (`?kiosk=tv`); a passing wall
   display only needs this row.
2. **WAF state** — Mode (per-mode tile, reads MIXED when routes
   disagree), Mode by route, Action distribution donut, Blocks and
   Detections counts over the visible window.
3. **Throughput & latency** — Request rate by action (stacked), Caddy
   responses by status class (stacked), WAF overhead p50/p95/p99,
   overhead as fraction of total, per-route overhead table.
4. **Errors & upstream** — Upstream errors by kind, Caddy 5xx vs WAF
   upstream 5xx attribution, body spool + decompression rejects.
5. **Threat detail** — Blocks vs detections, anomaly score heatmap,
   top attack categories, top targeted resources, Caddy 403 vs WAF
   blocks attribution.
6. **Operational signals** — Config reloads, CRS evaluation timeouts,
   security headers injected.

A separate **live-demo** dashboard ships in the
[barbacana-demo](https://github.com/barbacana-waf/barbacana-demo) repo
(single-stat heavy, dramatic-movement prioritised). The one here is for
production. Don't conflate them.

## Importing into Grafana

1. Open Grafana → *Dashboards* → *New* → *Import*.
2. Upload `barbacana.json` (or paste the JSON). Pick your Prometheus
   data source when prompted. Save.

The dashboard's `uid` is fixed (`barbacana`) so deep links remain
stable across re-imports. If you have an old `barbacana-summary` /
`barbacana-operations` / `barbacana-security` from before the
unification, delete them — they will not be auto-removed.

## Time range

The dashboard defaults to **Last 24 hours** with a 30-second auto
refresh. The time picker is the only window control: count panels
(Blocks, Detections, Action distribution, Top attack categories, Top
targeted resources) query `$__range` and adapt automatically — pick
"Last 15m" and they show 15 minute totals; pick "Last 7d" and they
show 7 day totals. Panel titles include `${__range}` so you can see
the active window from the panel header.

Quick-range presets configured: 15m, 1h, 12h, 24h, 7d.

## Variables

| Variable | Type | Default | What it does |
| --- | --- | --- | --- |
| `Prometheus` | datasource | first matching DS | Data source the dashboard queries. |
| `Route` | query, multi | All | Filters per-route panels. Whole-system panels (Golden Signals, errors-by-kind, config reloads) ignore it. |
| `Protection` | query, multi | All | Filters threat-detail panels. |
| `In-flight warn threshold` | constant | 100 | Saturation tile yellow above this. |
| `In-flight crit threshold` | constant | 500 | Saturation tile red above this. |
| `Audit log URL` | textbox | empty | URL template for your external audit-log viewer. See "Drill-downs and audit-log integration" below. |

Tune the in-flight thresholds for your traffic shape — 100 is
reasonable for a small-to-medium deployment, far too low for a
high-RPS frontend.

## Drill-downs and audit-log integration

Three panels carry click-through filters that reload the dashboard
with a variable pre-set. Time range is preserved.

| Click on a row in… | Sets variable |
| --- | --- |
| Per-route overhead | `route` |
| Top attack categories | `protection` |
| Top targeted resources | `route` |
| Mode by route | `route` |

Block-related and error-related panels also expose a "View audit
logs" data link. The link target is the `audit_log_url` variable.
Set it from the dashboard variable bar — Grafana resolves nested
template syntax inside data links, so you can use the standard
Grafana variables in the value:

| SIEM | Template (paste into the `Audit log URL` field) |
| --- | --- |
| Splunk | `https://splunk.example.com/en-US/app/search/search?q=index%3Dbarbacana%20route%3D%22${route:raw}%22%20protection%3D%22${protection:raw}%22&earliest=${__from:date:iso}&latest=${__to:date:iso}` |
| Loki (Grafana Explore) | `/explore?left=%5B%22${__from}%22,%22${__to}%22,%22Loki%22,%7B%22expr%22:%22%7Bapp%3D%5C%22barbacana%5C%22,route%3D%5C%22${route:raw}%5C%22%7D%22%7D%5D` |
| Elastic / Kibana | `https://kibana.example.com/app/discover#/?_g=(time:(from:'${__from:date:iso}',to:'${__to:date:iso}'))&_a=(query:(query_string:(query:'route:"${route:raw}" AND protection:"${protection:raw}"')))` |
| `kubectl logs` (operator note, not a clickable link) | `kubectl logs -n barbacana -l app=barbacana --since-time=$(date -ud @${__from:dateSeconds} +%FT%TZ) | jq 'select(.route == "${route:raw}")'` |

When the variable is empty the data links are inert; the dashboard
otherwise works normally.

## Wall-display and kiosk usage

Append `?kiosk=tv` to the dashboard URL. Grafana hides chrome and the
Four Golden Signals row reads as a wall display without scrolling.

## Metrics this dashboard depends on

All of these come from a stock Barbacana exposing `/metrics`:

- `waf_build_info` — version, CRS version, commit (annotation track marks deploys)
- `waf_requests_total{route, action}` — action ∈ {`allowed`, `detected`, `blocked`}
- `waf_requests_blocked_total{route, protection}`
- `waf_requests_in_flight` — capacity gauge
- `waf_detected_threats_total{route, protection}`
- `waf_anomaly_score_histogram_bucket{route, le}`
- `waf_request_duration_overhead_seconds_bucket{route, le}` — WAF-only time, excluding upstream RTT
- `waf_upstream_errors_total{route, kind}` — kind ∈ {`timeout`, `connection_refused`, `5xx`, `other`}
- `waf_evaluation_timeout_total{route}`
- `waf_body_spooled_total{route}`
- `waf_decompression_rejected_total{route}`
- `waf_security_headers_injected_total{route, header}`
- `waf_config_reload_total{result}`
- `waf_config_reload_timestamp_seconds`
- `waf_mode_info{route, mode}` — mode ∈ {`blocking`, `detect_only`}

Caddy's `caddy_http_*` series are optional. The status-code panels
read `code` from `caddy_http_request_duration_seconds_count` rather
than `caddy_http_requests_total`, because Caddy's bare request counter
does not carry a `code` label (only the histogram metrics do).

## Graceful degradation

The dashboard intentionally never errors when a metric is absent.

| Panel | What's needed | If absent |
| --- | --- | --- |
| Saturation | `waf_requests_in_flight` | Shows `N/A` |
| Errors (Golden Signals) | `caddy_http_*` (optional) | `or vector(0)` keeps the panel populated using `waf_upstream_errors_total` only |
| Caddy responses by status class | `caddy_http_request_duration_seconds_count` | Shows degradation message |
| WAF / total p95 | `caddy_http_request_duration_seconds_bucket` | Shows degradation message |
| 5xx attribution | `caddy_http_request_duration_seconds_count` | Shows degradation message |
| 403 attribution | `caddy_http_request_duration_seconds_count` | Shows degradation message |
| Mode, Mode by route | `waf_mode_info` | Empty until first config load |
| Everything else | core `waf_*` metrics | Empty if nothing has happened yet |

To enable the optional Caddy series, leave the http metrics flag on
in the configuration that produces the Caddy server config (this is
on by default in current Barbacana versions).

## Annotations

Three annotation tracks render vertical lines across every panel:

- **Config reloads** — every successful reload (`waf_config_reload_timestamp_seconds`).
- **Build version changes** — every `waf_build_info` change over 1 day.
- **Mode flips** — every `waf_mode_info` change over 1 day. An
  operator should be able to see "we flipped from detect-only to
  blocking at 14:00" overlaid on every panel.

## I want a separate SOC dashboard

This is a deliberate non-deliverable. SOC operators with their own
correlation requirements should build their own dashboards from the
same metric surface — Barbacana ships the metrics, not the SOC
artifact.

## What this dashboard does NOT cover

- **Alert rules.** Alerts live in your Prometheus AlertManager config,
  not the dashboard. We may publish suggested alert rules separately.
- **Per-CRS-rule breakdowns.** The `protection` label is sub-protection
  level; finer breakdowns aren't surfaced as metrics today.
- **Source-IP geomaps.** Barbacana does not do GeoIP — that's the
  responsibility of upstream log enrichment.
- **Per-request forensic detail.** Per-block detail belongs in the
  SIEM (audit logs, OCSF/ECS), not in Grafana over Prometheus
  aggregations. Use the audit-log data links above.

## Updating

The dashboard JSON in this repo is the source of truth. Edits made
inside Grafana stay local to that instance unless you export and PR
them back. Bump [`CHANGELOG.md`](CHANGELOG.md) when you do.
