# Secure Headers Scanner

A fast, self-hosted **HTTP Security Headers Scanner** built with a **Rust** scanning engine (`secscan-core`, `secscan-api`, `secscan-cli`) and a **React + TypeScript + Tailwind CSS** web UI (`secscan-ui`).

> **Türkçe Özet:** Web uygulamalarının HTTP güvenlik başlıklarını toplu olarak tarayan, SSRF korumalı, **Rust** tabanlı yüksek performanslı API + yerel CLI ve **React + TypeScript + Tailwind CSS** arayüzünden oluşan açık kaynaklı güvenlik tarayıcısıdır. Ağırlıklı skorlama (`A+`–`F`), derin CSP/HSTS/çerez analizi, kopyalanabilir çözüm önerileri (Nginx/Apache/Express/Cloudflare), anlık SSE akışı ve son taramanın **YAML** dosyasında saklanarak otomatik **diff** karşılaştırması özelliklerini içerir.

---

## Features

- **Rust Scanning Engine (`secscan-core`)**
  - **SSRF & DNS Rebinding Protection:** Custom `reqwest` DNS resolver validates every resolved IP on every redirect hop, blocking loopback, RFC1918/ULA private ranges, and cloud metadata (`169.254.169.254`) by default. Opt in for trusted internal audits via `ALLOW_PRIVATE_NETWORKS=true` (and optional `ALLOW_SELF_SIGNED_TLS=true`).
  - **Deep Header Analysis:** HSTS (`max-age`, `includeSubDomains`, `preload`), CSP directive parser (`unsafe-inline`, `unsafe-eval`, wildcard `*`, `object-src`, `base-uri`, `frame-ancestors`), Clickjacking, multi-header `Set-Cookie` (`Secure`, `HttpOnly`, `SameSite`), `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `COOP`/`COEP`/`CORP`, CORS (`ACAO`), `X-XSS-Protection`, and technology disclosure headers (`Server`, `X-Powered-By`, `X-AspNet-Version`, `Via`, `X-Generator`).
  - **HTTP→HTTPS Fallback & Redirect Chain:** Automatically falls back to HTTPS when port 80 is closed, preserves URL paths, and records the full redirect chain.
  - **Weighted Scoring (`0–100` / `A+`–`F`) & Remediations:** Actionable copy-paste snippets for **Nginx**, **Apache**, **Express (Helmet)**, and **Cloudflare**.
  - **YAML Snapshot & Diff Engine:** Persists the latest scan atomically to YAML (`LAST_SCAN_PATH`) and automatically computes score/header deltas (`improved`, `regressed`, `new`, `removed`) on subsequent scans.
- **Axum HTTP API (`secscan-api`)**
  - `POST /api/scan` — Batch JSON scan with snapshot and diff.
  - `POST /api/scan/stream` — Real-time Server-Sent Events (SSE) stream with client-side abort/cancellation.
  - `GET /api/last-scan` & `GET /api/last-scan/yaml` — Retrieve the saved YAML snapshot.
  - `POST /api/diff` — Compare current results against any uploaded YAML baseline.
  - `GET /api/healthz`, `GET /healthz`, `GET /api/openapi.json` — Health checks & OpenAPI 3.0 spec.
  - Built-in per-IP rate limiting, hardened API security headers, and structured JSON logging (`tracing`).
- **Native CLI (`secscan-cli`)**
  - Outputs `table`, `json`, `yaml`, or `sarif` (GitHub Code Scanning compatible).
  - CI/CD quality gate with `--min-grade B`, plus `--baseline last-scan.yaml` and `--save-yaml last-scan.yaml`.
- **Modern Web UI (`secscan-ui`)**
  - React + TypeScript + Tailwind CSS with Dark/Light mode and **TR / EN** i18n switcher.
  - Live SSE progress bar & cancel button, summary KPI cards, sortable/paginated table, Regex + vulnerability (AND/OR) + Diff filters.
  - Formula-injection-safe CSV (Summary & Detailed), JSON, YAML, and XSS-safe printable PDF exports.

---

## Project Structure

```text
Security-Headers-Scanner/
├─ Cargo.toml                     # Rust workspace
├─ docker-compose.yml             # Production stack (Rust API + unprivileged Nginx UI)
├─ .env.example                   # Environment variable reference
├─ crates/
│  ├─ secscan-core/               # Shared SSRF-safe fetcher, analyzers, scorer, remediations, YAML diff
│  ├─ secscan-api/                # Axum HTTP API + SSE server + Dockerfile
│  └─ secscan-cli/                # Native `secscan` CLI binary
└─ secscan-ui/                    # React + TypeScript + Vite + Tailwind CSS + hardened Nginx
```

---

## Quick Start

### 1. Run with Docker Compose

```bash
cp .env.example .env
docker compose build
docker compose up -d
```

- Web UI: `http://localhost/` (configurable via `UI_PORT`)
- Health check: `http://localhost/api/healthz` → `{"ok":true,"version":"2.0.0"}`
- OpenAPI spec: `http://localhost/api/openapi.json`

### 2. Local Development (without Docker)

**Backend (Rust API):**
```bash
cargo run -p secscan-api
# Listening on http://0.0.0.0:4000
```

**Frontend (Vite dev server with `/api` proxy to `:4000`):**
```bash
cd secscan-ui
npm install
npm run dev
# Listening on http://localhost:5173
```

### 3. Native CLI Usage (`secscan`)

```bash
# Scan domains and save snapshot to YAML
cargo run -p secscan-cli -- example.com github.com --save-yaml last-scan.yaml

# Compare against previous YAML baseline and enforce minimum grade B in CI
cargo run -p secscan-cli -- -f domains.txt --baseline last-scan.yaml --min-grade B

# Export SARIF report
cargo run -p secscan-cli -- example.com --format sarif -o results.sarif

# Scan internal network targets explicitly
cargo run -p secscan-cli -- http://10.0.0.5:8080 --allow-private --allow-self-signed
```

---

## Configuration

See [.env.example](.env.example) for all options:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `4000` | API listening port |
| `SCAN_CONCURRENCY` | `15` | Concurrent domain scan limit (`1–100`) |
| `MAX_DOMAINS_PER_REQUEST` | `500` | Maximum unique domains per API request |
| `ALLOW_PRIVATE_NETWORKS` | `false` | Allow private/loopback/metadata IPs (trusted internal audits only) |
| `ALLOW_SELF_SIGNED_TLS` | `false` | Accept invalid/self-signed TLS certificates |
| `RATE_LIMIT_PER_MINUTE` | `30` | Per-IP scan requests per minute |
| `CORS_ORIGIN` | *(empty)* | Comma-separated allowed origins (or `*`) |
| `LAST_SCAN_PATH` | `./data/last-scan.yaml` | File path for persisted previous scan YAML snapshot |

---

## Testing & Verification

```bash
# Rust formatting, lints, unit & integration tests
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Frontend typecheck, lint, unit tests, and production build
cd secscan-ui
npm run typecheck
npm run lint
npm test
npm run build
```

## License

MIT
