# Traefik Dynamic Logger

A lightweight, security‑aware logging layer and middleware for **Traefik**. It can observe requests in real time, enrich logs (GeoIP/ASN), detect brute‑force & signature‑based attacks, and **dynamically react**: emit structured logs, write deny/allow rules, or update Traefik’s dynamic config via the file provider. Use it as a **Traefik plugin** (local or remote) or as a **sidecar/companion service**.

> Built for Traefik users who want actionable security signals without a full SIEM stack.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Plugin Setup (Static Config)](#plugin-setup-static-config)
  - [Method A — Local Plugin](#method-a--local-plugin)
  - [Method B — Remote Plugin](#method-b--remote-plugin)
- [Define & Attach the Middleware (Dynamic Config)](#define--attach-the-middleware-dynamic-config)
- [Docker Compose Example](#docker-compose-example)
- [Configuration Reference](#configuration-reference)
- [Security Heuristics](#security-heuristics)
- [Companion REST API (Optional)](#companion-rest-api-optional)
- [Logging & Observability](#logging--observability)
- [Development](#development)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **Traefik middleware / plugin**: attach per‑router or globally.
- **Dynamic log level**: switch `debug|info|warn|error` at runtime.
- **Security heuristics**: suspicious path matching, regex signatures, brute‑force counters, temporary → permanent escalation.
- **GeoIP enrichment**: country/ASN tagging (when database is provided).
- **Structured logs**: JSON or text; ready for Loki/ELK ingestion.
- **File‑provider actions**: write deny/allow snippets Traefik can hot‑reload.
- **Simple config**: via env vars or dynamic YAML/TOML.
- **Optional REST API**: query events, manage bans, health checks.

---

## Architecture

```
Client → Traefik → [dynamic-logger middleware] → Upstream
                          │
                          ├── Structured logs (JSON)
                          ├── Heuristics (paths/signatures/attempts)
                          ├── GeoIP/ASN enrichment
                          └── Actions: temp/perma ban → writes to Traefik @file
```

- The middleware runs inside Traefik (plugin) and/or as a small companion process.
- Actions are written into a dynamic file that Traefik watches through the **file provider**.

---

## Quick Start

### 1) Clone

```bash
git clone https://github.com/HaeMeto/Traefik-Dynamic-Logger.git
cd Traefik-Dynamic-Logger
```

### 2) (Optional) Build binaries / run API
If you run a companion API:

```bash
cd security_api
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

For the plugin path, follow one of the **Plugin Setup** methods below.

---

## Plugin Setup (Static Config)

You can load **Traefik Dynamic Logger** as:

- **Method A — Local Plugin** (from filesystem), or
- **Method B — Remote Plugin** (fetched from this repo and pinned to a version).

> Static config belongs in `traefik.yml` (or `traefik.toml`, or CLI flags). Examples below use YAML.

### Method A — Local Plugin

**`traefik.yml` (static):**
```yaml
entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"

providers:
  file:
    directory: "/etc/traefik/dynamic"
    watch: true

localPlugins:
  Traefik-Dynamic-Logger:
    moduleName: "github.com/HaeMeto/Traefik-Dynamic-Logger"
```

**Container layout (Docker):** mount the plugin source into Traefik’s expected path:
```
/plugins-local/src/github.com/HaeMeto/Traefik-Dynamic-Logger/...
```

**`docker-compose.yml` (excerpt):**
```yaml
services:
  traefik:
    image: traefik:v3.0
    command:
      - "--providers.file.directory=/etc/traefik/dynamic"
      - "--providers.file.watch=true"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
    volumes:
      - ./traefik/dynamic:/etc/traefik/dynamic
      - ./plugins-local/src/github.com/HaeMeto/Traefik-Dynamic-Logger:/plugins-local/src/github.com/HaeMeto/Traefik-Dynamic-Logger
      - /var/run/docker.sock:/var/run/docker.sock:ro
    ports:
      - "80:80"
      - "443:443"
    restart: unless-stopped
```

### Method B — Remote Plugin

**`traefik.yml` (static):**
```yaml
entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"

providers:
  file:
    directory: "/etc/traefik/dynamic"
    watch: true

plugins:
  Traefik-Dynamic-Logger:
    moduleName: "github.com/HaeMeto/Traefik-Dynamic-Logger"
    version: "v0.1.0"
```

> Traefik will fetch the plugin via its Go module path and pin it to `v0.1.0`. Use your published tag.

---

## Define & Attach the Middleware (Dynamic Config)

Create a dynamic file (served by the file provider), e.g. `/etc/traefik/dynamic/dynamic-logger.yml`:

```yaml
http:
  middlewares:
    dynamic-logger:
      plugin:
        # Use the same key you configured in static:
        # - localPlugins: Traefik-Dynamic-Logger
        # - plugins:      Traefik-Dynamic-Logger
        Traefik-Dynamic-Logger:
          logLevel: "info"         # debug|info|warn|error
          logFormat: "json"        # json|text
          suspiciousPaths:
            - "/.env"
            - "/wp-login.php"
            - "/admin"
          maxAttempts: 10
          permaBanMinutes: 120
          # optional:
          # geoipDB: "/data/GeoLite2-Country.mmdb"
          # patterns:
          #   - "(?i)select.+from.+users"
          #   - "(?i)union.+select"

  routers:
    app:
      rule: "Host(`example.com`)"
      entryPoints: ["websecure"]
      service: app-svc
      middlewares: ["dynamic-logger@file"]

  services:
    app-svc:
      loadBalancer:
        servers:
          - url: "http://app:8080"
```

**Notes**
- The plugin name under `plugin:` **must match** your static config key (`Traefik-Dynamic-Logger`).
- Keep `watch: true` on the file provider for hot reloads.
- You can also declare this middleware globally on entryPoints if desired.

---

## Docker Compose Example

A minimal, ready‑to‑copy setup (remote plugin variant):

```yaml
services:
  traefik:
    image: traefik:v3.0
    command:
      - "--providers.file.directory=/etc/traefik/dynamic"
      - "--providers.file.watch=true"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
    volumes:
      - ./traefik/dynamic:/etc/traefik/dynamic
      - /var/run/docker.sock:/var/run/docker.sock:ro
    ports:
      - "80:80"
      - "443:443"
    restart: unless-stopped

  # Optional companion API for ban/event management
  security_api:
    build: ./security_api
    environment:
      - LOG_LEVEL=info
      - GEOIP_DB=/data/GeoLite2-Country.mmdb
    volumes:
      - ./geoip:/data
    restart: unless-stopped
```

Place your dynamic file at `./traefik/dynamic/dynamic-logger.yml` as shown earlier.

---

## Configuration Reference

You can set options via dynamic YAML/TOML or environment variables (if your wrapper reads them). Common fields:

| Field / Env             | Type     | Description                                                  | Default |
|-------------------------|----------|--------------------------------------------------------------|---------|
| `logLevel` / `LOG_LEVEL`| string   | `debug`, `info`, `warn`, `error`                             | `info`  |
| `logFormat`/`LOG_FORMAT`| string   | `json` or `text`                                             | `json`  |
| `suspiciousPaths`       | list     | Paths that count as suspicious                               | `[]`    |
| `patterns` / `PATTERNS` | list     | Regex signatures to flag/block                               | `[]`    |
| `maxAttempts`           | int      | Attempts before temp block                                   | `10`    |
| `permaBanMinutes`       | int      | Minutes threshold to escalate permanent ban                  | `120`   |
| `geoipDB` / `GEOIP_DB`  | string   | GeoIP database path for country/ASN enrichment               | empty   |

**Structured event** (example):
```json
{
  "event": "blocked",
  "reason": "signature",
  "ip": "203.0.113.10",
  "geo": {"country": "ID"},
  "count": 17,
  "path": "/.env"
}
```

---

## Security Heuristics

- **Signature hit** → immediately mark and optionally **block** (regex‑based match in URL/body).
- **Suspicious path + brute‑force** → if a known‑bad path is hit repeatedly beyond `maxAttempts`, escalate to **temp block**; continued abuse triggers **permanent ban** (`permaBanMinutes`).
- **GeoIP/ASN tagging** helps with triaging; actions remain configurable.

---

## Companion REST API (Optional)

A minimal HTTP API (see `security_api/`) can provide:

- `GET /health` – liveness probe
- `GET /events?limit=100` – recent events
- `POST /ban` – body: `{ "ip": "203.0.113.10", "minutes": 60 }`
- `DELETE /ban/{ip}` – remove a ban
- `GET /bans` – list active bans

This API can write deny rules into Traefik’s dynamic file so bans apply immediately via **@file**.

---

## Logging & Observability

- Logs are **structured** and suitable for **Loki/ELK** ingestion.
- Counters (attempts, blocked, banned) can be exported to Prometheus (roadmap) for Grafana dashboards.
- Consider tailing the dynamic file directory with your log/metrics pipeline for auditability.

---

## Development

```bash
# Format & test (adjust to your code layout)
go fmt ./...
go test ./...

# Python API (optional)
cd security_api
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

---

## FAQ

**Q: Does this replace a WAF?**  
A: No. It’s a lightweight, programmable guardrail and logging layer. You can run it alongside your WAF (e.g., crowdsec/ModSecurity/Cloudflare).

**Q: Can I attach the middleware globally?**  
A: Yes—attach to an entryPoint or declare it in each router that needs protection.

**Q: Where are deny rules written?**  
A: Into the directory served by Traefik’s file provider (e.g., `/etc/traefik/dynamic`). Traefik hot‑reloads changes when `watch: true`.

**Q: Can it run without GeoIP?**  
A: Yes. GeoIP is optional; without it, events won’t include country/ASN enrichment.

---

## Contributing

Issues and PRs are welcome! Please include a clear description, steps to reproduce, and relevant snippets/logs.

---

## License

MIT © HaeMeto. See [`LICENSE`](LICENSE).
