# app.py — versi ringkas & lebih ringan
import os
import time
import json
import socket
import logging
import ipaddress
import re
from typing import Any, Dict, Optional
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response
from pydantic import BaseModel

# load env dulu supaya LOG_PATH / konfigurasi tersedia
load_dotenv()

# ---------- konfigurasi ----------
APP_ENV = os.getenv("APP_ENV", "dev")
LOG_PATH = os.getenv("SECURITY_LOG", "/var/log/security_api/log.json")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

BRUTE_WINDOW_SEC = int(os.getenv("BRUTE_WINDOW_SEC", "300"))
BRUTE_MAX_ATTEMPTS = int(os.getenv("BRUTE_MAX_ATTEMPTS", "30"))
PERMA_BAN_MIN = int(os.getenv("PERMA_BAN_MIN", "1440"))

# DENY lists from env (simple)
def _env_set(name: str) -> set[str]:
    raw = os.getenv(name, "")
    return {p.strip() for p in raw.split(",") if p.strip()} if raw else set()

BLOCK_COUNTRIES = {c.upper() for c in _env_set("BLOCK_COUNTRIES")}
BLOCK_EMAIL_DOMAINS = {d.lower() for d in _env_set("BLOCK_EMAIL_DOMAINS")}
BLOCK_IPS = _env_set("BLOCK_IPS")

# patterns & suspicious paths (simple heuristics)
PATTERNS = [
    r"(?i)\bunion\s+select\b", r"(?i)\bdrop\s+table\b", r"(?i)<\s*script\b",
    r"(?i)\bsleep\s*\(", r"(?i)\bor\s+1\s*=\s*1\b", r"(?i)etc/passwd",
    r"(?i)\bselect\b.+\bfrom\b", r"(?i)\bupdate\b.+\bset\b", r"(?i)\bdelete\b.+\bfrom\b",
]
SUS_PATH = ["/wp-admin", "/wp-login.php", "/phpmyadmin", "/.env", "/admin"]

# ---------- logging (JSONL) ----------
logging.basicConfig(filename=LOG_PATH, level=logging.INFO, format="%(message)s")
def rfc3339_nano_now() -> str:
    ns = time.time_ns()
    s, rem = divmod(ns, 1_000_000_000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(s)) + f".{rem:09d}Z"

def json_log(event: str | Dict[str, Any], **extra: Any) -> None:
    """Satu baris JSON ke file + stdout. event bisa str atau dict untuk fleksibilitas."""
    if isinstance(event, dict):
        data = {**event}
    else:
        data = {"event": event}
    data.setdefault("ts", rfc3339_nano_now())
    data.update(extra)
    line = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    logging.info(line)
    print(line, flush=True)

# ---------- optional deps (redis, geoip) ----------
r = None
geo_reader = None
try:
    import redis
    r = redis.Redis(
        host=os.getenv("REDIS_HOST", "redis"),
        port=int(os.getenv("REDIS_PORT", "6379")),
        db=int(os.getenv("REDIS_DB", "0")),
        decode_responses=True,
        socket_connect_timeout=1,
    )
    # quick smoke test (don't raise)
    r.ping()
except Exception:
    r = None

try:
    import geoip2.database
    GEOIP_DB = os.getenv("GEOIP_DB", "/geoip/GeoLite2-City.mmdb")
    if os.path.exists(GEOIP_DB):
        geo_reader = geoip2.database.Reader(GEOIP_DB)
except Exception:
    geo_reader = None

# ---------- helpers IP / headers ----------
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def _is_public_ip(ip: str) -> bool:
    if not ip:
        return False
    try:
        ipobj = ipaddress.ip_address(ip.strip())
        if ipobj.is_loopback or ipobj.is_multicast or ipobj.is_reserved or ipobj.is_link_local:
            return False
        for net in _PRIVATE_NETS:
            if ipobj in net:
                return False
        return True
    except Exception:
        return False

def _get_hdr(d: Optional[dict], key: str) -> str:
    if not d: return ""
    v = d.get(key) or d.get(key.lower()) or d.get(key.title())
    if isinstance(v, list):
        return v[0] if v else ""
    return str(v) if v is not None else ""

def _first_public_from_list(header_value: str) -> str:
    if not header_value: return ""
    for p in (p.strip() for p in header_value.split(",") if p.strip()):
        if _is_public_ip(p):
            return p
    return ""

def get_client_ip_from_payload(headers: Optional[dict], fallback_ip: str) -> str:
    h = headers or {}
    ip = _get_hdr(h, "CF-Connecting-IP")
    if _is_public_ip(ip): return ip
    ip = _get_hdr(h, "X-Real-IP")
    if _is_public_ip(ip): return ip
    ip = _first_public_from_list(_get_hdr(h, "X-Forwarded-For"))
    if ip: return ip
    return fallback_ip or ""

def get_country_from_payload(headers: Optional[dict], ip: str) -> str:
    h = headers or {}
    cc = (_get_hdr(h, "CF-IPCountry") or _get_hdr(h, "X-Sec-Country") or "").upper()
    if cc: return cc
    # fallback to geoip if available
    try:
        if geo_reader and ip:
            g = geo_reader.city(ip)
            return (g.country.iso_code or "").upper()
    except Exception:
        pass
    return ""

def get_local_ips() -> list[str]:
    ips = set()
    try:
        name = socket.gethostname()
        for ai in socket.getaddrinfo(name, None):
            ips.add(ai[4][0])
    except Exception:
        pass
    return sorted(ips)

def build_client_chain(headers: dict, remote: str) -> list[str]:
    chain = []
    cf = headers.get("CF-Connecting-IP") or headers.get("cf-connecting-ip")
    if cf: chain.append(f"{cf} (CF-Connecting-IP)")
    xr = headers.get("X-Real-IP") or headers.get("x-real-ip")
    if xr: chain.append(f"{xr} (X-Real-IP)")
    xff = headers.get("X-Forwarded-For") or headers.get("x-forwarded-for")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            chain.append(f"{' -> '.join(parts)} (X-Forwarded-For)")
    chain.append(f"{remote} (RemoteAddr)")
    return chain

# ---------- Redis-backed helpers ----------
def incr_bruteforce(ip: str) -> int:
    if not r or not ip: return 0
    key = f"bf:{ip}:{int(time.time() // BRUTE_WINDOW_SEC)}"
    try:
        n = r.incr(key)
        r.expire(key, BRUTE_WINDOW_SEC + 60)
        return int(n)
    except Exception:
        return 0

def perma_ban(ip: str, minutes: int = PERMA_BAN_MIN) -> None:
    if not r or not ip: return
    try:
        r.setex(f"ban:{ip}", minutes * 60, "1")
    except Exception:
        pass

def is_banned(ip: str) -> bool:
    if not r or not ip: return False
    try:
        return r.exists(f"ban:{ip}") == 1
    except Exception:
        return False

# ---------- lists (Redis-backed optional) ----------
LIST_KEY_IPS = "lists:ips"
LIST_KEY_CC  = "lists:countries"
LIST_KEY_EM  = "lists:emails"

def get_list(name: str) -> list:
    if not r: return []
    try:
        return list(r.smembers(name) or [])
    except Exception:
        return []

def set_list(name: str, values: list) -> None:
    if not r: return
    try:
        r.delete(name)
        if values:
            r.sadd(name, *values)
    except Exception:
        pass

# ---------- FastAPI endpoints ----------
app = FastAPI(title="Security API", version="1.0.0")

class LogModel(BaseModel):
    ip: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    query: Optional[str] = None
    host: Optional[str] = None
    headers: Optional[Dict[str, Any]] = None
    body: Optional[str] = None
    ts: Optional[str] = None

@app.get("/health")
def health():
    return {"ok": True, "env": APP_ENV}

@app.post("/ban/{ip}")
def ban_ip(ip: str, minutes: int = PERMA_BAN_MIN):
    perma_ban(ip, minutes)
    return {"ok": True, "ip": ip, "minutes": minutes}

@app.post("/log")
async def log_endpoint(data: LogModel, request: Request):
    # payload berasal dari plugin (Traefik plugin / proxy) — gunakan payload headers bila ada
    original_headers = data.headers or {}
    fallback_remote = request.client.host if request.client else ""
    ip = get_client_ip_from_payload(original_headers, fallback_remote)
    country = get_country_from_payload(original_headers, ip)
    path = data.path or request.url.path
    method = data.method or request.method
    host = data.host or _get_hdr(original_headers, "Host")
    body = (data.body or "")[:65536]

    # log primary event (JSON)
    json_log({
        "event": "request",
        "ip": ip,
        "country": country,
        "method": method,
        "path": path,
        "host": host,
        "headers": original_headers,
    })

    # hard ban
    if is_banned(ip):
        # detail log
        json_log({"event": "blocked", "reason": "permanent", "ip": ip})
        return Response(content=json.dumps({"blocked": True, "reason": "permanent"}), media_type="application/json", status_code=403)

    # quick geo + counter
    geo = {}
    try:
        if geo_reader and ip:
            g = geo_reader.city(ip)
            geo = {"country": g.country.iso_code or "", "city": g.city.name or ""}
    except Exception:
        geo = {}

    count = incr_bruteforce(ip)

    # heuristics
    hit_sus_path = any(path.startswith(p) for p in SUS_PATH)
    hit_sig = any(re.search(p, body) for p in PATTERNS)

    if hit_sig or (hit_sus_path and count > BRUTE_MAX_ATTEMPTS):
        if r and hit_sig and count > BRUTE_MAX_ATTEMPTS * 2:
            perma_ban(ip, PERMA_BAN_MIN)
        json_log({"event": "blocked", "reason": "signature" if hit_sig else "bruteforce", "ip": ip, "count": count})
        return Response(
            content=json.dumps({"blocked": True, "reason": "signature" if hit_sig else "bruteforce", "ip": ip, "geo": geo, "count": count}),
            media_type="application/json",
            status_code=403,
        )

    # allowed — log one-line summary
    summary = {
        "event": "allowed",
        "ts": rfc3339_nano_now(),
        "hostname": socket.gethostname(),
        "remoteAddr": f"{fallback_remote}:{getattr(request.client, 'port', '')}" if request.client else fallback_remote,
        "clientIp": ip,
        "country": country, 
        "geo": geo,
        "clientChain": build_client_chain(original_headers, fallback_remote),
        "method": method,
        "path": path,
        "proto": request.scope.get("http_version", "HTTP/1.1"),
        "host": host,
        "localIPs": get_local_ips(),
    }
    json_log(summary)

    return {"ok": True, "ip": ip, "country": country, "geo": geo, "count": count, "path": path}

@app.get("/lists")
def get_lists():
    ips = list(get_list(LIST_KEY_IPS))
    cc = [c.upper() for c in get_list(LIST_KEY_CC)]
    ems = [e.lower() for e in get_list(LIST_KEY_EM)]
    # fallback gabung dengan ENV defaults
    ips = list(set(ips + list(BLOCK_IPS)))
    cc = list(set(cc + [c.upper() for c in BLOCK_COUNTRIES]))
    ems = list(set(ems + [d.lower() for d in BLOCK_EMAIL_DOMAINS]))
    return {"ips": ips, "countries": cc, "emails": ems}

class ListsPayload(BaseModel):
    ips: Optional[list[str]] = None
    countries: Optional[list[str]] = None
    emails: Optional[list[str]] = None

@app.post("/lists")
def update_lists(p: ListsPayload):
    if p.ips is not None:
        set_list(LIST_KEY_IPS, [i.strip() for i in p.ips if i and i.strip()])
    if p.countries is not None:
        set_list(LIST_KEY_CC, [c.strip().upper() for c in p.countries if c and c.strip()])
    if p.emails is not None:
        set_list(LIST_KEY_EM, [e.strip().lower() for e in p.emails if e and e.strip()])
    json_log({"event": "lists_update", "ips": p.ips, "countries": p.countries, "emails": p.emails})
    return {"ok": True}
