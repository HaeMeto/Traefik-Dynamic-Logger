import os
import re
import json
import time
from typing import Dict, Any, Optional
from fastapi import FastAPI, Request, Response
from pydantic import BaseModel
from dotenv import load_dotenv
from fastapi import HTTPException
# Optional deps
r = None
geo_reader = None
LIST_KEY_IPS = "lists:ips"
LIST_KEY_CC  = "lists:countries"
LIST_KEY_EM  = "lists:emails"

def get_list(name: str):
    if not r:
        return []
    try:
        return r.smembers(name)
    except Exception:
        return []

def set_list(name: str, values):
    if not r:
        return
    try:
        r.delete(name)
        if values:
            r.sadd(name, *values)
    except Exception:
        pass



load_dotenv()

# Try Redis
try:
    import redis
    r = redis.Redis(
        host=os.getenv("REDIS_HOST", "redis"),
        port=int(os.getenv("REDIS_PORT", "6379")),
        db=int(os.getenv("REDIS_DB", "0")),
        decode_responses=True,
    )
except Exception:
    r = None

# Try GeoIP2
try:
    import geoip2.database
    GEOIP_DB = os.getenv("GEOIP_DB", "/geoip/GeoLite2-City.mmdb")
    if os.path.exists(GEOIP_DB):
        geo_reader = geoip2.database.Reader(GEOIP_DB)
except Exception:
    geo_reader = None

APP_ENV = os.getenv("APP_ENV", "dev")
BRUTE_WINDOW_SEC = int(os.getenv("BRUTE_WINDOW_SEC", "300"))
BRUTE_MAX_ATTEMPTS = int(os.getenv("BRUTE_MAX_ATTEMPTS", "30"))
PERMA_BAN_MIN = int(os.getenv("PERMA_BAN_MIN", "1440"))  # 1 hari

# Simple patterns (kasar—bisa kamu upgrade)
PATTERNS = [
    r"(?i)\bunion\s+select\b",
    r"(?i)\bdrop\s+table\b",
    r"(?i)\bsleep\s*\(",
    r"(?i)\bor\s+1\s*=\s*1\b",
    r"(?i)<\s*script\b",
    r"(?i)etc/passwd",
    r"(?i)\bselect\b.+\bfrom\b",
    r"(?i)\bupdate\b.+\bset\b",
    r"(?i)\bdelete\b.+\bfrom\b",
    r"(?i)\bwget\b|\bcurl\b",
]

SUS_PATH = [
    "/wp-admin", "/wp-login.php", "/phpmyadmin", "/.env", "/admin",
]

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


def geoip(ip: str) -> Dict[str, Any]:
    if not geo_reader or not ip:
        return {}
    try:
        g = geo_reader.city(ip)
        return {
            "country": (g.country.iso_code or ""),
            "city": (g.city.name or ""),
            "asn": "",
        }
    except Exception:
        return {}


def incr_bruteforce(ip: str) -> int:
    """
    Sliding window sederhana pakai Redis.
    """
    if not r or not ip:
        return 0
    key = f"bf:{ip}:{int(time.time() // BRUTE_WINDOW_SEC)}"
    try:
        n = r.incr(key)
        r.expire(key, BRUTE_WINDOW_SEC + 60)
        return n
    except Exception:
        return 0


def perma_ban(ip: str, minutes: int = PERMA_BAN_MIN):
    if not r or not ip:
        return
    try:
        r.setex(f"ban:{ip}", minutes * 60, "1")
    except Exception:
        pass


def is_banned(ip: str) -> bool:
    if not r or not ip:
        return False
    try:
        return r.exists(f"ban:{ip}") == 1
    except Exception:
        return False


@app.get("/health")
def health():
    return {"ok": True, "env": APP_ENV}


@app.post("/ban/{ip}")
def ban_ip(ip: str, minutes: int = PERMA_BAN_MIN):
    perma_ban(ip, minutes)
    return {"ok": True, "ip": ip, "minutes": minutes}


@app.post("/log")
async def log_endpoint(data: LogModel, request: Request):
    ip = data.ip or request.client.host
    # Hard ban check
    if is_banned(ip):
        # Plugin akan cache block berdasarkan 403
        return Response(content=json.dumps({"blocked": True, "reason": "permanent"}),
                        media_type="application/json", status_code=403)

    # GeoIP (optional)
    g = geoip(ip)

    # Brute-force counter (berbasis request count)
    count = incr_bruteforce(ip)

    # Heuristik cepat
    body = (data.body or "")[:65536]
    path = data.path or ""
    hit_sus_path = any(path.startswith(p) for p in SUS_PATH)
    hit_sig = any(re.search(p, body) for p in PATTERNS)

    # Kriteria block:
    # 1) pattern SQLi/XSS dll terdeteksi
    # 2) request ke path mencurigakan + rate tinggi
    # 3) kombinasi keduanya
    if hit_sig or (hit_sus_path and count > BRUTE_MAX_ATTEMPTS):
        # opsional: simpan perma ban
        if r and (hit_sig and count > BRUTE_MAX_ATTEMPTS*2):
            perma_ban(ip, PERMA_BAN_MIN)

        # balas 403 → plugin akan cache (blockTTL)
        return Response(
            content=json.dumps({
                "blocked": True,
                "reason": "signature" if hit_sig else "bruteforce",
                "ip": ip,
                "geo": g,
                "count": count
            }),
            media_type="application/json",
            status_code=403
        )

    # Jika aman
    return {
        "ok": True,
        "ip": ip,
        "geo": g,
        "count": count,
        "path": path
    }

@app.get("/lists")
def get_lists():
    ips = list(get_list(LIST_KEY_IPS))
    cc  = [c.upper() for c in get_list(LIST_KEY_CC)]
    ems = [e.lower() for e in get_list(LIST_KEY_EM)]
    # fallback gabung dengan ENV defaults
    ips = list(set(ips + list(BLOCK_IPS)))
    cc  = list(set(cc + [c.upper() for c in BLOCK_COUNTRIES]))
    ems = list(set(ems + [d.lower() for d in BLOCK_EMAIL_DOMAINS]))
    return {"ips": ips, "countries": cc, "emails": ems}

class ListsPayload(BaseModel):
    ips: Optional[list[str]] = None
    countries: Optional[list[str]] = None
    emails: Optional[list[str]] = None

@app.post("/lists")
def update_lists(p: ListsPayload):
    # simple auth bisa pakai reverse proxy auth kalau perlu
    if p.ips is not None:
        set_list(LIST_KEY_IPS, [i.strip() for i in p.ips if i.strip()])
    if p.countries is not None:
        set_list(LIST_KEY_CC, [c.strip().upper() for c in p.countries if c.strip()])
    if p.emails is not None:
        set_list(LIST_KEY_EM, [e.strip().lower() for e in p.emails if e.strip()])
    json_log({"type":"lists_update","ips":p.ips,"countries":p.countries,"emails":p.emails,"ts":time.time()})
    return {"ok": True}