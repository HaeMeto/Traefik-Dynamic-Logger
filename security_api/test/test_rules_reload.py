# test/test_rules_reload.py
import json
import os
from pathlib import Path
import main as security_app

def write_rules(path, patterns=None, sus_paths=None):
    data = {
        "patterns": patterns or [],
        "sus_paths": sus_paths or []
    }
    path.write_text(json.dumps(data), encoding="utf-8")

def test_reload_rules_endpoint_and_runtime_effect(client, tmp_path, monkeypatch):
    """
    1) tulis rules.json baru dengan sebuah pattern unik dan satu sus_path unik
    2) set RULES_PATH ke file tersebut (monkeypatch)
    3) panggil endpoint /reload-rules (POST)
    4) verifikasi loader memuat pattern dan sus_path
    5) kirim request yang mengandung pattern -> harus 403
    6) kirim request ke sus_path -> depending on count may block (we check status code)
    """
    # 1. buat rules file di tmp
    rules_file = tmp_path / "rules_test.json"
    unique_pattern = r"BAD_INJECTION_ABC123"   # pattern literal
    unique_sus = "/forbidden-file-abc123"
    write_rules(rules_file, patterns=[unique_pattern], sus_paths=[unique_sus])

    # 2. override env RULES_PATH dan panggil reload
    monkeypatch.setenv("RULES_PATH", str(rules_file))
    # call reload endpoint
    r = client.post("/reload-rules")
    assert r.status_code == 200
    resp = r.json()
    assert resp.get("ok") is True
    assert resp.get("patterns", 0) == 1
    assert resp.get("sus_paths", 0) == 1

    # 3. pastikan internal compiled patterns updated
    assert len(security_app._PATTERNS_COMPILED) == 1
    assert security_app._SUS_PATHS and unique_sus in security_app._SUS_PATHS

    # 4. kirim payload yang memicu pattern
    ip = "198.51.100.5"
    body = f"this is an attack: {unique_pattern}()"
    payload = {"headers": {"X-Forwarded-For": ip, "Host": "example.com"}, "path": "/", "body": body}
    r2 = client.post("/log", json=payload)
    assert r2.status_code == 403
    data = r2.json()
    assert data.get("blocked") is True
    assert data.get("reason") in ("signature", "bruteforce")

    # 5. kirim ke sus_path — depending on rate it may be 200 or 403; ensure no 500
    payload2 = {"headers": {"X-Forwarded-For": ip, "Host": "example.com"}, "path": unique_sus, "body": "innocent"}
    r3 = client.post("/log", json=payload2)
    assert r3.status_code in (200, 403)


def test_rules_fallback_when_file_missing(monkeypatch, tmp_path):
    # set RULES_PATH ke lokasi yang tidak ada
    missing = tmp_path / "no-such-file.json"
    monkeypatch.setenv("RULES_PATH", str(missing))
    # panggil loader langsung (atau via endpoint)
    security_app.load_rules()
    # harus fallback ke default
    assert len(security_app._PATTERNS_COMPILED) >= 1
    assert len(security_app._SUS_PATHS) >= 1