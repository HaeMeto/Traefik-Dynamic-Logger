import json

def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data.get("ok") is True
    assert "env" in data

def test_lists_get_empty_defaults(client):
    r = client.get("/lists")
    assert r.status_code == 200
    data = r.json()
    assert "ips" in data and isinstance(data["ips"], list)
    assert "countries" in data and isinstance(data["countries"], list)
    assert "emails" in data and isinstance(data["emails"], list)

def test_lists_update_and_get(client):
    payload = {
        "ips": ["1.2.3.4", " 5.6.7.8 "],
        "countries": ["id", " US "],
        "emails": ["Foo@EXAMPLE.com", " bar@example.org "]
    }
    r = client.post("/lists", json=payload)
    assert r.status_code == 200
    assert r.json().get("ok") is True

    r2 = client.get("/lists")
    data = r2.json()
    # IPs stored as-is (but stripped)
    assert "1.2.3.4" in data["ips"]
    assert "5.6.7.8" in data["ips"]
    # countries uppercased
    assert "ID" in data["countries"]
    assert "US" in data["countries"]
    # emails lowercased
    assert "foo@example.com" in data["emails"]
    assert "bar@example.org" in data["emails"]

def test_ban_and_is_banned(client):
    ip = "9.9.9.9"
    # ban
    r = client.post(f"/ban/{ip}")
    assert r.status_code == 200
    assert r.json().get("ok") is True

    # subsequent /log should be blocked (we send payload with headers to match detection)
    payload = {
        "ip": None,
        "headers": {"X-Forwarded-For": ip},
        "path": "/",
        "body": ""
    }
    r2 = client.post("/log", json=payload)
    assert r2.status_code == 403
    data = r2.json()
    assert data.get("blocked") is True

def test_log_allowed_and_signature_block(client):
    # allowed request (benign body)
    payload_ok = {
        "headers": {"X-Forwarded-For": "123.123.123.123"},
        "path": "/",
        "body": "normal payload"
    }
    r = client.post("/log", json=payload_ok)
    assert r.status_code == 200
    data = r.json()
    assert data.get("ok") is True
    assert "ip" in data

    # signature: SQL injection pattern should cause 403
    payload_bad = {
        "headers": {"X-Forwarded-For": "8.8.8.8"},
        "path": "/wp-login.php",
        "body": "something UNION SELECT password FROM users"
    }
    r2 = client.post("/log", json=payload_bad)
    assert r2.status_code == 403
    data2 = r2.json()
    assert data2.get("blocked") is True
    assert data2.get("reason") in ("signature", "bruteforce")
