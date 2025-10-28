# tests/test_security_rules.py
import time
import json

def post_log(client, ip, path="/", body="normal payload", extra_headers=None):
    """
    Helper: kirim payload ke /log mirip plugin Traefik.
    original_headers diisi X-Forwarded-For agar get_client_ip_from_payload bisa ambil IP.
    """
    headers = {
        "Content-Type": "application/json",
        "X-Forwarded-For": ip,
        "CF-IPCountry": "ID",
        "Host": "example.com",
    }
    if extra_headers:
        headers.update(extra_headers)
    payload = {"headers": headers, "path": path, "body": body}
    return client.post("/log", json=payload, headers=headers)

def test_bruteforce_triggers_block(client, monkeypatch):
    # ambil threshold dari aplikasi
    import main as security_app
    ip = "10.100.100.1"

    # hit sampai melebihi BRUTE_MAX_ATTEMPTS
    threshold = security_app.BRUTE_MAX_ATTEMPTS

    # pastikan awalnya tidak terblok
    r0 = post_log(client, ip, path="/")
    assert r0.status_code == 200

    # kirim threshold kali (masih allowed)
    for i in range(threshold):
        r = post_log(client, ip, path="/")
        # tetap allowed sampai melewati threshold
        assert r.status_code in (200, 200)

    # satu request lagi harus memicu bruteforce block apabila path suspicious atau body pattern
    # in code: block condition is (hit_sus_path and count > BRUTE_MAX_ATTEMPTS)
    # so simulate access to suspicious path to trigger behavior
    r_block = post_log(client, ip, path="/.env", body="normal")
    assert r_block.status_code == 403
    data = r_block.json()
    assert data.get("blocked") is True

def test_signature_sql_injection_blocks_immediately(client):
    ip = "8.8.8.8"
    # kirim payload yang mengandung pattern SQLi
    payload_body = "name=foo UNION SELECT password FROM users WHERE '1'='1'"
    r = post_log(client, ip, path="/", body=payload_body)
    assert r.status_code == 403
    data = r.json()
    assert data.get("blocked") is True
    # reason biasanya "signature"
    assert data.get("reason") in ("signature", "bruteforce")

def test_sus_path_rate_and_then_ban_endpoint(client):
    import main as security_app
    ip = "172.200.200.5"
    threshold = security_app.BRUTE_MAX_ATTEMPTS

    # spam accesses to suspicious path until blocked
    for i in range(threshold + 1):
        r = post_log(client, ip, path="/.env", body="normal")
    assert r.status_code == 403
    assert r.json().get("blocked") is True

    # now test explicit ban endpoint sets ban flag
    rban = client.post(f"/ban/{ip}")
    assert rban.status_code == 200
    assert rban.json().get("ok") is True

    # after ban, requests return 403 (permanent)
    r_after = post_log(client, ip, path="/", body="ok")
    assert r_after.status_code == 403
    assert r_after.json().get("blocked") is True

def test_multiple_sus_paths_list_detection(client):
    # check several disallowed paths detection (quick smoke)
    bad_paths = ["/.env", "/wp-login.php", "/phpmyadmin", "/.git/config"]
    ip = "203.0.113.10"
    for p in bad_paths:
        r = post_log(client, ip, path=p, body="innocent")
        # if path is in SUS_PATH and counter low, might still be allowed; we check signature detection not necessary here
        # ensure endpoint returns either 200 or 403 but not 500
        assert r.status_code in (200, 403)
