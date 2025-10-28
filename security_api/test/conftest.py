import pytest
from fastapi.testclient import TestClient
import types

import sys, os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import main as security_app

class FakeRedis:
    def __init__(self):
        self.sets = {}
        self.kv = {}
    # set operations
    def smembers(self, name):
        return set(self.sets.get(name, []))
    def delete(self, name):
        self.sets.pop(name, None)
        self.kv.pop(name, None)
    def sadd(self, name, *values):
        self.sets.setdefault(name, set()).update(values)
    # simple incr/expire
    def incr(self, key):
        self.kv[key] = int(self.kv.get(key, 0)) + 1
        return self.kv[key]
    def expire(self, key, secs):
        # noop for tests
        return True
    def setex(self, key, seconds, value):
        self.kv[key] = value
    def exists(self, key):
        return 1 if key in self.kv else 0
    def ping(self):
        return True

class FakeGeo:
    class City:
        def __init__(self):
            self.country = types.SimpleNamespace(iso_code="ID")
            self.city = types.SimpleNamespace(name="Jakarta")
    def city(self, ip):
        return FakeGeo.City()

@pytest.fixture(autouse=True)
def stub_redis_and_geo(monkeypatch):
    """
    Replace app.r and app.geo_reader with fakes so tests are deterministic.
    """
    fake_r = FakeRedis()
    fake_geo = FakeGeo()
    # patch
    monkeypatch.setattr(security_app, "r", fake_r)
    monkeypatch.setattr(security_app, "geo_reader", fake_geo)
    # ensure env defaults (optional)
    security_app.BLOCK_COUNTRIES.clear()
    security_app.BLOCK_EMAIL_DOMAINS.clear()
    security_app.BLOCK_IPS.clear()
    yield
    # cleanup (not strictly necessary)
    monkeypatch.setattr(security_app, "r", None)
    monkeypatch.setattr(security_app, "geo_reader", None)

@pytest.fixture
def client():
    return TestClient(security_app.app)
