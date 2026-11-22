"""Shared test helpers: isolated temp apps + an adapter so the lab can call the shop in-process."""
import os
import shutil
import sys
import tempfile
import time
import unittest
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("SIM_API_SECRET", "test-secret")

from lab import create_app as create_lab          # noqa: E402
from lab.client import ShopClient                 # noqa: E402
from shop import create_app as create_shop        # noqa: E402
from shop.security import monitor                 # noqa: E402

UA = {"User-Agent": "TestBrowser/1.0"}
SECRET = "test-secret"


class _Resp:
    def __init__(self, r):
        self.status_code, self._r = r.status_code, r

    def json(self):
        data = self._r.get_json(silent=True)
        if data is None:
            raise ValueError("no json")
        return data

    @property
    def text(self):
        return self._r.get_data(as_text=True)


class ShopAdapter:
    """Looks like the `requests` module to lab/client.py, but calls the shop's Flask test client."""
    def __init__(self, shop_app, remote_addr="127.0.0.1"):
        self.shop_app, self.remote_addr = shop_app, remote_addr

    def request(self, method, url, data=None, headers=None, timeout=None):
        client = self.shop_app.test_client()
        r = client.open(urlparse(url).path, method=method, data=data, headers=headers,
                        environ_base={"REMOTE_ADDR": self.remote_addr})
        return _Resp(r)


class BaseCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        monitor._hits.clear(); monitor._beacons.clear(); monitor._beacon_alerted.clear()
        self.shop = create_shop({
            "TESTING": True, "DATABASE": os.path.join(self.tmp, "shop.db"),
            "SANDBOX_FOLDER": os.path.join(self.tmp, "sandbox", "dummy_files"),
            "LOG_FOLDER": os.path.join(self.tmp, "logs"), "SIM_API_SECRET": SECRET,
            "RATE_LIMIT_PER_MINUTE": 100000, "MIDTRANS_SERVER_KEY": "",
        })
        self.lab = create_lab({
            "TESTING": True, "DATABASE": os.path.join(self.tmp, "lab.db"), "SIM_API_SECRET": SECRET,
            "SHOP_URL": "http://127.0.0.1:5000", "TROJAN_MIN_INTERVAL": 0,
        })
        self.lab.extensions["shop_http"] = ShopAdapter(self.shop)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- helpers
    @staticmethod
    def csrf(client, key="_csrf"):
        with client.session_transaction() as s:
            s.setdefault(key, "tok")
            return s[key]

    def shop_login(self, username="budi", password="Customer@123", admin=False):
        c = self.shop.test_client()
        t = self.csrf(c)
        c.post("/admin/login" if admin else "/login", data={"csrf_token": t, "username": username, "password": password},
               headers=UA)
        return c

    def lab_login(self, username="analyst", password="Analyst@123"):
        c = self.lab.test_client()
        t = self.csrf(c)
        c.post("/login", data={"csrf_token": t, "username": username, "password": password}, headers=UA)
        return c

    def lab_post(self, client, url, body=None):
        return client.post(url, json=body or {}, headers={**UA, "X-CSRF-Token": self.csrf(client)})

    def shop_api(self, role="analyst", operator="tester", secret=SECRET, addr="127.0.0.1"):
        return ShopClient("http://127.0.0.1:5000", secret, "seclab-01", operator, role, http=ShopAdapter(self.shop, addr))

    def shop_q(self, sql, args=()):
        from shop.db import query
        with self.shop.app_context():
            return [dict(r) for r in query(sql, args)]

    def events(self, category):
        return self.shop_q("SELECT * FROM security_events WHERE category = ?", (category,))

    def wait(self, seconds):
        time.sleep(seconds)
