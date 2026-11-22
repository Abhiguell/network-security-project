"""The signed simulation API between the two websites."""
import hashlib
import json
import time

from helpers import SECRET, UA, BaseCase
from lab.client import ShopAPIError, sign


class TestAPIAuth(BaseCase):
    def test_unsigned_request_rejected(self):
        r = self.shop.test_client().post("/api/sim/spyware/collect", json={}, headers=UA)
        self.assertEqual(r.status_code, 401)
        self.assertTrue(self.events("Unauthorized Simulation API Access"))

    def test_wrong_secret_rejected(self):
        with self.assertRaises(ShopAPIError) as ctx:
            self.shop_api(secret="not-the-secret").status()
        self.assertEqual(ctx.exception.status, 401)

    def test_replay_rejected(self):
        body = json.dumps({"limit": 5}).encode()
        ts, nonce = str(int(time.time())), "ab" * 16
        h = {"X-Lab-Client": "seclab-01", "X-Lab-Timestamp": ts, "X-Lab-Nonce": nonce, "X-Lab-Operator": "eve",
             "X-Lab-Role": "analyst", "Content-Type": "application/json", **UA,
             "X-Lab-Signature": sign(SECRET, "POST", "/api/sim/spyware/collect", ts, nonce, "eve", "analyst", body)}
        c = self.shop.test_client()
        self.assertEqual(c.post("/api/sim/spyware/collect", data=body, headers=h).status_code, 200)
        r = c.post("/api/sim/spyware/collect", data=body, headers=h)       # exact same request again
        self.assertEqual(r.status_code, 401)
        self.assertIn("Replay", r.get_json()["message"])

    def test_expired_timestamp_rejected(self):
        ts, nonce, body = str(int(time.time()) - 600), "cd" * 16, b""
        h = {"X-Lab-Client": "seclab-01", "X-Lab-Timestamp": ts, "X-Lab-Nonce": nonce, "X-Lab-Operator": "eve",
             "X-Lab-Role": "analyst", **UA,
             "X-Lab-Signature": sign(SECRET, "GET", "/api/sim/status", ts, nonce, "eve", "analyst", body)}
        self.assertEqual(self.shop.test_client().get("/api/sim/status", headers=h).status_code, 401)

    def test_viewer_role_and_public_ip_and_disabled(self):
        with self.assertRaises(ShopAPIError) as ctx:
            self.shop_api(role="viewer").spyware_collect()
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(ShopAPIError) as ctx:
            self.shop_api(addr="8.8.8.8").status()
        self.assertEqual(ctx.exception.status, 403)
        from shop.db import set_setting
        with self.shop.app_context():
            set_setting("sim_api_enabled", "0")
        with self.assertRaises(ShopAPIError) as ctx:
            self.shop_api().status()
        self.assertIn("disabled", ctx.exception.message)


class TestSimulationEffects(BaseCase):
    def _real_snapshot(self):
        rows = self.shop_q("SELECT * FROM users WHERE is_synthetic = 0 ORDER BY id") + \
               self.shop_q("SELECT * FROM orders WHERE is_synthetic = 0 ORDER BY id")
        return hashlib.sha256(json.dumps(rows, sort_keys=True, default=str).encode()).hexdigest()

    def test_spyware_only_synthetic_and_real_data_untouched(self):
        before = self._real_snapshot()
        data = self.shop_api().spyware_collect(50)
        self.assertEqual(data["count"], 25)
        self.assertTrue(all(r["email"].endswith("@example.com") for r in data["records"]))
        self.assertTrue(all("budi" not in r["email"] and "admin" not in r["email"] for r in data["records"]))
        self.assertTrue(all("hash" not in json.dumps(r).replace("salted hash", "") for r in data["records"]))
        self.assertEqual(before, self._real_snapshot())
        self.assertTrue(self.events("Spyware Data Exposure"))
        self.assertEqual(self.shop_q("SELECT kind, status FROM incidents"), [{"kind": "spyware", "status": "open"}])

    def test_ransomware_start_reset_integrity(self):
        api = self.shop_api()
        before = {f["name"]: f["sha256"] for f in api.ransomware_state()["files"]}
        r = api.ransomware_start()
        self.assertTrue(r["attacked"])
        self.assertEqual(before, {f["name"]: f["sha256"] for f in r["files"]})
        self.assertTrue(self.shop_q("SELECT * FROM incidents WHERE kind='ransomware' AND status='open'"))
        r = api.ransomware_reset()
        self.assertTrue(r["integrity_ok"])
        self.assertFalse(self.shop_q("SELECT * FROM incidents WHERE kind='ransomware' AND status='open'"))

    def test_trojan_beacon_detection_and_reset(self):
        api = self.shop_api()
        api.trojan_event("install", "TRJ-TEST")
        detected = [api.trojan_event("beacon", "TRJ-TEST", i, 200).get("detected") for i in range(1, 7)]
        self.assertTrue(any(detected))
        self.assertTrue(self.events("C2 Beaconing"))
        self.assertTrue(self.events("Suspicious Application"))
        res = api.reset_all()
        self.assertGreaterEqual(res["incidents_resolved"], 1)
        self.assertFalse(self.shop_q("SELECT * FROM incidents WHERE status = 'open'"))
        self.assertFalse(self.shop_q("SELECT * FROM sim_traffic"))
