"""Website 2 (CyberSim Lab): auth, roles and end-to-end simulations against the store."""
import requests

from helpers import UA, BaseCase


class TestLabAccess(BaseCase):
    def test_pages_require_login(self):
        c = self.lab.test_client()
        self.assertEqual(c.get("/", headers=UA).status_code, 302)
        self.assertEqual(c.get("/api/status", headers=UA).status_code, 401)

    def test_pages_render(self):
        c = self.lab_login()
        for url in ["/", "/module/spyware", "/module/ransomware", "/module/trojan", "/events", "/api/status",
                    "/api/ransomware/state"]:
            self.assertEqual(c.get(url, headers=UA).status_code, 200, url)
        self.assertTrue(c.get("/api/status", headers=UA).get_json()["online"])

    def test_viewer_cannot_run(self):
        c = self.lab_login("viewer", "Viewer@123")
        self.assertEqual(self.lab_post(c, "/api/spyware/start").status_code, 403)
        self.assertFalse(self.shop_q("SELECT * FROM incidents"))

    def test_csrf_required(self):
        c = self.lab_login()
        r = c.post("/api/spyware/start", json={}, headers=UA)
        self.assertEqual(r.status_code, 400)


class TestEndToEnd(BaseCase):
    def run_and_get(self, client, url, body=None):
        r = self.lab_post(client, url, body)
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        return client.get(f"/api/runs/{r.get_json()['run_id']}", headers=UA).get_json()

    def test_spyware_from_lab_reaches_store(self):
        c = self.lab_login()
        run = self.run_and_get(c, "/api/spyware/start")
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["records"], 25)
        self.assertTrue(any("SYNTHETIC" in l["message"] for l in run["logs"]))
        ev = self.events("Spyware Data Exposure")[0]
        self.assertEqual(ev["source"], "simulation")
        self.assertEqual(ev["username"], "lab:analyst")                # audit trail names the lab operator

    def test_phishing_lure_follows_spyware_and_reset_removes_it(self):
        shopper = self.shop_login()
        self.assertNotIn("phishLure", shopper.get("/", headers=UA).get_data(as_text=True))
        c = self.lab_login()
        self.run_and_get(c, "/api/spyware/start")
        page = shopper.get("/", headers=UA).get_data(as_text=True)
        self.assertIn("Verify my account now", page)
        notice = shopper.get("/account-verification", headers=UA).get_data(as_text=True)
        self.assertIn("simulated", notice)
        self.assertNotIn("<input", notice.split("<main", 1)[1].split("</main>")[0])   # collects nothing
        self.assertTrue(self.events("Phishing Lure Clicked"))
        admin = self.shop_login("admin", "Admin@12345", admin=True)
        self.assertNotIn("phishLure", admin.get("/admin/", headers=UA).get_data(as_text=True))
        self.run_and_get(c, "/api/reset")
        self.assertNotIn("phishLure", shopper.get("/", headers=UA).get_data(as_text=True))

    def test_ransomware_from_lab(self):
        c = self.lab_login()
        run = self.run_and_get(c, "/api/ransomware/start")
        self.assertEqual(run["status"], "completed")
        self.assertTrue(all(f["locked"] for f in run["result"]["files"]))
        run = self.run_and_get(c, "/api/ransomware/reset")
        self.assertTrue(run["result"]["integrity_ok"])

    def test_trojan_from_lab_recorded_in_both_dashboards(self):
        c = self.lab_login("labadmin", "LabAdmin@123")
        run = self.run_and_get(c, "/api/trojan/start", {"interval": 0, "count": 8})
        self.assertEqual(run["status"], "completed")
        kinds = [t["kind"] for t in run["result"]["traffic"]]
        self.assertEqual(kinds.count("beacon"), 8)
        self.assertIn("exfil", kinds)
        self.assertTrue(self.events("C2 Beaconing"))
        self.assertTrue(self.shop_q("SELECT * FROM sim_traffic WHERE module='trojan' AND kind='beacon'"))
        from lab.db import query
        with self.lab.app_context():
            self.assertTrue(query("SELECT * FROM lab_events WHERE module='trojan'"))

    def test_reset_environment(self):
        c = self.lab_login()
        self.run_and_get(c, "/api/spyware/start")
        self.run_and_get(c, "/api/ransomware/start")
        run = self.run_and_get(c, "/api/reset")
        self.assertEqual(run["status"], "completed")
        self.assertFalse(self.shop_q("SELECT * FROM incidents WHERE status='open'"))

    def test_store_offline_handled(self):
        class Down:
            def request(self, *a, **k):
                raise requests.ConnectionError("down")
        self.lab.extensions["shop_http"] = Down()
        c = self.lab_login()
        run = self.run_and_get(c, "/api/spyware/start")
        self.assertEqual(run["status"], "failed")
        self.assertFalse(c.get("/api/status", headers=UA).get_json()["online"])
