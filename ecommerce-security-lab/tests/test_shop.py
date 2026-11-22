"""Website 1 (LabMart store): features, payments and web security."""
import hashlib
from unittest import mock

from helpers import UA, BaseCase


class TestStore(BaseCase):
    def test_public_pages(self):
        c = self.shop.test_client()
        for url in ["/", "/products", "/products?category=Fashion", "/product/1", "/cart", "/login", "/register"]:
            self.assertEqual(c.get(url, headers=UA).status_code, 200, url)

    def test_register_and_profile(self):
        c = self.shop.test_client()
        t = self.csrf(c)
        r = c.post("/register", data={"csrf_token": t, "username": "siti", "full_name": "Siti Test", "email": "siti@test.dev",
                                       "phone": "081299990000", "password": "Str0ng!Pass", "confirm_password": "Str0ng!Pass"},
                   headers=UA)
        self.assertEqual(r.status_code, 302)
        row = self.shop_q("SELECT is_synthetic FROM users WHERE username='siti'")[0]
        self.assertEqual(row["is_synthetic"], 0)                       # real accounts are never synthetic

    def test_full_checkout_demo_gateway(self):
        c = self.shop_login()
        t = self.csrf(c)
        stock_before = self.shop_q("SELECT stock FROM products WHERE id=1")[0]["stock"]
        c.post("/cart/add", data={"csrf_token": t, "product_id": 1, "qty": 2}, headers=UA)
        r = c.post("/checkout", data={"csrf_token": t, "shipping_name": "Budi Demo", "shipping_phone": "081200000001",
                                      "address": "Kampus Lab Ruang 204", "city": "Cikarang"}, headers=UA)
        self.assertIn("/pay/demo/", r.headers["Location"])
        r = c.post(r.headers["Location"], data={"csrf_token": t, "action": "pay"}, headers=UA)
        order = self.shop_q("SELECT * FROM orders WHERE is_synthetic = 0")[0]
        self.assertEqual(order["status"], "paid")
        self.assertEqual(order["total"], 2 * 459000)                   # price comes from the DB, not the browser
        self.assertEqual(self.shop_q("SELECT stock FROM products WHERE id=1")[0]["stock"], stock_before - 2)
        self.assertEqual(c.get("/account/orders", headers=UA).status_code, 200)

    def test_order_idor_blocked(self):
        code = self.shop_q("SELECT order_code FROM orders WHERE is_synthetic = 1 LIMIT 1")[0]["order_code"]
        c = self.shop_login()
        self.assertEqual(c.get(f"/account/orders/{code}", headers=UA).status_code, 403)
        self.assertTrue(self.events("IDOR Attempt"))

    def test_admin_pages_and_customer_forbidden(self):
        a = self.shop_login("admin", "Admin@12345", admin=True)
        for url in ["/admin/", "/admin/orders", "/admin/products", "/admin/customers", "/admin/security",
                    "/admin/incidents", "/admin/simulation", "/admin/api/alerts", "/admin/api/stats"]:
            self.assertEqual(a.get(url, headers=UA).status_code, 200, url)
        c = self.shop_login()
        self.assertEqual(c.get("/admin/", headers=UA).status_code, 403)

    def test_sql_injection_in_search_blocked(self):
        r = self.shop.test_client().get("/products?q=' UNION SELECT password_hash FROM users --", headers=UA)
        self.assertEqual(r.status_code, 403)
        self.assertTrue(self.events("SQL Injection"))

    def test_lockout(self):
        c = self.shop.test_client()
        t = self.csrf(c)
        for _ in range(5):
            c.post("/login", data={"csrf_token": t, "username": "budi", "password": "Wrong!123"}, headers=UA)
        self.assertTrue(self.events("Account Locked"))
        self.assertTrue(self.events("Brute Force Attack"))

    def test_separate_cookie_names(self):
        self.assertNotEqual(self.shop.config["SESSION_COOKIE_NAME"], self.lab.config["SESSION_COOKIE_NAME"])


class TestMidtrans(BaseCase):
    KEY = "SB-Mid-server-TESTKEY123"

    def setUp(self):
        super().setUp()
        self.shop.config["MIDTRANS_SERVER_KEY"] = self.KEY

    def _place_order(self, c):
        t = self.csrf(c)
        c.post("/cart/add", data={"csrf_token": t, "product_id": 8, "qty": 1}, headers=UA)
        fake = mock.Mock(status_code=201, content=b"x")
        fake.json.return_value = {"token": "abc", "redirect_url": "https://app.sandbox.midtrans.com/snap/v4/redirection/abc"}
        with mock.patch("shop.payments.midtrans.requests.post", return_value=fake) as post:
            r = c.post("/checkout", data={"csrf_token": t, "shipping_name": "Budi Demo", "shipping_phone": "081200000001",
                                          "address": "Kampus Lab Ruang 204", "city": "Cikarang"}, headers=UA)
        return r, post

    def test_snap_redirect_and_server_key_private(self):
        c = self.shop_login()
        r, post = self._place_order(c)
        self.assertTrue(r.headers["Location"].startswith("https://app.sandbox.midtrans.com/"))
        sent = post.call_args.kwargs
        self.assertEqual(sent["json"]["transaction_details"]["gross_amount"], 98000)
        self.assertIn("Basic ", sent["headers"]["Authorization"])
        for url in ["/", "/checkout", "/account/orders", "/cart"]:                  # key never reaches a page
            self.assertNotIn(self.KEY, c.get(url, headers=UA).get_data(as_text=True))

    def _finish(self, c, status):
        code = self.shop_q("SELECT order_code FROM orders WHERE is_synthetic = 0")[0]["order_code"]
        resp = mock.Mock()
        resp.json.return_value = {**status, "order_id": code}
        with mock.patch("shop.payments.midtrans.requests.get", return_value=resp):
            c.get(f"/payment/finish?order_id={code}&status_code=200&transaction_status=settlement", headers=UA)
        return self.shop_q("SELECT status FROM orders WHERE order_code = ?", (code,))[0]["status"]

    def test_finish_verified_with_status_api(self):
        c = self.shop_login()
        self._place_order(c)
        self.assertEqual(self._finish(c, {"transaction_status": "settlement", "gross_amount": "98000.00"}), "paid")

    def test_amount_tampering_detected(self):
        c = self.shop_login()
        self._place_order(c)
        self.assertEqual(self._finish(c, {"transaction_status": "settlement", "gross_amount": "1000.00"}), "failed")
        self.assertTrue(self.events("Payment Tampering"))

    def test_webhook_signature_required(self):
        r = self.shop.test_client().post("/payment/notification", json={"order_id": "X", "status_code": "200",
                                                                          "gross_amount": "1", "signature_key": "bad"},
                                         headers=UA)
        self.assertEqual(r.status_code, 403)
        good = hashlib.sha512(("X2001" + self.KEY).encode()).hexdigest()
        r = self.shop.test_client().post("/payment/notification", json={"order_id": "X", "status_code": "200",
                                                                          "gross_amount": "1", "signature_key": good},
                                         headers=UA)
        self.assertEqual(r.status_code, 404)              # valid signature, unknown order
