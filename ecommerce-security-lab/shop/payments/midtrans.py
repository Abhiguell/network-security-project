"""
shop/payments/midtrans.py: Midtrans SANDBOX integration (Snap, redirect mode).

Flow
  1. create_transaction(): our server sends the order to Midtrans with the
     SERVER KEY (HTTP Basic auth). Midtrans returns a redirect_url.
  2. The customer pays on Midtrans' own hosted page, so card data never
     touches our server (we never see or store payment details).
  3. Midtrans sends the customer back to /payment/finish and (optionally) a
     webhook to /payment/notification.
  4. We NEVER trust the browser's query string: we ask Midtrans' Status API
     what really happened before marking an order as paid.

Security
  * The server key is read from .env and is only ever used server-to-server.
  * Webhooks are verified with signature_key = SHA512(order_id + status_code + gross_amount + server_key).
  * The paid amount must equal the order total (stops amount tampering).
"""
import base64
import hashlib
import hmac

import requests
from flask import current_app

PAID = {"capture", "settlement"}
FAILED = {"deny", "cancel", "expire", "failure"}


class MidtransError(Exception):
    pass


def is_configured():
    key = current_app.config.get("MIDTRANS_SERVER_KEY", "")
    return bool(key) and key.startswith("SB-")            # sandbox keys only


def _auth_header():
    key = current_app.config["MIDTRANS_SERVER_KEY"]
    token = base64.b64encode(f"{key}:".encode()).decode()
    return {"Authorization": f"Basic {token}", "Accept": "application/json", "Content-Type": "application/json"}


def create_transaction(order, items, customer, finish_url):
    """Returns Midtrans' redirect_url for this order."""
    payload = {
        "transaction_details": {"order_id": order["order_code"], "gross_amount": int(order["total"])},
        "item_details": [{"id": str(i["product_id"]), "price": int(i["price"]), "quantity": int(i["qty"]),
                          "name": i["name"][:50]} for i in items],
        "customer_details": {"first_name": customer["full_name"][:50] or customer["username"],
                             "email": customer["email"], "phone": customer["phone"]},
        "credit_card": {"secure": True},
        "callbacks": {"finish": finish_url},
    }
    try:
        resp = requests.post(current_app.config["MIDTRANS_SNAP_URL"], json=payload, headers=_auth_header(), timeout=15)
    except requests.RequestException as exc:
        raise MidtransError(f"Cannot reach Midtrans Sandbox: {exc.__class__.__name__}") from exc
    data = resp.json() if resp.content else {}
    if resp.status_code not in (200, 201) or "redirect_url" not in data:
        raise MidtransError(f"Midtrans rejected the transaction ({resp.status_code}): "
                            f"{'; '.join(data.get('error_messages', [])) or 'unknown error'}")
    return data["redirect_url"]


def get_status(order_code):
    """Ask Midtrans directly for the real transaction status."""
    url = f"{current_app.config['MIDTRANS_API_URL']}/{order_code}/status"
    try:
        resp = requests.get(url, headers=_auth_header(), timeout=15)
    except requests.RequestException as exc:
        raise MidtransError(f"Cannot reach Midtrans Sandbox: {exc.__class__.__name__}") from exc
    return resp.json()


def verify_signature(payload):
    """Check a webhook really came from Midtrans."""
    key = current_app.config.get("MIDTRANS_SERVER_KEY", "")
    raw = f"{payload.get('order_id', '')}{payload.get('status_code', '')}{payload.get('gross_amount', '')}{key}"
    expected = hashlib.sha512(raw.encode()).hexdigest()
    return bool(key) and hmac.compare_digest(expected, str(payload.get("signature_key", "")))


def map_status(status):
    """Midtrans transaction_status -> our order status."""
    tx = status.get("transaction_status", "")
    fraud = status.get("fraud_status", "accept")
    if tx in PAID and fraud in ("accept", "", None):
        return "paid"
    if tx in FAILED or fraud == "deny":
        return "failed"
    return "pending"
