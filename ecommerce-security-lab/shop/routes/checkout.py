"""
shop/routes/checkout.py: checkout and payment.

Two payment modes:
  * MIDTRANS SANDBOX: used automatically when MIDTRANS_SERVER_KEY (SB-...) is set in .env.
    The customer is redirected to Midtrans' hosted payment page.
  * DEMO GATEWAY: used when no keys are configured, so the demo still works offline.
    Clearly labelled as a simulated payment page; no card details are ever asked.
"""
import json
import secrets
from datetime import datetime

from flask import (Blueprint, abort, current_app, flash, g, redirect, render_template, request,
                   session, url_for)

from ..db import execute, now_str, query
from ..payments import midtrans
from ..security import monitor, validators
from ..security.access import login_required
from .store import cart_items

bp = Blueprint("checkout", __name__)


def _new_order_code():
    return f"LM-{datetime.now():%Y%m%d}-{secrets.token_hex(3).upper()}"


def _mark_order(order, new_status, gateway_status, paid_amount=None):
    """Update an order once; decrement stock when it becomes paid."""
    if order["status"] == "paid":
        return                                               # never downgrade or double-count a paid order
    if new_status == "paid" and paid_amount is not None and int(float(paid_amount)) != order["total"]:
        monitor.log_event("critical", "Payment Tampering",
                          f"Paid amount {paid_amount} does not match order total {order['total']}",
                          f"order={order['order_code']}")
        new_status = "failed"
    execute("UPDATE orders SET status = ?, payment_status = ?, paid_at = ? WHERE id = ?",
            (new_status, gateway_status, now_str() if new_status == "paid" else None, order["id"]))
    if new_status == "paid":
        for item in query("SELECT product_id, qty FROM order_items WHERE order_id = ?", (order["id"],)):
            execute("UPDATE products SET stock = MAX(stock - ?, 0) WHERE id = ?", (item["qty"], item["product_id"]))


@bp.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    items, total = cart_items()
    if not items:
        flash("Your cart is empty.", "warning")
        return redirect(url_for("store.catalog"))
    u = g.user
    form = {"shipping_name": u["full_name"], "shipping_phone": u["phone"],
            "address": u["address"], "city": u["city"]}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in form}
        errors = [e for e in (validators.validate_name(form["shipping_name"]),
                              validators.validate_phone(form["shipping_phone"]),
                              validators.validate_address(form["address"]),
                              validators.validate_city(form["city"])) if e]
        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("checkout/checkout.html", items=items, total=total, form=form)

        method = "midtrans" if midtrans.is_configured() else "demo"
        code = _new_order_code()
        oid = execute(
            "INSERT INTO orders (order_code, user_id, status, payment_method, total, shipping_name, shipping_phone, "
            "shipping_address, created_at) VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?)",
            (code, u["id"], method, total, form["shipping_name"], form["shipping_phone"],
             f"{form['address']}, {form['city']}", now_str()))
        for i in items:
            execute("INSERT INTO order_items (order_id, product_id, name, price, qty) VALUES (?, ?, ?, ?, ?)",
                    (oid, i["product_id"], i["name"], i["price"], i["qty"]))
        session.pop("cart", None)
        order = query("SELECT * FROM orders WHERE id = ?", (oid,), one=True)

        if method == "midtrans":
            try:
                url = midtrans.create_transaction(order, items, u, url_for("checkout.finish", _external=True))
                return redirect(url)
            except midtrans.MidtransError as exc:
                _mark_order(order, "failed", "gateway_error")
                monitor.log_event("medium", "Payment Gateway Error", str(exc)[:250], f"order={code}")
                flash(f"Payment gateway error: {exc}. Your order was not charged.", "danger")
                return redirect(url_for("account.order_detail", code=code))
        return redirect(url_for("checkout.demo_pay", code=code))
    return render_template("checkout/checkout.html", items=items, total=total, form=form)


def _own_pending_order(code):
    order = query("SELECT * FROM orders WHERE order_code = ?", (code[:40],), one=True)
    if order is None:
        abort(404)
    if order["user_id"] != g.user["id"]:
        monitor.log_event("high", "IDOR Attempt", f"Tried to pay another customer's order {code[:40]}")
        abort(403)
    return order


@bp.route("/pay/demo/<code>", methods=["GET", "POST"])
@login_required
def demo_pay(code):
    order = _own_pending_order(code)
    if order["payment_method"] != "demo":
        abort(404)
    if request.method == "POST" and order["status"] == "pending":
        if request.form.get("action") == "pay":
            _mark_order(order, "paid", "settlement (demo)")
            flash("Payment successful (demo gateway, no real money).", "success")
        else:
            _mark_order(order, "cancelled", "cancel (demo)")
            flash("Payment cancelled.", "info")
        return redirect(url_for("account.order_detail", code=code))
    items = query("SELECT * FROM order_items WHERE order_id = ?", (order["id"],))
    return render_template("checkout/demo_pay.html", order=order, items=items)


@bp.route("/payment/finish")
@login_required
def finish():
    """Midtrans redirects the customer here. We verify with the Status API."""
    code = request.args.get("order_id", "")[:40]
    order = _own_pending_order(code)
    if order["payment_method"] == "midtrans" and order["status"] == "pending":
        try:
            status = midtrans.get_status(code)
            _mark_order(order, midtrans.map_status(status), status.get("transaction_status", ""),
                        status.get("gross_amount"))
        except midtrans.MidtransError as exc:
            flash(f"Could not confirm payment yet: {exc}", "warning")
    order = query("SELECT * FROM orders WHERE id = ?", (order["id"],), one=True)
    flash({"paid": "Payment confirmed by Midtrans Sandbox. Thank you!",
           "pending": "Payment is still pending. Complete it on the Midtrans page or check back later.",
           }.get(order["status"], f"Payment status: {order['status']}."),
          "success" if order["status"] == "paid" else "info")
    return redirect(url_for("account.order_detail", code=code))


@bp.route("/payment/notification", methods=["POST"])
def notification():
    """Midtrans webhook (server-to-server). Needs a public URL, e.g. ngrok, to receive it."""
    payload = request.get_json(silent=True) or {}
    if not midtrans.verify_signature(payload):
        monitor.log_event("high", "Payment Tampering", "Webhook with an invalid Midtrans signature",
                          json.dumps({k: payload.get(k) for k in ("order_id", "transaction_status")})[:300])
        abort(403)
    order = query("SELECT * FROM orders WHERE order_code = ?", (str(payload.get("order_id", ""))[:40],), one=True)
    if order is None:
        abort(404)
    try:
        status = midtrans.get_status(order["order_code"])   # double-check with Midtrans directly
    except midtrans.MidtransError:
        status = payload
    _mark_order(order, midtrans.map_status(status), status.get("transaction_status", ""), status.get("gross_amount"))
    return {"ok": True}
