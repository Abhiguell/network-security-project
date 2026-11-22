"""
shop/routes/account.py: customer profile and order history.
"""
from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from ..db import execute, query
from ..security import monitor, validators
from ..security.access import login_required

bp = Blueprint("account", __name__, url_prefix="/account")


@bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        if request.form.get("action") == "password":
            current, new = request.form.get("current_password", ""), request.form.get("new_password", "")
            weak = validators.validate_password(new)
            if not check_password_hash(g.user["password_hash"], current):
                monitor.log_event("medium", "Password Change Failed", "Wrong current password")
                flash("Current password is incorrect.", "danger")
            elif weak:
                flash("New password needs " + ", ".join(weak) + ".", "danger")
            elif new != request.form.get("confirm_password", ""):
                flash("New passwords do not match.", "danger")
            else:
                execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new), g.user["id"]))
                monitor.log_event("info", "Password Changed", "Customer changed their password")
                flash("Password updated.", "success")
        else:
            f = {k: request.form.get(k, "").strip() for k in ("full_name", "email", "phone", "address", "city")}
            f["email"] = f["email"].lower()
            errors = [e for e in (validators.validate_name(f["full_name"]), validators.validate_email(f["email"]),
                                  validators.validate_phone(f["phone"]),
                                  f["address"] and validators.validate_address(f["address"]),
                                  f["city"] and validators.validate_city(f["city"])) if e]
            if not errors and query("SELECT id FROM users WHERE email = ? AND id != ?", (f["email"], g.user["id"]), one=True):
                errors.append("That email is used by another account.")
            if errors:
                for e in errors:
                    flash(e, "danger")
            else:
                execute("UPDATE users SET full_name=?, email=?, phone=?, address=?, city=? WHERE id=?",
                        (f["full_name"], f["email"], f["phone"], f["address"], f["city"], g.user["id"]))
                flash("Profile saved.", "success")
        return redirect(url_for("account.profile"))
    stats = query("SELECT COUNT(*) AS orders, COALESCE(SUM(CASE WHEN status='paid' THEN total END), 0) AS spent "
                  "FROM orders WHERE user_id = ?", (g.user["id"],), one=True)
    return render_template("account/profile.html", stats=stats)


@bp.route("/orders")
@login_required
def orders():
    rows = query("SELECT o.*, (SELECT SUM(qty) FROM order_items WHERE order_id = o.id) AS items "
                 "FROM orders o WHERE user_id = ? ORDER BY id DESC", (g.user["id"],))
    return render_template("account/orders.html", orders=rows)


@bp.route("/orders/<code>")
@login_required
def order_detail(code):
    order = query("SELECT * FROM orders WHERE order_code = ?", (code[:40],), one=True)
    if order is None:
        abort(404)
    if order["user_id"] != g.user["id"] and g.user["role"] != "admin":
        monitor.log_event("high", "IDOR Attempt", f"Tried to open another customer's order {code[:40]}")
        abort(403, description="That order belongs to another customer. This attempt has been logged.")
    items = query("SELECT * FROM order_items WHERE order_id = ?", (order["id"],))
    return render_template("account/order_detail.html", order=order, items=items)
