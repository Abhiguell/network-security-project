"""
shop/routes/admin.py: store administration and security monitoring.

Pages: dashboard, orders, products, customers, security events, incidents,
simulation-API control. JSON: /admin/api/alerts (live notifications), /admin/api/stats (charts).
"""
from datetime import datetime, timedelta

from flask import Blueprint, flash, g, jsonify, redirect, render_template, request, url_for

from .. import ransomware_sandbox
from ..db import TS_FORMAT, execute, get_setting, now_str, query, set_setting
from ..security import monitor
from ..security.access import admin_required
from ..security.validators import mask_email

bp = Blueprint("admin", __name__, url_prefix="/admin")
SEVERITIES = ["info", "low", "medium", "high", "critical"]


@bp.route("/")
@admin_required
def dashboard():
    day_ago = (datetime.now() - timedelta(days=1)).strftime(TS_FORMAT)
    s = {
        "revenue": query("SELECT COALESCE(SUM(total), 0) AS v FROM orders WHERE status = 'paid'", one=True)["v"],
        "orders": query("SELECT COUNT(*) AS v FROM orders", one=True)["v"],
        "pending": query("SELECT COUNT(*) AS v FROM orders WHERE status = 'pending'", one=True)["v"],
        "customers": query("SELECT COUNT(*) AS v FROM users WHERE role = 'customer' AND is_synthetic = 0", one=True)["v"],
        "synthetic": query("SELECT COUNT(*) AS v FROM users WHERE is_synthetic = 1", one=True)["v"],
        "products": query("SELECT COUNT(*) AS v FROM products WHERE is_active = 1", one=True)["v"],
        "events_24h": query("SELECT COUNT(*) AS v FROM security_events WHERE ts >= ?", (day_ago,), one=True)["v"],
        "failed_24h": query("SELECT COUNT(*) AS v FROM login_attempts WHERE success = 0 AND ts >= ?", (day_ago,), one=True)["v"],
    }
    recent_orders = query("SELECT o.*, u.username FROM orders o JOIN users u ON u.id = o.user_id "
                          "WHERE o.is_synthetic = 0 ORDER BY o.id DESC LIMIT 6")
    alerts = query("SELECT * FROM security_events WHERE severity IN ('medium','high','critical') ORDER BY id DESC LIMIT 8")
    return render_template("admin/dashboard.html", s=s, recent_orders=recent_orders, alerts=alerts)


@bp.route("/api/stats")
@admin_required
def api_stats():
    days = [(datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]
    sales = {r["d"]: r["v"] for r in query(
        "SELECT substr(paid_at, 1, 10) AS d, SUM(total) AS v FROM orders WHERE status = 'paid' AND paid_at >= ? "
        "GROUP BY d", (days[0],))}
    by_sev = {r["severity"]: r["c"] for r in query("SELECT severity, COUNT(*) AS c FROM security_events GROUP BY severity")}
    return jsonify({"days": [d[5:] for d in days], "sales": [sales.get(d, 0) for d in days],
                    "severity": {"labels": SEVERITIES, "values": [by_sev.get(x, 0) for x in SEVERITIES]}})


@bp.route("/api/alerts")
@admin_required
def api_alerts():
    since = request.args.get("since", 0, type=int)
    rows = query("SELECT id, ts, severity, category, message, ip, source FROM security_events "
                 "WHERE id > ? AND severity IN ('medium','high','critical') ORDER BY id LIMIT 20", (since,))
    last = query("SELECT MAX(id) AS m FROM security_events", one=True)["m"] or 0
    open_alerts = query("SELECT COUNT(*) AS c FROM security_events WHERE acknowledged = 0 "
                        "AND severity IN ('high','critical')", one=True)["c"]
    incidents = query("SELECT id, kind, severity, title, ts FROM incidents WHERE status = 'open' ORDER BY id DESC")
    return jsonify({"alerts": [dict(r) for r in rows], "last_id": last, "open": open_alerts,
                    "status": monitor.security_status(), "incidents": [dict(r) for r in incidents]})


# ---------------------------------------------------------------- store management
@bp.route("/orders")
@admin_required
def orders():
    show = request.args.get("show", "real")
    where = "" if show == "all" else "WHERE o.is_synthetic = 0"
    rows = query(f"SELECT o.*, u.username FROM orders o JOIN users u ON u.id = o.user_id {where} "
                 "ORDER BY o.id DESC LIMIT 200")
    return render_template("admin/orders.html", orders=rows, show=show)


@bp.route("/products", methods=["GET", "POST"])
@admin_required
def products():
    if request.method == "POST":
        pid = request.form.get("product_id", type=int)
        price = request.form.get("price", type=int)
        stock = request.form.get("stock", type=int)
        if pid is None or price is None or stock is None or not (1000 <= price <= 100_000_000) or not (0 <= stock <= 100_000):
            flash("Price must be Rp 1.000 - Rp 100.000.000 and stock 0 - 100.000.", "danger")
        else:
            execute("UPDATE products SET price = ?, stock = ?, is_active = ? WHERE id = ?",
                    (price, stock, 1 if request.form.get("is_active") else 0, pid))
            monitor.log_event("info", "Product Updated", f"Product #{pid}: price={price} stock={stock}")
            flash("Product updated.", "success")
        return redirect(url_for("admin.products"))
    return render_template("admin/products.html", products=query("SELECT * FROM products ORDER BY id"))


@bp.route("/customers")
@admin_required
def customers():
    rows = query("SELECT u.*, (SELECT COUNT(*) FROM orders o WHERE o.user_id = u.id) AS order_count "
                 "FROM users u ORDER BY u.is_synthetic, u.id")
    return render_template("admin/customers.html", users=rows, mask=mask_email,
                           now=datetime.now().strftime(TS_FORMAT))


@bp.route("/customers/<int:uid>/<action>", methods=["POST"])
@admin_required
def customer_action(uid, action):
    user = query("SELECT * FROM users WHERE id = ?", (uid,), one=True)
    if user is None or user["id"] == g.user["id"]:
        flash("Not allowed.", "warning")
        return redirect(url_for("admin.customers"))
    if action == "toggle-active":
        execute("UPDATE users SET is_active = ? WHERE id = ?", (0 if user["is_active"] else 1, uid))
    elif action == "unlock":
        execute("UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE id = ?", (uid,))
    monitor.log_event("info", "User Management", f"{action} on account '{user['username']}'")
    flash("Account updated.", "success")
    return redirect(url_for("admin.customers"))


# ---------------------------------------------------------------- security
@bp.route("/security")
@admin_required
def security():
    sev, src, status = request.args.get("severity", ""), request.args.get("source", ""), request.args.get("status", "")
    sql, args = "SELECT * FROM security_events WHERE 1=1", []
    if sev in SEVERITIES:
        sql += " AND severity = ?"
        args.append(sev)
    if src in ("web", "simulation"):
        sql += " AND source = ?"
        args.append(src)
    if status == "open":
        sql += " AND acknowledged = 0"
    events = query(sql + " ORDER BY id DESC LIMIT 400", args)
    logins = query("SELECT * FROM login_attempts ORDER BY id DESC LIMIT 15")
    return render_template("admin/security.html", events=events, logins=logins, severities=SEVERITIES, f=request.args)


@bp.route("/security/ack/<int:eid>", methods=["POST"])
@admin_required
def ack(eid):
    execute("UPDATE security_events SET acknowledged = 1 WHERE id = ?", (eid,))
    return redirect(request.referrer or url_for("admin.security"))


@bp.route("/security/ack-all", methods=["POST"])
@admin_required
def ack_all():
    execute("UPDATE security_events SET acknowledged = 1 WHERE acknowledged = 0")
    flash("All events acknowledged.", "success")
    return redirect(url_for("admin.security"))


@bp.route("/incidents")
@admin_required
def incidents():
    rows = query("SELECT * FROM incidents ORDER BY status = 'resolved', id DESC LIMIT 100")
    return render_template("admin/incidents.html", incidents=rows)


@bp.route("/incidents/<int:iid>/resolve", methods=["POST"])
@admin_required
def resolve_incident(iid):
    inc = query("SELECT * FROM incidents WHERE id = ?", (iid,), one=True)
    if inc and inc["status"] == "open":
        execute("UPDATE incidents SET status = 'resolved', resolved_at = ? WHERE id = ?", (now_str(), iid))
        monitor.log_event("info", "Incident Response", f"Incident #{iid} ({inc['kind']}) marked resolved")
        flash(f"Incident #{iid} resolved.", "success")
    return redirect(request.referrer or url_for("admin.incidents"))


@bp.route("/simulation", methods=["GET", "POST"])
@admin_required
def simulation():
    """Control panel for the Cyber Lab's access to this store."""
    if request.method == "POST":
        enabled = "1" if request.form.get("enabled") == "1" else "0"
        set_setting("sim_api_enabled", enabled)
        monitor.log_event("medium" if enabled == "1" else "info", "Simulation API",
                          f"Simulation API {'ENABLED' if enabled == '1' else 'DISABLED'} by administrator")
        flash(f"Simulation API {'enabled' if enabled == '1' else 'disabled'}.", "success")
        return redirect(url_for("admin.simulation"))
    from flask import current_app
    sandbox = ransomware_sandbox.get_state(current_app.config["SANDBOX_FOLDER"])
    traffic = query("SELECT * FROM sim_traffic ORDER BY id DESC LIMIT 40")
    return render_template("admin/simulation.html", enabled=get_setting("sim_api_enabled", "1") == "1",
                           sandbox=sandbox, traffic=traffic)
