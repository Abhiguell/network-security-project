"""
WEBSITE 1: LabMart e-commerce store (the simulated victim).

create_app() wires: config -> database (+ seed) -> security pipeline -> blueprints.

Security pipeline (every request):
  1. load_logged_in_user()  (+ session hijack check)
  2. rate_limit_check()     (request floods)
  3. inspect_request()      (SQLi / XSS / traversal / command injection / scanners)
  4. csrf.protect()         (forged form posts)
"""
import os

from flask import Flask, g, render_template, request, session

from . import db
from .config import Config
from .security import access, csrf, monitor


def rupiah(value):
    """459000 -> 'Rp 459.000'"""
    return "Rp " + f"{int(value or 0):,}".replace(",", ".")


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    for key in ("SANDBOX_FOLDER", "LOG_FOLDER"):
        os.makedirs(app.config[key], exist_ok=True)
    os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)

    db.init_app(app)
    app.jinja_env.filters["rupiah"] = rupiah

    @app.before_request
    def security_pipeline():
        if request.endpoint == "static":
            return
        access.load_logged_in_user()
        monitor.rate_limit_check()
        monitor.inspect_request()
        csrf.protect()

    @app.after_request
    def after_request(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        # Only our own scripts. Midtrans is used in REDIRECT mode, so no third-party JS runs on our pages.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "object-src 'none'; frame-ancestors 'none'; base-uri 'self'; "
            "form-action 'self' https://app.sandbox.midtrans.com")
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
            monitor.log_activity(response)
        return response

    @app.context_processor
    def inject_globals():
        from .payments import midtrans
        cart = session.get("cart", {})
        data = {"csrf_token": csrf.generate_csrf_token, "cart_count": sum(cart.values()),
                "midtrans_live": midtrans.is_configured(), "app_name": app.config["APP_NAME"]}
        # Phishing-awareness lure: shown to shoppers while a spyware incident is open
        # (attackers typically follow a data leak with "verify your account" messages).
        if not request.path.startswith("/admin") and request.endpoint != "store.phishing_notice":
            lure = db.query("SELECT id FROM incidents WHERE kind = 'spyware' AND status = 'open' "
                            "ORDER BY id DESC LIMIT 1", one=True)
            data["phishing_lure"] = lure["id"] if lure else None
        user = g.get("user")
        if user is not None and user["role"] == "admin":
            data["sec_status"] = monitor.security_status()
            row = db.query("SELECT MAX(id) AS last_id, "
                           "SUM(acknowledged = 0 AND severity IN ('high','critical')) AS open "
                           "FROM security_events", one=True)
            data["last_event_id"] = row["last_id"] or 0
            data["open_alerts"] = row["open"] or 0
            data["open_incidents"] = db.query("SELECT * FROM incidents WHERE status = 'open' ORDER BY id DESC")
        return data

    from .routes import account, admin, auth, checkout, simapi, store
    for bp in (store.bp, auth.bp, account.bp, checkout.bp, admin.bp, simapi.bp):
        app.register_blueprint(bp)

    def error_page(code, title, default):
        def handler(err):
            if request.path.startswith("/api/"):
                return {"error": title, "message": getattr(err, "description", default)}, code
            return render_template("error.html", code=code, title=title,
                                   message=getattr(err, "description", None) or default), code
        return handler

    for code, title, msg in ((400, "Bad Request", "The request was invalid."),
                             (401, "Unauthorized", "Authentication required."),
                             (403, "Access Denied", "You are not allowed to do that."),
                             (404, "Not Found", "That page does not exist."),
                             (413, "Too Large", "Request too large."),
                             (429, "Too Many Requests", "Slow down: too many requests."),
                             (500, "Server Error", "Something went wrong.")):
        app.register_error_handler(code, error_page(code, title, msg))
    return app
