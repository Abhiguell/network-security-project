"""
WEBSITE 2: CyberSim Lab, the attack-simulation control panel.

A completely separate Flask app (own database, users, session cookie and UI).
It affects the LabMart store only through the signed simulation API.
"""
import os

from flask import Flask, g, render_template, request

from . import db
from .config import Config
from .security import access


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)
    db.init_app(app)

    @app.before_request
    def pipeline():
        if request.endpoint == "static":
            return
        access.load_user()
        access.csrf_protect()

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                                                   "img-src 'self' data:; object-src 'none'; frame-ancestors 'none'")
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.context_processor
    def inject():
        return {"csrf_token": access.csrf_token, "shop_url": app.config["SHOP_URL"],
                "can_run": g.get("user") is not None and g.user["role"] in access.RUN_ROLES}

    from .routes import api, auth, pages
    app.register_blueprint(auth.bp)
    app.register_blueprint(pages.bp)
    app.register_blueprint(api.bp)

    def err(code, title):
        def handler(e):
            if request.path.startswith("/api/"):
                return {"error": title, "message": getattr(e, "description", title)}, code
            return render_template("error.html", code=code, title=title,
                                   message=getattr(e, "description", title)), code
        return handler
    for code, title in ((400, "Bad Request"), (403, "Forbidden"), (404, "Not Found"), (500, "Server Error")):
        app.register_error_handler(code, err(code, title))
    return app
