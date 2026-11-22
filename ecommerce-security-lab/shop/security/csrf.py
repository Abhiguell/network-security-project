"""
app/security/csrf.py: Cross-Site Request Forgery protection.

Every form gets a hidden random token that is also stored in the user's
session. A malicious site can make your browser send a POST request,
but it cannot read the token, so the request is rejected.
"""
import hmac
import secrets

from flask import abort, current_app, request, session

from . import monitor

# Machine-to-machine endpoints use their own authentication instead:
#  /api/sim/...           -> HMAC-signed requests from the Cyber Lab
#  /payment/notification -> Midtrans webhook, verified by signature_key
EXEMPT_PREFIXES = ("/api/sim/", "/payment/notification")


def generate_csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(32)
    return session["_csrf"]


def protect():
    if request.method != "POST" or not current_app.config.get("CSRF_ENABLED", True):
        return
    if request.path.startswith(EXEMPT_PREFIXES):
        return
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
    expected = session.get("_csrf", "")
    if not expected or not hmac.compare_digest(sent, expected):
        monitor.log_event("medium", "CSRF", "POST request without a valid CSRF token",
                          f"path={request.path}")
        abort(400, description="Invalid or missing security token. Reload the page and try again.")
