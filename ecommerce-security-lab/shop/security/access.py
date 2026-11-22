"""
app/security/access.py: login sessions and access control.

- login_user() / logout_user() manage the session cookie.
- load_logged_in_user() runs before every request and sets g.user.
- @login_required and @admin_required protect pages.

Session hardening:
  * session.clear() on login prevents "session fixation".
  * We store a fingerprint of the browser (User-Agent hash). If a stolen
    cookie is replayed from a different browser, the session is killed
    and a "Session Hijacking" alert is raised.
"""
import hashlib
from functools import wraps
from urllib.parse import urlparse

from flask import abort, flash, g, redirect, request, session, url_for

from ..db import query
from . import monitor


def _fingerprint():
    return hashlib.sha256(request.headers.get("User-Agent", "").encode()).hexdigest()


def login_user(user):
    cart = session.get("cart")          # keep the shopping cart across login
    session.clear()
    if cart:
        session["cart"] = cart
    session.permanent = True
    session["user_id"] = user["id"]
    session["fp"] = _fingerprint()


def logout_user():
    session.clear()


def load_logged_in_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id is None:
        return
    if session.get("fp") != _fingerprint():
        monitor.log_event("high", "Session Hijacking",
                          "Session cookie reused from a different browser. Session terminated.",
                          f"user_id={user_id}", username="")
        session.clear()
        return
    user = query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if user is None or not user["is_active"]:
        session.clear()
        return
    g.user = user


def is_safe_next(target):
    """Only allow redirects to pages on this site (prevents open redirects)."""
    if not target:
        return False
    parsed = urlparse(target)
    return not parsed.scheme and not parsed.netloc and target.startswith("/") and not target.startswith("//")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.admin_login", next=request.path))
        if g.user["role"] != "admin":
            monitor.log_event("medium", "Privilege Escalation",
                              "Non-admin user tried to open an admin page", f"path={request.path}")
            abort(403, description="Administrators only. This attempt has been logged.")
        return view(*args, **kwargs)
    return wrapped
