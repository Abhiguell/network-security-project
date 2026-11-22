"""lab/routes/auth.py: lab operator sign-in / sign-out (separate from the store's accounts)."""
from datetime import datetime, timedelta

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from ..db import TS_FORMAT, add_event, execute, now_str, query
from ..security.access import login_user

bp = Blueprint("auth", __name__)
_DUMMY = generate_password_hash("x")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("pages.dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:30]
        user = query("SELECT * FROM lab_users WHERE username = ?", (username,), one=True)
        if user and user["locked_until"] and datetime.strptime(user["locked_until"], TS_FORMAT) > datetime.now():
            flash("Account locked after too many failed attempts. Try again later.", "danger")
        elif user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            execute("UPDATE lab_users SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?",
                    (now_str(), user["id"]))
            login_user(user)
            add_event("info", "auth", f"Operator '{username}' ({user['role']}) signed in", username)
            return redirect(url_for("pages.dashboard"))
        else:
            if not user:
                check_password_hash(_DUMMY, "x")
            else:
                n = user["failed_attempts"] + 1
                if n >= current_app.config["MAX_FAILED_LOGINS"]:
                    until = (datetime.now() + timedelta(minutes=current_app.config["LOCKOUT_MINUTES"])).strftime(TS_FORMAT)
                    execute("UPDATE lab_users SET failed_attempts = 0, locked_until = ? WHERE id = ?", (until, user["id"]))
                    add_event("high", "auth", f"Lab account '{username}' locked after {n} failed logins")
                else:
                    execute("UPDATE lab_users SET failed_attempts = ? WHERE id = ?", (n, user["id"]))
            add_event("low", "auth", f"Failed lab login for '{username}'")
            flash("Invalid username or password.", "danger")
    return render_template("login.html")


@bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Signed out of the lab.", "info")
    return redirect(url_for("auth.login"))
