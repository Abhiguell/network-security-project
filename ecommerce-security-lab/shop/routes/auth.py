"""
shop/routes/auth.py: customer registration, login, admin login, logout.
"""
from datetime import datetime, timedelta

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from ..db import TS_FORMAT, execute, now_str, query
from ..security import monitor, validators
from ..security.access import is_safe_next, login_user, logout_user

bp = Blueprint("auth", __name__)
_DUMMY_HASH = generate_password_hash("timing-equaliser")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("store.home"))
    form = {k: "" for k in ("username", "full_name", "email", "phone")}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in form}
        password, confirm = request.form.get("password", ""), request.form.get("confirm_password", "")
        errors = [e for e in (validators.validate_username(form["username"]),
                              validators.validate_name(form["full_name"]),
                              validators.validate_email(form["email"]),
                              validators.validate_phone(form["phone"])) if e]
        weak = validators.validate_password(password)
        if weak:
            errors.append("Password needs " + ", ".join(weak) + ".")
        if password != confirm:
            errors.append("Passwords do not match.")
        if not errors and query("SELECT id FROM users WHERE username = ? OR email = ?",
                                (form["username"], form["email"].lower()), one=True):
            errors.append("That username or email is already registered.")
        if errors:
            for e in errors:
                flash(e, "danger")
        else:
            execute("INSERT INTO users (username, email, password_hash, full_name, phone, is_synthetic, created_at) "
                    "VALUES (?, ?, ?, ?, ?, 0, ?)",
                    (form["username"], form["email"].lower(), generate_password_hash(password),
                     form["full_name"], form["phone"], now_str()))
            monitor.log_event("info", "Registration", f"New customer account: {form['username']}",
                              username=form["username"])
            flash("Welcome to LabMart! Your account is ready. Please sign in.", "success")
            return redirect(url_for("auth.login"))
    return render_template("auth/register.html", form=form)


def _handle_login(admin_portal):
    username = request.form.get("username", "").strip()[:50]
    password = request.form.get("password", "")
    user = query("SELECT * FROM users WHERE username = ?", (username,), one=True)

    if user and user["locked_until"]:
        until = datetime.strptime(user["locked_until"], TS_FORMAT)
        if until > datetime.now():
            monitor.record_login(username, False)
            mins = int((until - datetime.now()).total_seconds() // 60) + 1
            flash(f"Account temporarily locked after too many failed attempts. Try again in {mins} min.", "danger")
            return None

    ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)
    if user and ok and user["is_active"]:
        if admin_portal and user["role"] != "admin":
            monitor.record_login(username, False)
            monitor.log_event("medium", "Privilege Escalation",
                              f"Customer '{username}' tried to sign in to the admin portal", username=username)
            flash("This portal is for store administrators only.", "danger")
            return None
        execute("UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?",
                (now_str(), user["id"]))
        monitor.record_login(username, True)
        if user["role"] == "admin":
            monitor.log_event("info", "Admin Login", f"Administrator '{username}' signed in", username=username)
        login_user(user)
        return user

    monitor.record_login(username, False)
    if user and user["is_active"]:
        attempts = user["failed_attempts"] + 1
        cfg = current_app.config
        if attempts >= cfg["MAX_FAILED_LOGINS"]:
            until = (datetime.now() + timedelta(minutes=cfg["LOCKOUT_MINUTES"])).strftime(TS_FORMAT)
            execute("UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?", (until, user["id"]))
            monitor.log_event("high", "Account Locked",
                              f"Account '{username}' locked after {attempts} failed logins", username=username)
        else:
            execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (attempts, user["id"]))
    flash("This account has been disabled." if user and not user["is_active"]
          else "Invalid username or password.", "danger")
    return None


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("store.home"))
    if request.method == "POST":
        user = _handle_login(admin_portal=False)
        if user:
            if user["role"] == "admin":
                return redirect(url_for("admin.dashboard"))
            nxt = request.args.get("next")
            return redirect(nxt if is_safe_next(nxt) else url_for("store.home"))
    return render_template("auth/login.html", admin_portal=False)


@bp.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if g.user and g.user["role"] == "admin":
        return redirect(url_for("admin.dashboard"))
    if request.method == "POST" and _handle_login(admin_portal=True):
        return redirect(url_for("admin.dashboard"))
    return render_template("auth/login.html", admin_portal=True)


@bp.route("/logout", methods=["POST"])
def logout():
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("store.home"))
