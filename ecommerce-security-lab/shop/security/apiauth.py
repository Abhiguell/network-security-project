"""
shop/security/apiauth.py: authentication for the Lab -> Shop simulation API.

Every request from the Cyber Lab must carry an HMAC-SHA256 signature made with a
shared secret (SIM_API_SECRET in .env). The secret itself is never sent.

Headers sent by the lab:
  X-Lab-Client     fixed client id ("seclab-01")
  X-Lab-Timestamp  unix time; requests older/newer than 60 s are rejected
  X-Lab-Nonce      random value; each nonce may be used once (blocks replay attacks)
  X-Lab-Operator   lab username who clicked the button (for the audit trail)
  X-Lab-Role       lab role; only 'admin' and 'analyst' may run simulations
  X-Lab-Signature  hex( HMAC_SHA256(secret, canonical_string) )

canonical_string = METHOD \n PATH \n TIMESTAMP \n NONCE \n OPERATOR \n ROLE \n SHA256(body)

Extra controls: the store admin can switch the API off, and only localhost /
private lab addresses are accepted.
"""
import hashlib
import hmac
import ipaddress
import re
import sqlite3
import time
from functools import wraps

from flask import abort, current_app, g, request

from ..db import execute, get_setting
from . import monitor

NONCE_RE = re.compile(r"^[a-f0-9]{16,64}$")
OPERATOR_RE = re.compile(r"^[A-Za-z0-9_]{1,20}$")
ALLOWED_ROLES = {"admin", "analyst"}


def canonical(method, path, ts, nonce, operator, role, body):
    return "\n".join([method.upper(), path, str(ts), nonce, operator, role, hashlib.sha256(body).hexdigest()])


def sign(secret, method, path, ts, nonce, operator, role, body):
    return hmac.new(secret.encode(), canonical(method, path, ts, nonce, operator, role, body).encode(),
                    hashlib.sha256).hexdigest()


def is_lab_address(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_private


def _deny(reason, code=401, severity="high"):
    monitor.log_event(severity, "Unauthorized Simulation API Access", reason,
                      f"path={request.path} client={request.headers.get('X-Lab-Client', '-')[:30]}",
                      username="", source="simulation")
    abort(code, description=reason)


def require_lab_signature(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        cfg = current_app.config
        if get_setting("sim_api_enabled", "1") != "1":
            monitor.log_event("low", "Simulation API", "Lab request refused: API disabled by store admin",
                              f"path={request.path}", username="", source="simulation")
            abort(403, description="Simulation API is disabled by the store administrator.")
        if cfg["SIM_API_ALLOW_PRIVATE_ONLY"] and not is_lab_address(monitor.client_ip()):
            _deny(f"Request from non-lab address {monitor.client_ip()}", 403)
        secret = cfg.get("SIM_API_SECRET", "")
        if not secret:
            abort(500, description="SIM_API_SECRET is not configured.")

        h = request.headers
        client, ts, nonce = h.get("X-Lab-Client", ""), h.get("X-Lab-Timestamp", ""), h.get("X-Lab-Nonce", "")
        operator, role, signature = h.get("X-Lab-Operator", ""), h.get("X-Lab-Role", ""), h.get("X-Lab-Signature", "")

        if client != cfg["SIM_API_CLIENT_ID"]:
            _deny("Missing or unknown API client id")
        try:
            ts_value = float(ts)
        except ValueError:
            _deny("Missing timestamp")
        if abs(time.time() - ts_value) > cfg["SIM_API_MAX_SKEW"]:
            _deny("Expired timestamp (possible replay attack)")
        if not NONCE_RE.match(nonce) or not OPERATOR_RE.match(operator):
            _deny("Malformed nonce or operator")
        expected = sign(secret, request.method, request.path, ts, nonce, operator, role, request.get_data())
        if not hmac.compare_digest(expected, signature):
            _deny("Invalid HMAC signature")
        if role not in ALLOWED_ROLES:
            _deny(f"Lab role '{role}' is not authorised to run simulations", 403, "medium")

        # Replay protection: remember nonces for twice the allowed clock skew.
        execute("DELETE FROM api_nonces WHERE ts < ?", (time.time() - 2 * cfg["SIM_API_MAX_SKEW"],))
        try:
            execute("INSERT INTO api_nonces (nonce, ts) VALUES (?, ?)", (nonce, time.time()))
        except sqlite3.IntegrityError:
            _deny("Replay attack: nonce was already used")

        g.lab_operator, g.lab_role = operator, role
        return view(*args, **kwargs)
    return wrapped
