"""
lab/config.py: settings for WEBSITE 2, the Cyber Security Lab (attack simulator).

The lab has its OWN database, its OWN users and its OWN session cookie. It talks to the
store only through the signed simulation API (see lab/client.py).
"""
import os
import secrets
from datetime import timedelta

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
ENV_FILE = os.path.join(ROOT_DIR, ".env")


def load_env(path=ENV_FILE):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ.setdefault(key.strip(), value.strip())
    if not os.environ.get("SIM_API_SECRET"):
        secret = secrets.token_hex(32)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"\n# Shared secret for signed Lab -> Shop simulation API calls (auto-generated)\n"
                     f"SIM_API_SECRET={secret}\n")
        os.environ["SIM_API_SECRET"] = secret


load_env()


class Config:
    APP_NAME = "CyberSim Lab"
    SECRET_KEY = os.environ.get("LAB_SECRET_KEY") or secrets.token_hex(32)
    DATABASE = os.path.join(BASE_DIR, "instance", "lab.db")

    SESSION_COOKIE_NAME = "seclab_session"          # different from the shop's cookie
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)
    MAX_FAILED_LOGINS = 5
    LOCKOUT_MINUTES = 10

    # Where the victim store runs, and the shared API secret
    SHOP_URL = os.environ.get("SHOP_URL", "http://127.0.0.1:5000").rstrip("/")
    SIM_API_SECRET = os.environ.get("SIM_API_SECRET", "")
    SIM_API_CLIENT_ID = "seclab-01"
    SHOP_TIMEOUT = 10

    # Trojan simulation limits
    TROJAN_MIN_INTERVAL = 1
    TROJAN_MAX_BEACONS = 30

    DEFAULT_USERS = [
        ("labadmin", "LabAdmin@123", "admin"),
        ("analyst", "Analyst@123", "analyst"),
        ("viewer", "Viewer@123", "viewer"),      # read-only: cannot run simulations
    ]
