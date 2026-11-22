"""
shop/config.py: settings for WEBSITE 1, the LabMart e-commerce store (the "victim").

Secrets are read from the project's .env file (never hard-coded, never sent
to the browser). See .env.example in the project root.
"""
import os
import secrets
from datetime import timedelta

BASE_DIR = os.path.dirname(os.path.abspath(__file__))          # .../shop
ROOT_DIR = os.path.dirname(BASE_DIR)                            # project root
ENV_FILE = os.path.join(ROOT_DIR, ".env")


def load_env(path=ENV_FILE):
    """Read KEY=VALUE lines from .env into os.environ (without overwriting)."""
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ.setdefault(key.strip(), value.strip())
    # The shared lab<->shop API secret is created automatically the first time.
    if not os.environ.get("SIM_API_SECRET"):
        secret = secrets.token_hex(32)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"\n# Shared secret for signed Lab -> Shop simulation API calls (auto-generated)\n"
                     f"SIM_API_SECRET={secret}\n")
        os.environ["SIM_API_SECRET"] = secret


load_env()


class Config:
    APP_NAME = "LabMart"
    SECRET_KEY = os.environ.get("SHOP_SECRET_KEY") or secrets.token_hex(32)

    DATABASE = os.path.join(BASE_DIR, "instance", "shop.db")
    SANDBOX_FOLDER = os.path.join(BASE_DIR, "sandbox", "dummy_files")
    LOG_FOLDER = os.path.join(BASE_DIR, "logs")

    # Session cookie. A UNIQUE cookie name matters: browsers share cookies between
    # 127.0.0.1:5000 and 127.0.0.1:5001, so the shop and lab must not both use "session".
    SESSION_COOKIE_NAME = "labmart_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False                     # True when served over HTTPS
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024

    # Login protection
    MAX_FAILED_LOGINS = 5
    LOCKOUT_MINUTES = 10
    BRUTE_FORCE_WINDOW_MIN = 5
    BRUTE_FORCE_THRESHOLD = 5
    RATE_LIMIT_PER_MINUTE = 300
    CSRF_ENABLED = True

    # ---- Midtrans Sandbox (keys come ONLY from .env) ----
    MIDTRANS_SERVER_KEY = os.environ.get("MIDTRANS_SERVER_KEY", "")   # secret: server side only
    MIDTRANS_CLIENT_KEY = os.environ.get("MIDTRANS_CLIENT_KEY", "")   # public key (not needed in redirect mode)
    MIDTRANS_IS_PRODUCTION = False                                    # forced sandbox in this project
    MIDTRANS_SNAP_URL = "https://app.sandbox.midtrans.com/snap/v1/transactions"
    MIDTRANS_API_URL = "https://api.sandbox.midtrans.com/v2"

    # ---- Simulation API (called by the Cyber Lab) ----
    SIM_API_SECRET = os.environ.get("SIM_API_SECRET", "")
    SIM_API_CLIENT_ID = "seclab-01"
    SIM_API_MAX_SKEW = 60                 # seconds a signed request stays valid
    SIM_API_ALLOW_PRIVATE_ONLY = True     # only localhost / private lab network may call it

    # Demo accounts (created on first run)
    DEFAULT_ADMIN = ("admin", "admin@labmart.test", "Admin@12345")
    DEFAULT_CUSTOMER = ("budi", "budi@labmart.test", "Customer@123")
    SYNTHETIC_CUSTOMERS = 25
