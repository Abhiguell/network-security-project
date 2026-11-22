"""
shop/security/validators.py: input validation for the store.
Never trust the browser: check format and length before using input.
"""
import re

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
NAME_RE = re.compile(r"^[A-Za-z .'\-]{2,60}$")
PHONE_RE = re.compile(r"^\+?[0-9\- ]{8,20}$")
ADDRESS_RE = re.compile(r"^[A-Za-z0-9 .,'/#()\-]{5,150}$")
CITY_RE = re.compile(r"^[A-Za-z .()\-]{2,40}$")


def validate_username(v):
    return None if USERNAME_RE.match(v or "") else "Username must be 3-20 letters, numbers or underscore."


def validate_email(v):
    return None if v and len(v) <= 100 and EMAIL_RE.match(v) else "Please enter a valid email address."


def validate_name(v):
    return None if NAME_RE.match(v or "") else "Name must be 2-60 letters (spaces, . ' - allowed)."


def validate_phone(v):
    return None if PHONE_RE.match(v or "") else "Phone must be 8-20 digits (spaces, - and + allowed)."


def validate_address(v):
    return None if ADDRESS_RE.match(v or "") else "Address must be 5-150 characters without special symbols."


def validate_city(v):
    return None if CITY_RE.match(v or "") else "City must be 2-40 letters."


def validate_password(p):
    p, problems = p or "", []
    if len(p) < 8:
        problems.append("at least 8 characters")
    if len(p) > 128:
        problems.append("at most 128 characters")
    if not re.search(r"[A-Z]", p):
        problems.append("an uppercase letter")
    if not re.search(r"[a-z]", p):
        problems.append("a lowercase letter")
    if not re.search(r"\d", p):
        problems.append("a number")
    if not re.search(r"[^A-Za-z0-9]", p):
        problems.append("a symbol")
    return problems


def mask_email(email):
    """budi@labmart.test -> b***@labmart.test (used in admin lists)."""
    if not email or "@" not in email:
        return email
    name, domain = email.split("@", 1)
    return f"{name[:1]}***@{domain}"
