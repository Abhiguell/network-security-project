"""
lab/client.py: the ONLY way the Cyber Lab talks to the store.

Every call is signed with HMAC-SHA256 using the shared secret from .env.
The secret itself is never sent; the store recomputes the signature and
rejects anything that doesn't match, is older than 60 s, or reuses a nonce.

canonical_string = METHOD \n PATH \n TIMESTAMP \n NONCE \n OPERATOR \n ROLE \n SHA256(body)
"""
import hashlib
import hmac
import json
import secrets
import time

import requests


class ShopAPIError(Exception):
    def __init__(self, status, message):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.message = message


def sign(secret, method, path, ts, nonce, operator, role, body):
    canonical = "\n".join([method.upper(), path, str(ts), nonce, operator, role, hashlib.sha256(body).hexdigest()])
    return hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()


class ShopClient:
    def __init__(self, base_url, secret, client_id, operator, role, http=requests, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.secret, self.client_id = secret, client_id
        self.operator, self.role = operator, role
        self.http, self.timeout = http, timeout     # `http` can be swapped for a test adapter

    def _request(self, method, path, payload=None):
        body = json.dumps(payload).encode() if payload is not None else b""
        ts, nonce = str(int(time.time())), secrets.token_hex(16)
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "CyberSimLab/1.0 (+simulation)",
            "X-Lab-Client": self.client_id,
            "X-Lab-Timestamp": ts,
            "X-Lab-Nonce": nonce,
            "X-Lab-Operator": self.operator,
            "X-Lab-Role": self.role,
            "X-Lab-Signature": sign(self.secret, method, path, ts, nonce, self.operator, self.role, body),
        }
        try:
            resp = self.http.request(method, self.base_url + path, data=body, headers=headers, timeout=self.timeout)
        except requests.RequestException as exc:
            raise ShopAPIError(0, f"Store unreachable at {self.base_url} ({exc.__class__.__name__}). "
                                  "Is run_shop.py running?") from exc
        try:
            data = resp.json()
        except ValueError:
            data = {"message": resp.text[:200]}
        if resp.status_code >= 400:
            raise ShopAPIError(resp.status_code, data.get("message") or data.get("error") or "error")
        return data

    # ---- API methods ----
    def status(self):
        return self._request("GET", "/api/sim/status")

    def spyware_collect(self, limit=25):
        return self._request("POST", "/api/sim/spyware/collect", {"limit": limit})

    def ransomware_state(self):
        return self._request("GET", "/api/sim/ransomware/state")

    def ransomware_start(self):
        return self._request("POST", "/api/sim/ransomware/start", {})

    def ransomware_reset(self):
        return self._request("POST", "/api/sim/ransomware/reset", {})

    def trojan_event(self, phase, bot_id, seq=0, nbytes=0):
        return self._request("POST", "/api/sim/trojan/event",
                             {"phase": phase, "bot_id": bot_id, "seq": seq, "bytes": nbytes})

    def reset_all(self):
        return self._request("POST", "/api/sim/reset", {})
