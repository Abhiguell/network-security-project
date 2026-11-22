# E-Commerce Security Testing and Malware Simulation Laboratory

**Course:** Network Security · **Stack:** Python Flask, SQLite, HTML/CSS/JavaScript, REST, Midtrans Sandbox, Wireshark, VirtualBox

---

## 1. Overview

The project is a **two-website system**:

1. **LabMart** (victim): a functional online store with catalog, cart, checkout, Midtrans Sandbox payment,
   customer profiles, order history, an admin dashboard and security monitoring.
2. **CyberSim Lab** (attack simulator): a separate cybersecurity control panel with three simulation modules:
   **Spyware**, **Ransomware** and **Trojan**.

A presenter opens the store in one tab and the lab in another. Clicking a simulation in the lab produces visible,
logged, **simulated** effects in the store: alerts, incidents, threat level changes and traffic records.
Nothing real is harmed: the lab can only reach synthetic data, a sandbox folder and simulated network events.

## 2. Architecture

```
┌──────────────────────── Browser (2 tabs, separate cookies) ─────────────────────────┐
│  Tab 1: LabMart  (cookie labmart_session)        Tab 2: CyberSim Lab (seclab_session)│
└─────────────┬────────────────────────────────────────────────┬──────────────────────┘
              │ HTTP :5000                                      │ HTTP :5001
┌─────────────▼──────────────────────────┐        ┌─────────────▼──────────────────────┐
│ WEBSITE 1 · shop/ (Flask)              │        │ WEBSITE 2 · lab/ (Flask)           │
│ store · auth · account · checkout      │        │ auth (roles) · pages · api         │
│ admin (dashboard, incidents, events)   │ ◄───── │ simulations.py (spyware/ransomware │
│ simapi  /api/sim/*  ← HMAC-protected   │ signed │   /trojan thread/reset)            │
│ security: WAF, CSRF, lockout, monitor  │  REST  │ client.py (HMAC signer)            │
│ payments/midtrans.py ──► Midtrans      │        │                                    │
│ SQLite shop.db · sandbox/dummy_files   │        │ SQLite lab.db                      │
└────────────────────────────────────────┘        └────────────────────────────────────┘
```

* **Separate frontends:** different templates, CSS themes, JavaScript, ports and session cookie names.
  (Cookies are shared across ports on the same host, so unique cookie names are required.)
* **Separate auth:** store users (customer/admin) vs. lab operators (admin/analyst/viewer), in different databases.
* **REST API:** the only connection between the two apps.

### Data model (store)
`users` (with `is_synthetic`), `products`, `orders` (with `is_synthetic`), `order_items`, `security_events`
(with `source` = web | simulation), `incidents`, `activity_log`, `login_attempts`, `sim_traffic`, `api_nonces`, `settings`.

### Data model (lab)
`lab_users`, `sim_runs`, `run_logs`, `lab_events`.

## 3. Simulation API (store side)

| Method | Path | Effect |
|---|---|---|
| GET | `/api/sim/status` | health, synthetic record count, open incidents, threat level |
| POST | `/api/sim/spyware/collect` | returns up to 50 **synthetic** customer records; logs HIGH + CRITICAL events; opens incident |
| GET | `/api/sim/ransomware/state` | sandbox files and SHA-256 hashes |
| POST | `/api/sim/ransomware/start` | marks sandbox files "locked" (state flag only); CRITICAL incident |
| POST | `/api/sim/ransomware/reset` | removes the flag, verifies hashes, resolves the incident |
| POST | `/api/sim/trojan/event` | phases `install`, `beacon`, `exfil`, `stop`; beacon detection |
| POST | `/api/sim/reset` | resolves all incidents, acknowledges simulation events, clears simulated traffic |

### Authentication of every API request
```
X-Lab-Client: seclab-01        X-Lab-Timestamp: 1763280000     X-Lab-Nonce: 32 hex chars
X-Lab-Operator: analyst        X-Lab-Role: analyst             X-Lab-Signature: HMAC_SHA256(secret, canonical)

canonical = METHOD \n PATH \n TIMESTAMP \n NONCE \n OPERATOR \n ROLE \n SHA256(body)
```
The store rejects a request (and logs **Unauthorized Simulation API Access**) when the signature is wrong, the
timestamp is more than 60 s off, the nonce was already used (**replay attack**), the role is not admin/analyst,
the source IP is not loopback/private, or the store admin has disabled the API.
The shared secret lives only in `.env`; it is never transmitted.

## 4. The three simulations

### 4.1 Spyware
**Lab:** *Start Spyware Simulation* → signed POST `/spyware/collect` → shows the exposed records, the record count,
bytes exposed and how many real accounts were protected. All results are labelled **SIMULATED**.
**Store:** query is restricted with `WHERE is_synthetic = 1`; passwords appear as "NOT EXPOSED (salted hash)" and
payment data as "NOT STORED (Midtrans)". Events: *Spyware Data Exposure* (high), *Mass Data Access* (critical).
Incident: "Simulated spyware exposed N synthetic customer records".
**Lesson:** least privilege, hashing, not storing card data, DLP alerts on bulk PII reads, UU PDP notification duty.

### 4.2 Ransomware
**Lab:** *Start Ransomware Simulation* → files appear as `*.locked`, with victim ID and fake ransom.
*Reset & verify integrity* restores and proves every SHA-256 hash is unchanged.
**Store:** works only in `shop/sandbox/dummy_files/` (path guard refuses any other folder); writes only a small
`.sim_state.json`. Events: mass file access (high), mass rename + ransom note (critical). CRITICAL incident.
**Lesson:** offline 3-2-1 backups, EDR behaviour detection, patching, segmentation, incident response.

### 4.3 Trojan
**Lab:** *Start Trojan Simulation* (interval and count selectable, **Stop** available) runs a background thread:
`install` → N × `beacon` (with one fake 512-byte `exfil` after beacon 6) → `stop`. A live table shows every connection.
**Store:** *Suspicious Application* (medium) and *Suspicious Connection* (low), then the beacon detector raises
**C2 Beaconing** (high) once 5+ check-ins arrive with low timing jitter. Events are recorded in **both** dashboards
(store security log + lab event log). No persistence, no remote access, no files written.
**Lesson:** application allow-listing, egress filtering, IDS/beacon detection, user awareness.

### Reset
*Reset environment* (lab dashboard) stops a running trojan, restores the sandbox, resolves incidents and acknowledges
simulation alerts. It never deletes or edits real customers, orders or payments.

## 5. E-commerce security controls

| Control | Implementation |
|---|---|
| SQL injection | parameterised queries everywhere + WAF signature blocking |
| XSS | Jinja auto-escaping, `textContent` in JS, strict CSP (`script-src 'self'`) |
| CSRF | per-session token on every form/POST (machine endpoints use HMAC / Midtrans signature instead) |
| Authentication | salted password hashes, strong-password policy, lockout after 5 failures, brute-force alerts, timing-safe login |
| Sessions | HttpOnly, SameSite=Lax, 30-min expiry, regenerated on login, browser-fingerprint hijack detection |
| Authorisation | customer vs admin, separate admin portal, IDOR checks on orders |
| Payments | Midtrans **redirect** mode (no third-party JS on our pages, card data never on our server); server key only in `.env`; finish URL and webhook both re-verified with the Status API; webhook `signature_key` (SHA-512) check; paid amount must equal order total (tampering alert); prices always re-read from the DB |
| Monitoring | security events (DB + `shop/logs/security.log`), activity log, incidents, live admin toasts, threat level |
| Headers | CSP, X-Frame-Options DENY, nosniff, Referrer-Policy, no-store |

## 6. Installation

See `README.md`. Summary: create a virtual environment, `pip install -r requirements.txt`, run `start_all.bat`
(or `python run_shop.py` and `python run_lab.py`). `.env` is created automatically with the shared API secret.
Add Midtrans **Sandbox** keys to `.env` to use real sandbox payments; otherwise the Demo gateway is used.

### Two-VM VirtualBox setup (optional)
* Host-Only network (e.g. 192.168.56.0/24). VM-A runs the store with `SHOP_HOST=0.0.0.0`; VM-B runs the lab with
  `SHOP_URL=http://192.168.56.10:5000`. Copy the **same** `SIM_API_SECRET` into both `.env` files.
* The store accepts simulation calls only from private/loopback addresses.
* Midtrans needs internet access, so use the Demo gateway on an isolated network, or add a NAT adapter to VM-A.

## 7. Testing

`python -m unittest discover -s tests -v` runs **29 tests**:

* **Store (12):** pages, registration, full checkout with stock update, DB-priced totals, IDOR, admin/customer
  separation, SQL injection, lockout, separate cookies; Midtrans: Snap redirect payload, server key never in HTML,
  finish verified via Status API, amount tampering, webhook signature.
* **Signed API (8):** unsigned, wrong secret, replay, expired timestamp, viewer role, public IP, API disabled;
  spyware returns only synthetic rows and leaves a SHA-256 snapshot of real users/orders unchanged; ransomware
  integrity; trojan beaconing; global reset.
* **Lab (9):** login required, page rendering, viewer blocked, CSRF, and end-to-end spyware / ransomware / trojan /
  reset from the lab into the store, plus graceful failure when the store is offline.

Manual checklist: follow `docs/DEMO_SCRIPT.md`.

## 8. Network traffic analysis (Wireshark)

Capture on the **Npcap loopback adapter** (single PC) or the Host-Only adapter (two VMs).

| Filter | Shows |
|---|---|
| `tcp.port == 5000` | all traffic to the store |
| `http.request.uri contains "/api/sim"` | every lab → store simulation call |
| `http.request.uri contains "trojan"` | trojan beacons (use *Statistics → I/O Graph*: evenly spaced spikes) |
| `http.request.uri contains "spyware"` | the data-exposure request; the response is large (~9 KB of PII) |
| `http.request.method == "POST" && http.request.uri contains "/login"` | login posts: the password is visible in plain HTTP |
| `http.response.code == 401` | rejected API calls (bad signature / replay) |

Talking points: *Follow → HTTP Stream* shows `X-Lab-Signature` and the nonce but **not** the secret (HMAC);
replaying a captured request fails because the nonce is single-use and the timestamp expires; plaintext HTTP
exposes passwords and personal data, so production must use HTTPS/TLS.

## 9. Recommendations for production
HTTPS + HSTS and `SESSION_COOKIE_SECURE`; MFA for admins; a production WSGI server and mature WAF (ModSecurity/OWASP CRS);
Redis-backed rate limiting; column encryption for PII; SIEM forwarding (Wazuh/ELK); regular offline backups and restore tests;
Midtrans webhook on a public HTTPS URL; secrets in a vault instead of `.env`; mutual TLS or OAuth2 client credentials for service-to-service APIs.

## 10. Conclusion
The laboratory shows the full chain **attack → detection → response → recovery** on a realistic e-commerce target,
while guaranteeing safety: synthetic data only, sandboxed files, simulated network events, and a strictly
authenticated, auditable and switch-off-able API between the attacker console and the victim store.
