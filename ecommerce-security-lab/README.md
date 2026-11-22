# E-Commerce Security Testing and Malware Simulation Laboratory

Two **separate** websites for a Network Security project:

| | Website 1: **LabMart** (victim) | Website 2: **CyberSim Lab** (attack simulator) |
|---|---|---|
| URL | http://127.0.0.1:5000 | http://127.0.0.1:5001 |
| Purpose | Working online store with Midtrans Sandbox, admin dashboard and security monitoring | Control panel that runs spyware / ransomware / trojan simulations against the store |
| Look | Light retail theme | Dark cybersecurity console |
| Accounts | admin `admin / Admin@12345` · customer `budi / Customer@123` | `labadmin / LabAdmin@123` · `analyst / Analyst@123` · `viewer / Viewer@123` (read-only) |
| Database | `shop/instance/shop.db` | `lab/instance/lab.db` |

They talk **only** through an HMAC-signed REST API (`/api/sim/...` on the store).

## Run it (Windows)
```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
start_all.bat
```
`start_all.bat` opens both servers in two windows and both sites in your browser.
Manual alternative: `python run_shop.py` in one terminal, then `python run_lab.py` in a second one.

**Live demo:** Tab 1 = LabMart admin, Tab 2 = CyberSim Lab. Click **Start Spyware / Ransomware / Trojan Simulation**
in the lab; within 3 seconds the store's admin shows a pop-up alert, a red incident banner and a new threat level.
**Reset environment** on the lab dashboard undoes everything.

## Midtrans Sandbox (optional)
1. Create a free account at https://dashboard.sandbox.midtrans.com and copy the **Sandbox** Server Key and Client Key (start with `SB-Mid-`).
2. Put them in `.env` (see `.env.example`): `MIDTRANS_SERVER_KEY=SB-Mid-server-...`
3. Restart `run_shop.py`. Checkout now redirects to Midtrans' payment page.
   Test card `4811 1111 1111 1114`, CVV `123`, any future expiry, OTP `112233`.

Without keys the store uses a clearly-labelled **Demo gateway**, so the demo always works offline.
Only sandbox keys (`SB-…`) are accepted; the server key never leaves the server.

## Tests
```
python -m unittest discover -s tests -v
```
29 tests cover the store, payments (Midtrans mocked), the signed API, both access-control systems, all three
simulations end-to-end, reset, and the store being offline.

## Safety guarantees
* The lab can only read rows flagged `is_synthetic = 1` (25 generated customers with `@example.com` emails).
* Real customers, orders and payments are never returned or modified (verified by tests).
* Ransomware touches only `shop/sandbox/dummy_files/`, never encrypts/renames/deletes; SHA-256 proves it.
* The trojan has no persistence and no remote access. It only sends simulated network events.
* Simulation endpoints need: HMAC signature + 60 s timestamp + one-time nonce + lab role admin/analyst +
  private/loopback IP + the store admin's "API enabled" switch.

Docs: `docs/PROJECT_DOCUMENTATION.md` (architecture, API, security, testing, Wireshark) · `docs/DEMO_SCRIPT.md`.
