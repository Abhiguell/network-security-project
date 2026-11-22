# Live Demo Script (about 12 minutes)

**Before class:** delete `shop/instance/shop.db` and `lab/instance/lab.db` for a clean start, run `start_all.bat`,
and open Wireshark (Npcap loopback adapter, filter `tcp.port == 5000`).
Put the two browser tabs side by side: **Tab 1 = LabMart** (admin), **Tab 2 = CyberSim Lab** (analyst).

| Time | Tab | Action | What to say |
|---|---|---|---|
| 0:00 | slides | Architecture: two apps, two databases, one signed API | "The lab can only touch the store through a controlled, authenticated API." |
| 1:00 | 1 | Browse as a customer (`budi`), add to cart, checkout, pay (Midtrans Sandbox test card, or Demo gateway) | A normal e-commerce flow; card data never touches our server |
| 3:00 | 1 | Sign out, sign in at `/admin/login` as `admin` | Dashboard, threat level **SECURE**, customers list with 25 *synthetic* records |
| 4:00 | 2 | Sign in as `viewer`, try to start a simulation → refused | Role-based authorisation in the lab |
| 4:30 | 2 | Sign in as `analyst`. Dashboard shows **STORE API ONLINE** | HMAC signature, 60 s timestamp, one-time nonce |
| 5:00 | 2 | **Spyware → Start** | 25 synthetic records exposed; passwords/payment data NOT exposed; real accounts protected |
| 5:30 | 1 | Toasts + red incident banner + **UNDER ATTACK** | Detection: "Spyware Data Exposure" + "Mass Data Access" |
| 6:30 | 2 | **Ransomware → Start**, then **Reset & verify integrity** | Files "locked", ransom note; SHA-256 proves nothing changed = backups |
| 8:00 | 2 | **Trojan → Start** (1 s, 12 beacons). Show **Stop** | Fake voucher app, periodic C2 beacons, IDS flags low jitter |
| 9:00 | Wireshark | `http.request.uri contains "/api/sim/trojan"` → Statistics → I/O Graph | Evenly spaced spikes = machine beaconing. Follow HTTP Stream shows `X-Lab-Signature` but not the secret |
| 10:30 | 1 | Security events (filter Source = Cyber Lab), Incidents page, Simulation API page | Audit trail shows `lab:analyst`; admin can switch the API off |
| 11:30 | 2 | Dashboard → **Reset environment** | Incidents resolved, sandbox restored, threat level back to SECURE, real orders untouched |

**If something fails:** run `python -m unittest discover -s tests -v`. 29 passing tests prove every feature.
