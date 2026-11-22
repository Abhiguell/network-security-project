"""
shop/ransomware_sandbox.py: SAFE ransomware simulation target inside the shop.

What real ransomware does:
  1. Finds the victim's documents.
  2. Encrypts them and renames them (e.g. report.docx -> report.docx.locked).
  3. Drops a ransom note demanding payment.

What THIS simulation does:
  * Works ONLY with dummy files that it creates itself in sandbox/dummy_files/.
  * NEVER encrypts, renames, modifies or deletes any file. The "locked" state is
    just a small JSON note (.sim_state.json) that the web page reads to show the
    files as "encrypted".
  * Shows SHA-256 hashes before and after so you can PROVE nothing changed.
  * reset() removes the JSON note and restores the dummy set.
"""
import hashlib
import json
import os
import secrets
from datetime import datetime

STATE_FILE = ".sim_state.json"

# Fictional documents (no real data).
DUMMY_FILES = {
    "product_catalog_backup.csv": "sku,name,price\nLM-001,Wireless Earbuds Pro,459000\n(dummy backup for simulation)\n",
    "invoice_template.txt": "LabMart Invoice Template v2 (dummy file for ransomware simulation)\n",
    "customer_export_SYNTHETIC.csv": "name,email\nAndi Example,andi@example.com\n(synthetic data only)\n",
    "promo_banner_assets.txt": "banner_1111.png\nbanner_harbolnas.png\n(dummy asset list)\n",
    "shipping_rates.json": '{"JNE": 12000, "SiCepat": 11000, "note": "dummy"}\n',
    "sales_report_Q3.txt": "Q3 sales (fictional): Rp 123.456.789\n",
    "supplier_contacts.csv": "supplier,email\nPT Contoh Jaya,sales@example.org\n",
    "store_config_backup.txt": "theme=default\ncurrency=IDR\n(dummy config)\n",
}


def _safe_folder(folder):
    """Refuse to run anywhere except the dedicated sandbox folder."""
    real = os.path.realpath(folder)
    if not real.replace("\\", "/").endswith("sandbox/dummy_files"):
        raise RuntimeError("Ransomware simulation may only run inside sandbox/dummy_files")
    os.makedirs(real, exist_ok=True)
    return real


def _sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def ensure_dummy_files(folder):
    folder = _safe_folder(folder)
    for name, content in DUMMY_FILES.items():
        path = os.path.join(folder, name)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
    return folder


def _read_state(folder):
    path = os.path.join(folder, STATE_FILE)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def get_state(folder):
    """Everything the web page needs: file list, hashes, attack status."""
    folder = ensure_dummy_files(folder)
    state = _read_state(folder)
    files = []
    for name in DUMMY_FILES:
        path = os.path.join(folder, name)
        files.append({
            "name": name,
            "size": os.path.getsize(path),
            "sha256": _sha256(path),
            "locked": bool(state),
            "display_name": f"{name}.locked" if state else name,
        })
    return {"attacked": bool(state), "state": state, "files": files}


def run_attack(folder):
    """Simulate the attack (writes ONLY the small JSON state file)."""
    folder = ensure_dummy_files(folder)
    before = {f["name"]: f["sha256"] for f in get_state(folder)["files"]}
    state = {
        "victim_id": secrets.token_hex(6).upper(),
        "started": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ransom": "2.5 BTC (FAKE)",
        "wallet": "SIMULATION-ONLY-NO-REAL-WALLET",
        "hashes_before": before,
    }
    with open(os.path.join(folder, STATE_FILE), "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
    return get_state(folder)


def reset(folder):
    """Remove the simulation state and recreate any missing dummy files."""
    folder = _safe_folder(folder)
    state = _read_state(folder)
    path = os.path.join(folder, STATE_FILE)
    if os.path.exists(path):
        os.remove(path)
    result = get_state(folder)
    if state:
        before = state.get("hashes_before", {})
        result["integrity_ok"] = all(before.get(f["name"]) == f["sha256"] for f in result["files"])
    else:
        result["integrity_ok"] = True
    return result
