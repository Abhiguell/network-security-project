"""
shop/seed.py: fills an empty database with demo data.

* 12 products
* 1 admin + 1 "real" demo customer (budi), is_synthetic = 0
* 25 SYNTHETIC customers with fake orders, is_synthetic = 1
  Names are invented, emails use the reserved example.com domain, phone numbers
  use a fake 0000 block, and synthetic accounts have an unusable random password.
"""
import random
import secrets

from werkzeug.security import generate_password_hash

from .db import execute, now_str, query, set_setting

PRODUCTS = [
    ("LM-001", "Wireless Earbuds Pro", "Electronics", "Bluetooth 5.3 earbuds with noise cancelling and 30h battery.", 459000, 40, "🎧", "#6366f1"),
    ("LM-002", "Mechanical Keyboard 75%", "Electronics", "Hot-swappable switches, RGB backlight, USB-C.", 689000, 25, "⌨️", "#0ea5e9"),
    ("LM-003", "Smartwatch Fit 2", "Electronics", "Heart-rate, SpO2, GPS and 10-day battery.", 899000, 18, "⌚", "#14b8a6"),
    ("LM-004", "Power Bank 20.000 mAh", "Electronics", "Fast charging 22.5W, two USB-A + one USB-C.", 249000, 60, "🔋", "#22c55e"),
    ("LM-005", "Batik Shirt Parang", "Fashion", "Cotton batik shirt, slim fit, hand-finished.", 325000, 30, "👔", "#b45309"),
    ("LM-006", "Canvas Sneakers", "Fashion", "Classic low-top sneakers, unisex sizes 36-44.", 279000, 45, "👟", "#ef4444"),
    ("LM-007", "Laptop Backpack 15\"", "Fashion", "Water-resistant, anti-theft zipper, USB port.", 349000, 35, "🎒", "#334155"),
    ("LM-008", "Kopi Gayo Arabica 250g", "Food & Drink", "Single-origin Aceh Gayo coffee beans, medium roast.", 98000, 80, "☕", "#78350f"),
    ("LM-009", "Keripik Singkong Pedas", "Food & Drink", "Spicy cassava chips, 3 x 200g pack.", 45000, 120, "🌶️", "#dc2626"),
    ("LM-010", "Teh Melati Premium", "Food & Drink", "Jasmine tea, 50 tea bags.", 39000, 100, "🍵", "#65a30d"),
    ("LM-011", "Desk Lamp LED", "Home", "Dimmable LED lamp with wireless charger base.", 219000, 28, "💡", "#f59e0b"),
    ("LM-012", "Ceramic Mug Set", "Home", "Set of 4 handmade ceramic mugs, 350 ml.", 159000, 50, "🍶", "#a855f7"),
]

FIRST = ["Andi", "Sari", "Rizky", "Dewi", "Fajar", "Putri", "Bayu", "Intan", "Galih", "Maya", "Yoga", "Nadia",
         "Reza", "Ayu", "Hendra", "Lestari", "Dimas", "Wulan", "Arif", "Citra", "Eko", "Fitri", "Joko", "Rina", "Tono"]
LAST = ["Pratama", "Wijaya", "Santoso", "Kusuma", "Saputra", "Lestari", "Hidayat", "Nugroho", "Permata",
        "Siregar", "Halim", "Gunawan"]
STREETS = ["Jl. Contoh", "Jl. Simulasi", "Jl. Uji Coba", "Jl. Dummy Raya", "Jl. Fiktif"]
CITIES = ["Cikarang (synthetic)", "Bekasi (synthetic)", "Bandung (synthetic)", "Jakarta (synthetic)",
          "Bogor (synthetic)", "Depok (synthetic)"]


def _order_code(prefix="LM"):
    return f"{prefix}-{secrets.token_hex(4).upper()}"


def seed(app):
    if query("SELECT COUNT(*) AS c FROM products", one=True)["c"] == 0:
        for p in PRODUCTS:
            execute("INSERT INTO products (sku, name, category, description, price, stock, emoji, color) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", p)

    for (username, email, password), role, name in (
        (app.config["DEFAULT_ADMIN"], "admin", "Store Administrator"),
        (app.config["DEFAULT_CUSTOMER"], "customer", "Budi Demo"),
    ):
        if query("SELECT id FROM users WHERE username = ?", (username,), one=True) is None:
            execute("INSERT INTO users (username, email, password_hash, full_name, phone, address, city, role, "
                    "is_synthetic, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
                    (username, email, generate_password_hash(password), name, "081200000001",
                     "Kampus Lab, Ruang 204", "Cikarang", role, now_str()))

    if query("SELECT COUNT(*) AS c FROM users WHERE is_synthetic = 1", one=True)["c"] == 0:
        rng = random.Random(2026)          # fixed seed -> same synthetic data every install
        products = query("SELECT id, name, price FROM products")
        for i in range(app.config["SYNTHETIC_CUSTOMERS"]):
            first, last = FIRST[i % len(FIRST)], rng.choice(LAST)
            username = f"syn_{first.lower()}{i + 1:02d}"
            uid = execute(
                "INSERT INTO users (username, email, password_hash, full_name, phone, address, city, role, "
                "is_synthetic, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'customer', 1, ?)",
                (username, f"{first.lower()}.{last.lower()}{i + 1}@example.com",
                 # random 24-byte password nobody knows -> account can't be used to sign in
                 generate_password_hash(secrets.token_urlsafe(24), method="pbkdf2:sha256:1000"),
                 f"{first} {last}", f"+62-812-0000-{1000 + i:04d}",
                 f"{rng.choice(STREETS)} No. {rng.randint(1, 120)}", rng.choice(CITIES), now_str()))
            for _ in range(rng.randint(1, 3)):
                items = rng.sample(list(products), rng.randint(1, 3))
                qtys = [rng.randint(1, 2) for _ in items]
                total = sum(p["price"] * q for p, q in zip(items, qtys))
                oid = execute(
                    "INSERT INTO orders (order_code, user_id, status, payment_method, payment_status, total, "
                    "shipping_name, shipping_phone, shipping_address, is_synthetic, created_at, paid_at) "
                    "VALUES (?, ?, 'paid', 'demo', 'settlement', ?, ?, ?, ?, 1, ?, ?)",
                    (_order_code("SYN"), uid, total, f"{first} {last}", f"+62-812-0000-{1000 + i:04d}",
                     "synthetic address", now_str(), now_str()))
                for p, q in zip(items, qtys):
                    execute("INSERT INTO order_items (order_id, product_id, name, price, qty) VALUES (?, ?, ?, ?, ?)",
                            (oid, p["id"], p["name"], p["price"], q))

    if query("SELECT value FROM settings WHERE key = 'sim_api_enabled'", one=True) is None:
        set_setting("sim_api_enabled", "1")
