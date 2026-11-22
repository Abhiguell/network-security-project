"""
shop/routes/store.py: homepage, product catalog, product page and shopping cart.

The cart lives in the (signed) session cookie as {product_id: quantity}.
Prices are NEVER taken from the browser; they're always re-read from the database.
"""
from flask import Blueprint, abort, flash, g, redirect, render_template, request, session, url_for

from ..db import execute, now_str, query
from ..security import monitor

bp = Blueprint("store", __name__)


@bp.route("/account-verification")
def phishing_notice():
    """
    Where the simulated "verify your account" lure leads. It is an AWARENESS page:
    there is no form and nothing is collected. The click itself is logged so the
    admin can see how many shoppers would have fallen for it.
    """
    lure = query("SELECT id FROM incidents WHERE kind = 'spyware' AND status = 'open' ORDER BY id DESC LIMIT 1", one=True)
    who = g.user["username"] if g.user else "guest"
    if lure:
        execute("INSERT INTO sim_traffic (ts, ip, module, kind, operator, detail) VALUES (?, ?, 'phishing', 'click', ?, ?)",
                (now_str(), monitor.client_ip(), "store", f"lure clicked by {who}"))
        monitor.log_event("medium", "Phishing Lure Clicked",
                          f"Shopper '{who}' clicked the simulated 'verify your account' message (SIMULATED)",
                          f"incident={lure['id']}", source="simulation")
    return render_template("store/phishing_notice.html", active=bool(lure))

MAX_QTY = 10


def cart_items():
    """Return (items, total) for the current cart, using live DB prices."""
    cart = session.get("cart", {})
    items, total = [], 0
    for pid, qty in cart.items():
        p = query("SELECT * FROM products WHERE id = ? AND is_active = 1", (int(pid),), one=True)
        if p is None:
            continue
        qty = max(1, min(int(qty), MAX_QTY, p["stock"]))
        subtotal = p["price"] * qty
        items.append({"product": p, "product_id": p["id"], "name": p["name"], "price": p["price"],
                      "qty": qty, "subtotal": subtotal})
        total += subtotal
    return items, total


@bp.route("/")
def home():
    featured = query("SELECT * FROM products WHERE is_active = 1 ORDER BY id LIMIT 8")
    categories = query("SELECT category, COUNT(*) AS c FROM products WHERE is_active = 1 GROUP BY category")
    return render_template("store/home.html", featured=featured, categories=categories)


@bp.route("/products")
def catalog():
    q = request.args.get("q", "").strip()[:50]
    category = request.args.get("category", "").strip()[:30]
    sql, args = "SELECT * FROM products WHERE is_active = 1", []
    if q:
        sql += " AND (name LIKE ? OR description LIKE ?)"
        args += [f"%{q}%", f"%{q}%"]
    if category:
        sql += " AND category = ?"
        args.append(category)
    products = query(sql + " ORDER BY name", args)
    categories = [r["category"] for r in query("SELECT DISTINCT category FROM products ORDER BY category")]
    return render_template("store/catalog.html", products=products, categories=categories, q=q, category=category)


@bp.route("/product/<int:pid>")
def product(pid):
    p = query("SELECT * FROM products WHERE id = ? AND is_active = 1", (pid,), one=True)
    if p is None:
        abort(404)
    related = query("SELECT * FROM products WHERE category = ? AND id != ? AND is_active = 1 LIMIT 4",
                    (p["category"], pid))
    return render_template("store/product.html", p=p, related=related)


@bp.route("/cart")
def cart():
    items, total = cart_items()
    return render_template("store/cart.html", items=items, total=total)


@bp.route("/cart/add", methods=["POST"])
def cart_add():
    pid = request.form.get("product_id", type=int)
    qty = request.form.get("qty", 1, type=int) or 1
    p = query("SELECT * FROM products WHERE id = ? AND is_active = 1", (pid,), one=True)
    if p is None:
        abort(404)
    cart = session.get("cart", {})
    new_qty = min(MAX_QTY, p["stock"], cart.get(str(pid), 0) + max(1, qty))
    if new_qty < 1:
        flash("Sorry, this product is out of stock.", "warning")
        return redirect(url_for("store.product", pid=pid))
    cart[str(pid)] = new_qty
    session["cart"] = cart
    flash(f"Added {p['name']} to your cart.", "success")
    return redirect(url_for("store.catalog") if request.form.get("back") == "catalog" else url_for("store.cart"))


@bp.route("/cart/update", methods=["POST"])
def cart_update():
    pid = str(request.form.get("product_id", type=int))
    qty = request.form.get("qty", 0, type=int)
    cart = session.get("cart", {})
    if qty <= 0:
        cart.pop(pid, None)
    elif pid in cart:
        cart[pid] = min(qty, MAX_QTY)
    session["cart"] = cart
    return redirect(url_for("store.cart"))
