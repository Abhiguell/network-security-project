"""
Start WEBSITE 1, the LabMart e-commerce store:   python run_shop.py
Then open http://127.0.0.1:5000
"""
import os

from shop import create_app

app = create_app()

if __name__ == "__main__":
    a, c = app.config["DEFAULT_ADMIN"], app.config["DEFAULT_CUSTOMER"]
    print("=" * 62)
    print(" WEBSITE 1 · LabMart e-commerce store      http://127.0.0.1:5000")
    print(f" Store admin : {a[0]} / {a[2]}   (admin portal: /admin/login)")
    print(f" Customer    : {c[0]} / {c[2]}")
    from shop.payments import midtrans
    with app.app_context():
        print(" Payments    : " + ("Midtrans SANDBOX" if midtrans.is_configured() else "Demo gateway (no Midtrans keys in .env)"))
    print("=" * 62)
    app.run(host=os.environ.get("SHOP_HOST", "127.0.0.1"), port=5000, debug=os.environ.get("FLASK_DEBUG") == "1",
            threaded=True)
