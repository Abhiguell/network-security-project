"""
Start WEBSITE 2, the CyberSim Lab:   python run_lab.py
Then open http://127.0.0.1:5001   (start the store first with: python run_shop.py)
"""
import os

from lab import create_app

app = create_app()

if __name__ == "__main__":
    print("=" * 62)
    print(" WEBSITE 2 · CyberSim Lab (attack simulator)  http://127.0.0.1:5001")
    for u, p, r in app.config["DEFAULT_USERS"]:
        print(f" {r:<8}: {u} / {p}")
    print(f" Target store: {app.config['SHOP_URL']}")
    print("=" * 62)
    app.run(host=os.environ.get("LAB_HOST", "127.0.0.1"), port=5001, debug=os.environ.get("FLASK_DEBUG") == "1",
            threaded=True)
