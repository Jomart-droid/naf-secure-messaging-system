"""Reset local demo account passwords.

Usage:
    python scripts/reset_demo_passwords.py "NewStrongPassword123!"

This script is for local/demo databases only. Do not run it against production data.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app, db
from app.models import User


def main():
    if len(sys.argv) != 2:
        raise SystemExit('Usage: python scripts/reset_demo_passwords.py "NewStrongPassword123!"')
    password = sys.argv[1]
    if len(password) < 12:
        raise SystemExit("Password must be at least 12 characters.")

    app = create_app()
    with app.app_context():
        users = User.query.order_by(User.id.asc()).all()
        for user in users:
            user.set_password(password)
            user.must_change_password = True
            user.failed_login_count = 0
            user.locked_until = None
        db.session.commit()
        print(f"Reset {len(users)} local/demo account password(s).")


if __name__ == "__main__":
    main()
