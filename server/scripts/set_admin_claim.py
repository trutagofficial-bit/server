"""
set_admin_claim.py
===================
Run this ONCE, locally, by you, to grant the isAdmin custom claim to
the admin dashboard's Firebase user. This is deliberately a manual
script and not an HTTP endpoint — nothing in api.py can ever grant
this claim, by design (spec §2: "custom claim isAdmin: true (set only
via Admin SDK, never client)").

Setup:
    pip install firebase-admin
Usage (run in the same folder as hemm.json, or set FIREBASE_CRED_PATH):
    python set_admin_claim.py zuAwKiOHCLbKF7jFiw7Cdr4WI352
"""
import sys
import os
import firebase_admin
from firebase_admin import auth, credentials

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python set_admin_claim.py <admin-firebase-uid>")
        sys.exit(1)

    uid = sys.argv[1]
    cred_path = os.environ.get("FIREBASE_CRED_PATH", "hemm.json")

    if not firebase_admin._apps:
        firebase_admin.initialize_app(credentials.Certificate(cred_path))

    auth.set_custom_user_claims(uid, {"isAdmin": True})
    print(f"Granted isAdmin=true to uid={uid}. They must sign out/in again for the new token claim to take effect.")
