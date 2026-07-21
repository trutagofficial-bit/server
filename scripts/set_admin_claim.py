"""
server/scripts/set_admin_claim.py
===================================
Run this ONCE, locally, by you, to grant the isAdmin custom claim to
the admin dashboard's Firebase user. This is deliberately a manual
script and not an HTTP endpoint — nothing in api.py can ever grant
this claim, by design (spec §2: "custom claim isAdmin: true (set only
via Admin SDK, never client)").

Usage:
    export FIREBASE_CRED_PATH=/path/to/rotated-service-account.json
    python -m server.scripts.set_admin_claim <admin-firebase-uid>

Find the uid in Firebase Console -> Authentication -> Users, after the
admin has signed in once via the new admin-login screen.
"""

import sys

import firebase_admin
from firebase_admin import auth, credentials
import os

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m server.scripts.set_admin_claim <admin-firebase-uid>")
        sys.exit(1)

    uid = sys.argv[1]
    cred_path = os.environ.get("FIREBASE_CRED_PATH", "hemm.json")

    if not firebase_admin._apps:
        firebase_admin.initialize_app(credentials.Certificate(cred_path))

    auth.set_custom_user_claims(uid, {"isAdmin": True})
    print(f"Granted isAdmin=true to uid={uid}. They must sign out/in again for the new token claim to take effect.")
