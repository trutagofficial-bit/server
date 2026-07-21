"""
server/auth_middleware.py
==========================
FastAPI dependencies that verify the caller before any endpoint touches
the database. Every write path in api.py depends on one of these — see
migration spec §2 ("Auth model used across all endpoints") and §4
("Every authenticated endpoint does the same three things...").

Three dependencies, three trust levels:
  require_user()   -> any signed-in Firebase user (Google Sign-In or
                       Anonymous Auth). Returns the decoded token.
  require_admin()  -> signed-in user AND the custom claim isAdmin=true
                       (claim is set only via Admin SDK, never by a
                       client — see main admin.html change notes).
  require_anonymous_or_any() -> convenience wrapper for the /public/*
                       endpoints, which accept anonymous-auth tokens
                       but don't care about identity beyond rate-limiting.

None of these ever trust a uid the client puts in the request body for
authorization decisions — the uid used for permission checks always
comes from the verified token (decoded["uid"]), never from JSON.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Header, HTTPException, status
from firebase_admin import auth as firebase_auth

# Import main.py first so firebase_admin.initialize_app() has already
# run (main.py guards against double-init — see its top-of-file comment).
from . import main  # noqa: F401  (import for side effect: Firebase init)


@dataclass
class AuthedUser:
    uid: str
    token: dict
    is_admin: bool
    is_anonymous: bool


def _extract_bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header. Expected 'Bearer <Firebase ID token>'.",
        )
    return authorization.split(" ", 1)[1].strip()


def _verify(id_token: str) -> dict:
    try:
        # check_revoked=True forces a lookup against Firebase's revocation
        # list so a token from a signed-out/disabled account is rejected
        # even if it hasn't expired yet.
        return firebase_auth.verify_id_token(id_token, check_revoked=True)
    except firebase_auth.RevokedIdTokenError:
        raise HTTPException(status_code=401, detail="Session revoked, please sign in again.")
    except firebase_auth.ExpiredIdTokenError:
        raise HTTPException(status_code=401, detail="Session expired, please sign in again.")
    except Exception:
        # Deliberately generic — never leak *why* verification failed
        # (malformed vs. wrong project vs. tampered signature) to the client.
        raise HTTPException(status_code=401, detail="Invalid authentication token.")


async def require_user(authorization: str | None = Header(default=None)) -> AuthedUser:
    """Any signed-in Firebase user — Google Sign-In or Anonymous Auth."""
    id_token = _extract_bearer_token(authorization)
    decoded = _verify(id_token)
    return AuthedUser(
        uid=decoded["uid"],
        token=decoded,
        is_admin=bool(decoded.get("isAdmin", False)),
        is_anonymous=decoded.get("firebase", {}).get("sign_in_provider") == "anonymous",
    )


async def require_non_anonymous_user(authorization: str | None = Header(default=None)) -> AuthedUser:
    """Google Sign-In only — rejects anonymous-auth tokens. Use for
    salesman / owner / admin endpoints where the caller must be a real
    account, not just a rate-limit identity."""
    user = await require_user(authorization)
    if user.is_anonymous:
        raise HTTPException(status_code=403, detail="This action requires a signed-in account.")
    return user


async def require_admin(authorization: str | None = Header(default=None)) -> AuthedUser:
    """Signed-in user with the isAdmin custom claim. The claim is set
    exactly once, out-of-band, via the Admin SDK (see the one-off
    scripts/set_admin_claim.py helper) — there is intentionally no
    endpoint that lets a client grant itself this claim."""
    user = await require_non_anonymous_user(authorization)
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required.")
    return user


async def require_anonymous_or_any(authorization: str | None = Header(default=None)) -> AuthedUser:
    """For /public/* endpoints: any verified Firebase token works
    (anonymous or signed-in) — identity here is only used as a
    rate-limit key, never for permissions."""
    return await require_user(authorization)
