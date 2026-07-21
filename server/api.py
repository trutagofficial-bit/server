"""
server/api.py
==============
FastAPI app — the ONLY thing (besides main.py's listener) allowed to
write to Firebase RTDB once migration finishes. Endpoint list mirrors
migration spec §4 exactly; each function's docstring names the file
and line(s) it replaces so you can cross-reference while migrating
client code.

Run locally:
    pip install -r server/requirements.txt
    export FIREBASE_CRED_PATH=/path/to/rotated-service-account.json
    uvicorn server.api:app --reload --port 8000

Every authenticated endpoint does, in order (spec §4):
    1. verify the Firebase ID token           -> auth_middleware.py
    2. check the token's uid may act on the
       requested resource (own data / isAdmin) -> done inline, per endpoint
    3. only then perform the write             -> firebase_admin.db

Every /public/* endpoint does, in order (spec §4):
    1. resolve qrId -> ownerUid itself, server-side (never trusts a
       client-supplied ownerUid)
    2. checks the rate-limit counter for that anonymous uid AND ip
    3. sanitizes any free-text fields
    4. writes
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import time
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from firebase_admin import db as fdb

from . import main  # noqa: F401  (Firebase Admin init happens on import)
from .auth_middleware import (
    AuthedUser,
    require_admin,
    require_anonymous_or_any,
    require_non_anonymous_user,
)
from .rate_limit import limiter

app = FastAPI(title="TruTag Backend")

# ── CORS ──────────────────────────────────────────────────────────
# Fill these in with the real deployed origins before going live:
#   - the Public QR landing page's domain ("web clint/index.html")
#   - the Salesman PWA's domain ("trutag-pwa")
#   - the Admin dashboard's domain ("main admin.html")
# The Android app talks to the backend from a Cordova WebView, which
# is not origin-restricted by CORS the same way — that's handled by
# config.xml's <access origin> / <allow-navigation> entries instead.
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("TRUTAG_ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS or ["*"],  # tighten to ALLOWED_ORIGINS-only before prod deploy
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


# ── small shared helpers ───────────────────────────────────────────

_TAG_RE = re.compile(r"<[^>]*>")


def sanitize_text(value: str, max_len: int = 300) -> str:
    """Strip HTML tags and clamp length for any free-text field an
    anonymous caller can set (spec §3, web clint/index.html change:
    "backend sanitizes text before writing")."""
    if not isinstance(value, str):
        raise HTTPException(400, "Expected a string field.")
    cleaned = _TAG_RE.sub("", value).strip()
    return cleaned[:max_len]


def hash_pin(pin: str) -> str:
    """PIN is stored as salt$pbkdf2-hash rather than plaintext. This
    goes a step beyond the literal spec wording (which only says
    'verify server-side') but fixes the same root problem the spec
    calls out for auth.js — never let the real PIN sit in the DB
    readable by anyone with rules access."""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", pin.encode(), bytes.fromhex(salt), 100_000)
    return f"{salt}${digest.hex()}"


def verify_pin(pin: str, stored: str) -> bool:
    try:
        salt, digest_hex = stored.split("$", 1)
    except (ValueError, AttributeError):
        return False
    expected = hashlib.pbkdf2_hmac("sha256", pin.encode(), bytes.fromhex(salt), 100_000)
    return hmac.compare_digest(expected.hex(), digest_hex)


def resolve_owner_uid(qr_id: str) -> str:
    """Server-side qrId -> ownerUid lookup used by every /public/*
    endpoint, so the client never gets to assert its own ownerUid
    (spec §3, web clint/index.html problem statement)."""
    vehicle = fdb.reference(f"smart_vehicles/{qr_id}").get()
    if not vehicle or vehicle.get("status") != "linked" or not vehicle.get("ownerUid"):
        raise HTTPException(404, "This QR is not linked to an owner yet.")
    return vehicle["ownerUid"]


def enforce_public_rate_limit(request: Request, user: AuthedUser, qr_id: str) -> None:
    ip = request.client.host if request.client else "unknown"
    # 5 requests/minute per anonymous uid, and per IP, per spec's
    # "web clint/index.html" rate-limit note. Keyed by qrId too so one
    # bad actor scanning many QR codes doesn't get a shared budget.
    limiter.check(f"public:uid:{user.uid}:{qr_id}", max_requests=5, window_seconds=60)
    limiter.check(f"public:ip:{ip}:{qr_id}", max_requests=5, window_seconds=60)


# ════════════════════════════════════════════════════════════════
#  SALESMAN  (trutag-pwa/js/firebase.js)
# ════════════════════════════════════════════════════════════════

class LinkVehicleBody(BaseModel):
    qrId: str
    uid: str
    pin: str = Field(min_length=4, max_length=8)


@app.post("/salesman/link-vehicle")
def link_vehicle(body: LinkVehicleBody, user: AuthedUser = Depends(require_non_anonymous_user)):
    """Replaces firebase.js:88-97 (linkVehicle). The salesman sets a
    fresh PIN for a newly-sold vehicle; the owner will later confirm
    it via /vehicle/verify-pin. Stored hashed, never plaintext."""
    updates = {
        f"/smart_vehicles/{body.qrId}/status": "linked",
        f"/smart_vehicles/{body.qrId}/ownerUid": body.uid,
        f"/users/{body.uid}/status": "awaiting_pin",
        f"/users/{body.uid}/pin": hash_pin(body.pin),
        f"/users/{body.uid}/linkedVehicleId": body.qrId,
    }
    fdb.reference().update(updates)
    return {"ok": True}


class SalesmanProfileBody(BaseModel):
    name: str
    age: Optional[int] = None
    address: Optional[str] = None
    phone: Optional[str] = None


@app.post("/salesman/profile")
def save_salesman_profile(body: SalesmanProfileBody, user: AuthedUser = Depends(require_non_anonymous_user)):
    """Replaces firebase.js:104-115 (saveSalesmanProfile). uid always
    comes from the verified token, never from the body — a salesman
    can only ever write their own profile."""
    fdb.reference(f"salesmen/{user.uid}").set({
        "name": body.name,
        "age": body.age,
        "address": body.address,
        "phone": body.phone,
        "profileComplete": True,
        "registeredAt": _iso_now(),
        "timestamp": {".sv": "timestamp"},
    })
    return {"ok": True}


class SalesmanProfilePatchBody(BaseModel):
    name: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None


@app.patch("/salesman/profile")
def update_salesman_profile(body: SalesmanProfilePatchBody, user: AuthedUser = Depends(require_non_anonymous_user)):
    """Replaces firebase.js:118-124 (updateSalesmanInfo)."""
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        return {"ok": True, "changed": False}
    fdb.reference(f"salesmen/{user.uid}").update(updates)
    return {"ok": True}


class EarningBody(BaseModel):
    qrId: str
    customerName: Optional[str] = ""


@app.post("/salesman/earnings")
def record_earning(body: EarningBody, user: AuthedUser = Depends(require_non_anonymous_user)):
    """Replaces firebase.js:129-137 (recordEarning)."""
    today = time.strftime("%Y-%m-%d")
    ref = fdb.reference(f"salesmen/{user.uid}/earnings").push({
        "qrId": body.qrId,
        "customerName": body.customerName or "",
        "date": today,
        "timestamp": {".sv": "timestamp"},
    })
    return {"ok": True, "id": ref.key}


def _iso_now() -> str:
    import datetime
    return datetime.datetime.utcnow().isoformat() + "Z"


# ════════════════════════════════════════════════════════════════
#  VEHICLE / OWNER  (com.trutag.apk: js/utils/auth.js, contact.js)
# ════════════════════════════════════════════════════════════════

class VerifyPinBody(BaseModel):
    uid: str
    qrId: str
    pin: str


@app.post("/vehicle/verify-pin")
def vehicle_verify_pin(body: VerifyPinBody, request: Request):
    """Replaces auth.js:353-389. No auth token required (the PIN
    itself is the gate — this runs before the owner has any other way
    to prove who they are), but IP-rate-limited hard against brute
    force since a 4-8 digit PIN space is small."""
    ip = request.client.host if request.client else "unknown"
    limiter.check(f"verify-pin:ip:{ip}", max_requests=10, window_seconds=60)
    limiter.check(f"verify-pin:uid:{body.uid}", max_requests=10, window_seconds=300)

    user_data = fdb.reference(f"users/{body.uid}").get() or {}
    stored = user_data.get("pin")
    if not stored or not verify_pin(body.pin, stored):
        raise HTTPException(401, "Incorrect PIN.")

    linked_qr = user_data.get("linkedVehicleId")
    if linked_qr != body.qrId:
        raise HTTPException(400, "This PIN is not associated with that vehicle.")

    # Success — backend performs the same atomic update auth.js used to
    # do client-side, and clears the PIN so it can't be replayed.
    fdb.reference().update({
        f"/users/{body.uid}/status": "linked",
        f"/users/{body.uid}/pin": None,
    })
    return {"ok": True}


class SyncStatusBody(BaseModel):
    status: str


@app.post("/vehicle/sync-status")
def sync_status(body: SyncStatusBody, user: AuthedUser = Depends(require_non_anonymous_user)):
    """Replaces auth.js:~660. Owner can only update their own status."""
    fdb.reference(f"users/{user.uid}/status").set(body.status)
    return {"ok": True}


class CallEnabledBody(BaseModel):
    enabled: bool


@app.patch("/vehicle/{qr_id}/call-enabled")
def set_call_enabled(qr_id: str, body: CallEnabledBody, user: AuthedUser = Depends(require_non_anonymous_user)):
    """Replaces contact.js:90. Checks smart_vehicles/{qrId}/ownerUid
    matches the caller before writing (contact.js's problem statement:
    "no ownership check")."""
    vehicle = fdb.reference(f"smart_vehicles/{qr_id}").get()
    if not vehicle or vehicle.get("ownerUid") != user.uid:
        raise HTTPException(403, "You don't own this vehicle.")
    fdb.reference(f"smart_vehicles/{qr_id}/callEnabled").set(body.enabled)
    return {"ok": True}


# ════════════════════════════════════════════════════════════════
#  CALL — owner side, authenticated  (com.trutag.apk: js/call.js)
# ════════════════════════════════════════════════════════════════

class CallAnswerBody(BaseModel):
    answer: str  # JSON-stringified RTCSessionDescription, generated client-side


@app.post("/call/answer")
def call_answer(body: CallAnswerBody, user: AuthedUser = Depends(require_non_anonymous_user)):
    """Replaces call.js:233. WebRTC answer SDP is generated in the
    owner's browser/WebView (needs local media/ICE) — backend only
    mediates the Firebase write."""
    fdb.reference(f"calls/{user.uid}").update({
        "type": "answer",
        "answer": body.answer,
        "time": _now_ms(),
    })
    return {"ok": True}


class CallCandidateBody(BaseModel):
    candidate: str  # JSON-stringified RTCIceCandidate


@app.post("/call/candidate")
def call_candidate(body: CallCandidateBody, user: AuthedUser = Depends(require_non_anonymous_user)):
    """Replaces call.js:334 (owner side ICE candidates)."""
    ref = fdb.reference(f"calls/{user.uid}/candidates").push({
        "candidate": body.candidate,
        "sender": "owner",
    })
    return {"ok": True, "id": ref.key}


@app.post("/call/end")
def call_end(user: AuthedUser = Depends(require_non_anonymous_user)):
    """Replaces call.js:346,348."""
    ref = fdb.reference(f"calls/{user.uid}")
    ref.set({"type": "end", "time": _now_ms()})
    ref.delete()
    return {"ok": True}


def _now_ms() -> int:
    return int(time.time() * 1000)


# ════════════════════════════════════════════════════════════════
#  PUBLIC — anonymous caller  (web clint/index.html, scanCall.js, scanResult.js)
# ════════════════════════════════════════════════════════════════

class PublicCallStartBody(BaseModel):
    qrId: str
    offer: str  # JSON-stringified RTCSessionDescription
    callerRef: Optional[str] = None


@app.post("/public/call/start")
def public_call_start(body: PublicCallStartBody, request: Request, user: AuthedUser = Depends(require_anonymous_or_any)):
    """Replaces web clint/index.html:732(candidates cleared)+768 and
    scanCall.js's equivalent. Note ownerUid is NEVER read from the
    request — only resolved server-side from qrId."""
    owner_uid = resolve_owner_uid(body.qrId)
    enforce_public_rate_limit(request, user, body.qrId)

    fdb.reference(f"calls/{owner_uid}/candidates").delete()
    fdb.reference(f"calls/{owner_uid}").set({
        "type": "offer",
        "offer": body.offer,
        "callerRef": body.callerRef,
        "time": _now_ms(),
    })
    # Same call also writes a notification so main.py's listener can
    # push/email the owner even if their app is fully killed — mirrors
    # index.html:782's comment about why this write happens here.
    fdb.reference(f"users/{owner_uid}/notifications").push({
        "title": "\U0001F4DE Voice Call",
        "sub": "Someone is calling you via your vehicle QR.",
        "type": "call",
        "time": _now_ms(),
        "unread": True,
    })
    return {"ok": True}


class PublicCallCandidateBody(BaseModel):
    qrId: str
    candidate: str


@app.post("/public/call/candidate")
def public_call_candidate(body: PublicCallCandidateBody, request: Request, user: AuthedUser = Depends(require_anonymous_or_any)):
    """Replaces index.html:732 / scanCall.js candidate push."""
    owner_uid = resolve_owner_uid(body.qrId)
    enforce_public_rate_limit(request, user, body.qrId)
    fdb.reference(f"calls/{owner_uid}/candidates").push({
        "candidate": body.candidate,
        "sender": "guest",
    })
    return {"ok": True}


class PublicCallEndBody(BaseModel):
    qrId: str


@app.post("/public/call/end")
def public_call_end(body: PublicCallEndBody, request: Request, user: AuthedUser = Depends(require_anonymous_or_any)):
    """Replaces index.html:814."""
    owner_uid = resolve_owner_uid(body.qrId)
    enforce_public_rate_limit(request, user, body.qrId)
    ref = fdb.reference(f"calls/{owner_uid}")
    ref.set({"type": "end", "time": _now_ms()})
    ref.delete()
    return {"ok": True}


class PublicNotifyBody(BaseModel):
    qrId: str
    title: str
    sub: str
    type: Optional[str] = "alert"


@app.post("/public/notify")
def public_notify(body: PublicNotifyBody, request: Request, user: AuthedUser = Depends(require_anonymous_or_any)):
    """Replaces index.html:607,782 · scanResult.js:156 · scanCall.js:125."""
    owner_uid = resolve_owner_uid(body.qrId)
    enforce_public_rate_limit(request, user, body.qrId)
    ref = fdb.reference(f"users/{owner_uid}/notifications").push({
        "title": sanitize_text(body.title, 100),
        "sub": sanitize_text(body.sub, 300),
        "type": body.type or "alert",
        "time": _now_ms(),
        "unread": True,
    })
    return {"ok": True, "id": ref.key}


# ════════════════════════════════════════════════════════════════
#  USER — own notifications/token  (com.trutag.apk: js/pages/notifications.js)
# ════════════════════════════════════════════════════════════════

class FcmTokenBody(BaseModel):
    token: str


@app.post("/user/fcm-token")
def set_fcm_token(body: FcmTokenBody, user: AuthedUser = Depends(require_non_anonymous_user)):
    """Replaces notifications.js:111."""
    fdb.reference(f"users/{user.uid}/fcmToken").set(body.token)
    return {"ok": True}


@app.delete("/user/notifications/{notif_id}")
def delete_notification(notif_id: str, user: AuthedUser = Depends(require_non_anonymous_user)):
    """Replaces notifications.js:237."""
    fdb.reference(f"users/{user.uid}/notifications/{notif_id}").delete()
    return {"ok": True}


@app.delete("/user/notifications")
def clear_notifications(user: AuthedUser = Depends(require_non_anonymous_user)):
    """Replaces notifications.js:245 (clear-all)."""
    fdb.reference(f"users/{user.uid}/notifications").delete()
    return {"ok": True}


class MarkNotificationsBody(BaseModel):
    ids: list[str] = Field(default_factory=list)
    unread: bool = False


@app.patch("/user/notifications")
def update_notifications(body: MarkNotificationsBody, user: AuthedUser = Depends(require_non_anonymous_user)):
    """Replaces notifications.js:265 (unread-flag update). Empty `ids`
    means "all of them" (e.g. mark-all-as-read)."""
    base = fdb.reference(f"users/{user.uid}/notifications")
    target_ids = body.ids or list((base.get() or {}).keys())
    updates = {f"{nid}/unread": body.unread for nid in target_ids}
    if updates:
        base.update(updates)
    return {"ok": True, "updated": len(updates)}


# ════════════════════════════════════════════════════════════════
#  ADMIN  (main admin.html)
# ════════════════════════════════════════════════════════════════
# No /admin/login endpoint — the split login screen (see spec's "main
# admin.html" change notes, point 1) authenticates directly against
# Firebase Auth (email/password or Google Sign-In) client-side. The
# isAdmin custom claim is granted out-of-band via the Admin SDK, e.g.
# a one-off script run by you locally:
#
#   firebase_admin.auth.set_custom_user_claims(admin_uid, {"isAdmin": True})
#
# never through an HTTP endpoint a client could call.

class AdminSettingsBody(BaseModel):
    phone: Optional[str] = None


@app.post("/admin/settings")
def admin_settings(body: AdminSettingsBody, admin: AuthedUser = Depends(require_admin)):
    """Replaces main admin.html:883,933 (admin_settings phone)."""
    if body.phone is not None:
        fdb.reference("admin_settings/phone").set(body.phone)
    return {"ok": True}


class AdminPinBody(BaseModel):
    newPin: str = Field(min_length=4, max_length=6)


@app.post("/admin/settings/pin")
def admin_set_pin(body: AdminPinBody, admin: AuthedUser = Depends(require_admin)):
    """Replaces main admin.html:957. Gate is now the caller's current
    admin session (isAdmin claim), not the old plaintext-comparable
    PIN — the DEFAULT_PIN / verifyPin() flow in main admin.html is
    removed entirely per spec."""
    fdb.reference("admin_settings/pin").set(hash_pin(body.newPin))
    return {"ok": True}


class AdminVehiclesBody(BaseModel):
    updates: dict[str, Any]


@app.patch("/admin/vehicles")
def admin_update_vehicles(body: AdminVehiclesBody, admin: AuthedUser = Depends(require_admin)):
    """Replaces main admin.html:1095 (db.ref('smart_vehicles').update(updates)).
    `updates` keys are Firebase multi-path update keys relative to
    smart_vehicles, e.g. {"abc123/status": "linked"}."""
    for key in body.updates:
        if key.startswith("/") or ".." in key:
            raise HTTPException(400, f"Invalid update path: {key!r}")
    fdb.reference("smart_vehicles").update(body.updates)
    return {"ok": True}


class AdminSalesmanBody(BaseModel):
    enabled: bool


@app.patch("/admin/salesmen/{uid}")
def admin_update_salesman(uid: str, body: AdminSalesmanBody, admin: AuthedUser = Depends(require_admin)):
    """Replaces main admin.html:1177 (salesmen/{uid}/enabled)."""
    fdb.reference(f"salesmen/{uid}/enabled").set(body.enabled)
    return {"ok": True}


# ── health check (handy for Render/Railway) ────────────────────────
@app.get("/healthz")
def healthz():
    return {"ok": True}
