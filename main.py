"""
TruTag — Live Push Notification Listener + Users Report
==========================================================
Do modes:
  1) Live listener (default) — Firebase Realtime DB pe naye
     notifications ka wait karta hai aur turant real FCM push
     bhejta hai us user ke phone pe.
  2) Report — sabhi users, unka FCM token, aur notifications
     ek baar print karta hai (purana behavior).

Setup:
    pip install firebase-admin
Run (listener — default):
    python main.py
Run (report only):
    python main.py --report
"""

import os
import ssl
import smtplib
import sys
import threading
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

import firebase_admin
from firebase_admin import credentials, db, messaging

# ─────────────────────────────────────────────
#  FIREBASE ADMIN INIT
#  Migration spec §0 / per-file change list: credential path now comes
#  from FIREBASE_CRED_PATH env var (falls back to "hemm.json" for local
#  dev only). The actual key file must be rotated in Firebase Console
#  and never committed to git — see server/.gitignore.
#
#  Guarded with `if not firebase_admin._apps` because this module gets
#  imported by api.py (FastAPI app) as well as run standalone — without
#  the guard, importing it twice (or reloading under uvicorn --reload)
#  would raise "The default Firebase app already exists".
# ─────────────────────────────────────────────
_CRED_PATH = os.environ.get("FIREBASE_CRED_PATH", "hemm.json")

if not firebase_admin._apps:
    cred = credentials.Certificate(_CRED_PATH)
    firebase_admin.initialize_app(cred, {
        "databaseURL": "https://trutag-ef578-default-rtdb.asia-southeast1.firebasedatabase.app"
    })


# ─────────────────────────────────────────────
#  EMAIL FALLBACK CONFIG
#  ─────────────────────────────────────────────
#  Push notification fail ho jaaye (invalid/missing FCM token) tab
#  bhi "important" notifications user tak email ke through pahunch
#  jaayen — isliye Gmail SMTP + app password use kar rahe hain.
#
#  SECURITY: App password ko seedha yahan hardcode karne ke bajaye
#  environment variable se lena better hai (production me):
#      export TRUTAG_EMAIL_APP_PASSWORD="xxxx xxxx xxxx xxxx"
#  Agar env var set nahi hai, to neeche wala fallback value use hoga
#  — isse code repo/git mein commit MAT karo agar real password hai.
# ─────────────────────────────────────────────
SMTP_HOST = "smtp.gmail.com"   # Custom domain email use karoge to provider ke hisaab se badlo
SMTP_PORT = 465

# ⚠️ Abhi personal Gmail use ho raha hai. Jab domain email ready ho jaaye
# (jaise alerts@trutag.in via Google Workspace/Zoho), ye do values +
# SMTP_HOST + app password sab update karna — spam problem ka sabse bada
# fix yehi hai (SPF/DKIM/DMARC verified domain, personal Gmail nahi).
SENDER_EMAIL = "trutagofficial@gmail.com"
SENDER_APP_PASSWORD = os.environ.get(
    "TRUTAG_EMAIL_APP_PASSWORD",
    "zhct mthd zidf bcvy"  # ⚠️ REPLACE with your real 16-char Gmail App Password
).replace(" ", "")

# Logo ab hosted URL se load hoga (attachment/inline-CID ke bajaye) —
# apna real logo URL yahan daal do.
LOGO_URL = "https://i.ibb.co/VcQRjgtt/icon.png"


# =============================================
#  EMAIL FALLBACK — jab push na pahunch paaye
# =============================================
def send_email_notification(to_email, title, body, user_name=None):
    """
    Push notification fail ho (ya token hi na ho) tab is function se
    same message email ke through bheja jaata hai — TruTag logo (hosted
    URL se) ke saath, app jaisi dark-theme design mein, HTML + plain-text
    dono formats mein, proper headers ke saath (taaki spam mein na jaaye).

    user_name diya ho to email "Hi {name}," se personalized hoti hai —
    generic/bulk-looking mail spam filters ko zyada suspicious lagti hai,
    naam se address karna ek real, targeted message jaisa signal deta hai.

    Returns True/False (success/failure) — kabhi exception raise
    nahi karta, taaki listener/loop kabhi crash na ho.
    """
    if not to_email:
        print("⚠️  Email fallback skip — user ka email hi nahi mila")
        return False

    # 'alternative' hi outer container ho sakta hai ab kyunki image
    # attachment nahi hai, sirf hosted URL — 'related' ki zaroorat nahi.
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"TruTag Alert: {title}"
    msg["From"] = f"TruTag <{SENDER_EMAIL}>"
    msg["To"] = to_email
    msg["Reply-To"] = SENDER_EMAIL

    # Ye do headers Gmail/Outlook jaise clients ko batate hain ki mail
    # "asli" hai, malformed/spoofed nahi — inke bina automated mail
    # bahut zyada spam-score paati hai.
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="trutagofficial.app")

    # Gmail policy: bulk/automated senders ke liye List-Unsubscribe
    # header zaroori hai, warna Gmail sidha Spam mein daal deta hai —
    # chahe content bilkul legit ho. Abhi hosted unsubscribe page nahi
    # hai, isliye mailto: fallback diya hai (support ko reply karke
    # unsubscribe maang sakta hai user).
    msg["List-Unsubscribe"] = f"<mailto:{SENDER_EMAIL}?subject=Unsubscribe>"

    logo_html = (
        f'<img src="{LOGO_URL}" alt="TruTag" width="56" height="56" '
        f'style="width:56px;height:56px;object-fit:contain;display:block;margin:0 auto 12px;'
        f'border-radius:14px;">'
    )

    # Personalization — "Hi Rahul," generic "Dear Customer" se kahin
    # zyada trustworthy signal hai spam filters ke liye.
    first_name = (user_name or "").strip().split(" ")[0] if user_name else ""
    greeting_name = first_name if first_name else "there"

    # ── Plain-text alternative — spam filters ise HTML-only mail se
    #    zyada trust karte hain (real users bhejte hain, bots nahi). ──
    text_body = (
        f"Hi {greeting_name},\n\n"
        f"TruTag Alert: {title}\n\n"
        f"{body}\n\n"
        f"------------------------------\n"
        f"Ye alert email par bheja gaya hai kyunki app notification "
        f"aapke device tak nahi pahunch payi.\n"
        f"Notification preferences badalne ke liye App > Settings kholen, "
        f"ya humein reply karein: {SENDER_EMAIL}\n"
        f"TruTag — Safe Connect for Your Vehicle\n"
    )

    # ── Dark, app-jaisa design (welcome.js / styles.css se match) ──
    # Note: 'Inter' web font zyadatar email clients (Gmail included)
    # strip kar dete hain, isliye system font stack fallback rakha
    # hai — colors/spacing app ke jaise hi rakhe hain.
    html_body = f"""
    <div style="background:#020617;padding:32px 16px;">
      <div style="font-family:-apple-system,'Segoe UI',Arial,sans-serif;max-width:420px;
                  margin:0 auto;background:#0f172a;border:1px solid #334155;
                  border-radius:16px;overflow:hidden;">

        <!-- Header: logo + brand, jaise welcome screen -->
        <div style="padding:28px 24px 20px;text-align:center;border-bottom:1px solid #334155;">
          {logo_html}
          <div style="font-size:22px;font-weight:800;letter-spacing:0.04em;color:#f8fafc;">
            Tru<span style="color:#3b82f6;">Tag</span>
          </div>
          <div style="font-size:11px;color:#9ca3af;margin-top:4px;letter-spacing:0.02em;">
            Safe Connect for Your Vehicle
          </div>
        </div>

        <!-- Alert content -->
        <div style="padding:24px;">
          <p style="color:#e2e8f0;font-size:14px;margin:0 0 14px;">Hi {greeting_name},</p>
          <div style="display:inline-block;background:rgba(59,130,246,0.15);color:#60a5fa;
                      font-size:11px;font-weight:600;padding:4px 10px;border-radius:9999px;
                      margin-bottom:14px;letter-spacing:0.02em;">
            ALERT
          </div>
          <h3 style="color:#f8fafc;margin:0 0 10px;font-size:16px;">{title}</h3>
          <p style="color:#cbd5e1;font-size:14px;line-height:1.6;margin:0;">{body}</p>
        </div>

        <!-- Footer -->
        <div style="padding:16px 24px 24px;border-top:1px solid #334155;">
          <p style="color:#6b7280;font-size:11px;line-height:1.5;margin:0 0 8px;">
            Ye alert email par bheja gaya hai kyunki app notification aapke device tak nahi pahunch payi.
          </p>
          <p style="color:#6b7280;font-size:11px;line-height:1.5;margin:0;">
            Notification preferences badalne ke liye App &gt; Settings kholen, ya
            <a href="mailto:{SENDER_EMAIL}?subject=Unsubscribe" style="color:#60a5fa;">yahan unsubscribe request bhejen</a>.
          </p>
        </div>
      </div>
    </div>
    """

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context) as server:
            server.login(SENDER_EMAIL, SENDER_APP_PASSWORD)
            server.send_message(msg)  # send_message() header handling zyada reliable hai vs sendmail()
        print(f"📧 Email fallback bheja: {to_email} → \"{title}\"")
        return True
    except Exception as e:
        print(f"❌ Email fallback fail ({to_email}): {e}")
        return False


def is_important(notif):
    """
    Notification "important" hai ya nahi — email fallback tabhi
    SKIP hota hai jab notification explicitly low-priority marked ho.
    Baaki har notification (call, complaint, alert, etc.) by default
    important maani jaati hai, taaki push fail hone par email zaroor
    jaaye.

    Kisi specific notification ko email fallback se EXCLUDE karna ho
    (jaise routine/info reminders), to Firebase mein set karo:
        notifications/{id}/important = false
        ya notifications/{id}/type = "info" / "low"
    """
    if not isinstance(notif, dict):
        return False
    if notif.get("important") is False:
        return False
    return notif.get("type") not in ("info", "low", "reminder")


# =============================================
#  MODE 1 — LIVE PUSH LISTENER
# =============================================
def on_new_notification(event):
    """
    Firebase 'users' node pe har change pe fire hota hai —
    isliye pehle filter karo ki ye ek asli naya notification
    entry hai (users/{uid}/notifications/{notifId}), warna
    ignore karo (status update, fcmToken update, initial full
    tree dump, delete event, etc.)
    """
    parts = [p for p in (event.path or "").strip("/").split("/") if p]

    if len(parts) != 3 or parts[1] != "notifications":
        return  # naya notification nahi hai — skip

    uid, _, notif_id = parts
    notif = event.data

    if not isinstance(notif, dict):
        return  # delete event (data None) ya corrupt data — skip

    user = db.reference(f"users/{uid}").get() or {}
    token = user.get("fcmToken")
    email = user.get("email")
    name = user.get("name")
    title = notif.get("title", "TruTag")
    body_text = notif.get("sub") or notif.get("body") or ""
    important = is_important(notif)

    if not token:
        print(f"⚠️  {uid} ke paas FCM token nahi hai — push skip")
        # Token hi nahi hai — push kabhi pahunch hi nahi sakti.
        # Important message ho to seedha email fallback chalao.
        if important:
            send_email_notification(email, title, body_text, user_name=name)
        return

    # Is user ke saare notifications se unread count nikalo — isi count
    # ko data payload mein bhejenge taaki native Java side (background
    # FCM receiver) app khule bina bhi ShortcutBadger.applyCount() se
    # app icon badge update kar sake.
    all_notifs = user.get("notifications", {}) or {}
    unread_count = sum(
        1 for n in all_notifs.values()
        if isinstance(n, dict) and n.get("unread")
    )

    message = messaging.Message(
        notification=messaging.Notification(
            title=title,
            body=body_text
        ),
        token=token,
        data={
            "notifId": notif_id,
            "type": notif.get("type", "info"),
            # Native side isi field ko padh ke background mein
            # ShortcutBadger.applyCount(context, badge) call karega
            "badge": str(unread_count),
        }
    )

    try:
        messaging.send(message)
        print(f"✅ Push bheja: {uid} → \"{title}\"  (badge={unread_count})")
    except Exception as e:
        print(f"❌ Push fail ({uid}): {e}")
        # Push server-side hi fail ho gayi (invalid/unregistered token,
        # app uninstall, etc.) — is case mein bhi agar message important
        # hai to email fallback se user tak pahunchate hain.
        if important:
            send_email_notification(email, title, body_text, user_name=name)


def run_listener():
    db.reference("users").listen(on_new_notification)
    print("Listening for new notifications...")
    # listen() background thread pe chalta hai, isliye process ko
    # zinda rakhna zaroori hai warna script turant exit ho jaayegi.
    # Event().wait() bina input/command ke silently block karta hai —
    # koi on/off toggle nahi, koi keypress trigger nahi. Sirf naya
    # notification aane pe on_new_notification() khud print karega.
    # Process sirf tabhi rukega jab tumhi ise band karoge (Ctrl+C ya
    # window close).
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nStopped.")


# =============================================
#  MODE 2 — ONE-TIME USERS REPORT (purana behavior)
# =============================================
def fmt_time(ms):
    if not ms:
        return "—"
    try:
        return datetime.fromtimestamp(ms / 1000).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ms)


def print_report():
    users = db.reference("users").get() or {}

    if not users:
        print("❌ users/ node me koi bhi user nahi mila.")
        return

    print("=" * 70)
    print(f"TruTag — All Users Report   ({len(users)} users mile)")
    print("=" * 70)

    for uid, udata in users.items():
        if not isinstance(udata, dict):
            continue

        name = udata.get("name", "—")
        email = udata.get("email", "—")
        phone = udata.get("phone", "—")
        status = udata.get("status", "—")
        linked_vehicle = udata.get("linkedVehicleId", "—")
        vehicle = udata.get("vehicle", {}) or {}
        vnumber = vehicle.get("number", "—")
        fcm_token = udata.get("fcmToken")

        print(f"\n👤 {name}")
        print(f"   UID:            {uid}")
        print(f"   Email:          {email}")
        print(f"   Phone:          {phone}")
        print(f"   Status:         {status}")
        print(f"   Vehicle Number: {vnumber}   (QR: {linked_vehicle})")

        if fcm_token:
            print(f"   FCM Token:      ✅ {fcm_token[:25]}...{fcm_token[-12:]}")
        else:
            print(f"   FCM Token:      ❌ MISSING — is user ko push nahi ja sakti")

        notifications = udata.get("notifications", {}) or {}
        if not notifications:
            print(f"   Notifications:  (koi nahi)")
        else:
            print(f"   Notifications:  ({len(notifications)} total)")
            sorted_notifs = sorted(
                notifications.items(),
                key=lambda kv: kv[1].get("time", 0) if isinstance(kv[1], dict) else 0,
                reverse=True
            )
            for notif_id, n in sorted_notifs:
                if not isinstance(n, dict):
                    continue
                title = n.get("title", "—")
                sub = n.get("sub") or n.get("body") or "—"
                time_str = fmt_time(n.get("time"))
                unread = "🔵 unread" if n.get("unread") else "  read"
                print(f"     • [{time_str}] {title} — \"{sub}\"  ({unread})")

    print("\n" + "=" * 70)
    print("Report khatam.")
    print("=" * 70)


if __name__ == "__main__":
    if "--report" in sys.argv:
        print_report()
    else:
        run_listener()
