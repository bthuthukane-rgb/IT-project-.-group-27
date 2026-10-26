"""Validation, password policy, CSRF, signed links, one-time codes, throttling."""
import re, time, hmac, hashlib, secrets, json
from flask import current_app, session, request
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from db import q, x

# ---------- password policy (mirrored live in static/js/app.js) ----------
COMMON = ["password", "password1", "password123", "123456789", "1234567890", "qwerty123",
          "letmein123", "welcome123", "admin123", "iloveyou", "abc123456", "passw0rd",
          "changeme", "qwertyuiop", "111111111", "000000000"]
MIN_LEN = 10
RULES = [  # (id, label)
    ("length", f"At least {MIN_LEN} characters"),
    ("upper", "One uppercase letter (A-Z)"),
    ("lower", "One lowercase letter (a-z)"),
    ("digit", "One number (0-9)"),
    ("special", "One special character (e.g. ! @ # $ % &)"),
    ("nospace", "No spaces"),
    ("common", "Not a common password"),
    ("personal", "Does not contain your name or email name"),
]


def check_password(pw, email="", name=""):
    """Return [(rule_id, label, passed)]."""
    pw = pw or ""
    low = pw.lower()
    bits = [b for b in re.split(r"[\s._@+-]+", (email or "").split("@")[0] + " " + (name or "")) if len(b) >= 3]
    ok = {
        "length": len(pw) >= MIN_LEN,
        "upper": bool(re.search(r"[A-Z]", pw)),
        "lower": bool(re.search(r"[a-z]", pw)),
        "digit": bool(re.search(r"\d", pw)),
        "special": bool(re.search(r"[^A-Za-z0-9\s]", pw)),
        "nospace": not re.search(r"\s", pw) and len(pw) > 0,
        "common": not any(c in low for c in COMMON),
        "personal": not any(b.lower() in low for b in bits),
    }
    return [(i, label, ok[i]) for i, label in RULES]


def password_errors(pw, email="", name=""):
    return [label for _, label, ok in check_password(pw, email, name) if not ok]


def rules_json():
    return json.dumps({"min": MIN_LEN, "common": COMMON, "rules": RULES})


# ---------- input validation ----------
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^\+?[0-9 ()\-]{7,18}$")
NAME_RE = re.compile(r"^[^\W\d_][\w .'\-]{1,79}$", re.UNICODE)


def clean(s, maxlen=255):
    s = "" if s is None else str(s)
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", s).strip()
    return s[:maxlen]


def valid_email(e):
    return bool(EMAIL_RE.match(e)) and len(e) <= 120


def valid_phone(p):
    return p == "" or bool(PHONE_RE.match(p))


def valid_name(n):
    return bool(NAME_RE.match(n))


def to_money(v):
    """Parse an optional money field -> float|None; raises ValueError."""
    v = clean(v, 20).replace(",", ".").replace("R", "").replace(" ", "")
    if v == "":
        return None
    f = float(v)
    if not (0 <= f <= 1_000_000):
        raise ValueError
    return round(f, 2)


def safe_next(target):
    """Only allow same-site relative redirects (prevents open redirects)."""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return None


# ---------- CSRF ----------
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def csrf_ok():
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    return bool(sent) and hmac.compare_digest(sent, session.get("csrf", ""))


# ---------- signed e-mail links ----------
def _ser():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])


def make_token(salt, data):
    return _ser().dumps(data, salt=salt)


def read_token(salt, token, max_age):
    try:
        return _ser().loads(token, salt=salt, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None


# ---------- one-time codes (login on new device, e-mail/password change) ----------
def _h(code):
    return hmac.new(current_app.config["SECRET_KEY"].encode(), code.encode(), hashlib.sha256).hexdigest()


def create_otp(user_id, purpose, payload=""):
    code = f"{secrets.randbelow(1_000_000):06d}"
    x("UPDATE otps SET used=1 WHERE user_id=? AND purpose=?", (user_id, purpose))
    x("INSERT INTO otps(user_id,purpose,code_hash,payload,expires_at) VALUES(?,?,?,?,?)",
      (user_id, purpose, _h(code), payload, int(time.time()) + 600))
    return code


def check_otp(user_id, purpose, code):
    """-> (ok, payload, message). Max 5 attempts, 10-minute expiry, single use."""
    row = q("SELECT * FROM otps WHERE user_id=? AND purpose=? AND used=0 ORDER BY id DESC LIMIT 1",
            (user_id, purpose), one=True)
    if not row or row["expires_at"] < time.time():
        return False, None, "That code has expired. Please request a new one."
    if row["attempts"] >= 5:
        return False, None, "Too many attempts. Please request a new code."
    x("UPDATE otps SET attempts=attempts+1 WHERE id=?", (row["id"],))
    if not hmac.compare_digest(row["code_hash"], _h(clean(code, 6))):
        return False, None, "Incorrect code. Check the e-mail and try again."
    x("UPDATE otps SET used=1 WHERE id=?", (row["id"],))
    return True, row["payload"], ""


def last_otp_payload(user_id, purpose):
    r = q("SELECT payload FROM otps WHERE user_id=? AND purpose=? ORDER BY id DESC LIMIT 1",
          (user_id, purpose), one=True)
    return r["payload"] if r else ""


# ---------- throttling ----------
_hits = {}


def throttle(key, limit, window):
    """In-memory sliding window. True = allowed."""
    if not current_app.config.get("THROTTLE", True):
        return True
    now = time.time()
    lst = [t for t in _hits.get(key, []) if now - t < window]
    if len(lst) >= limit:
        _hits[key] = lst
        return False
    lst.append(now)
    _hits[key] = lst
    return True


def locked_out(email, ip):
    a = q("SELECT COUNT(*) c FROM login_attempts WHERE email=? AND success=0 AND created_at>datetime('now','-15 minutes')",
          (email,), one=True)["c"]
    b = q("SELECT COUNT(*) c FROM login_attempts WHERE ip=? AND success=0 AND created_at>datetime('now','-15 minutes')",
          (ip,), one=True)["c"]
    return a >= 5 or b >= 20


def audit(user_id, action, detail=""):
    x("INSERT INTO audit_log(user_id,action,detail,ip) VALUES(?,?,?,?)",
      (user_id, action, clean(detail, 300), request.remote_addr if request else None))
