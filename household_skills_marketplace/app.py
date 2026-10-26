"""Household Skills Marketplace - Flask application (routes)."""
import os, json, hashlib, threading, time, secrets
from datetime import date, datetime
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for, flash, session, g, abort,
                   send_file, Response)
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config, CATEGORIES
import db, security as sec, mailer, backup, reports
from db import q, x

PAGE = 9
DUMMY_HASH = generate_password_hash("not-a-real-password")


def create_app(overrides=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if overrides:
        app.config.update(overrides)
    db.init_db(app.config["DATABASE"])
    app.teardown_appcontext(db.close_db)
    bootstrap_admin(app)

    @app.route("/test-email")
    def test_email():
        from mail import send_email

        result = send_email(
            "yourgmail@gmail.com",
            "SMTP Test",
            "If you receive this email, SMTP is working."
        )

        return f"Result: {result}"

    # ------------------------------------------------------------ helpers
    def abs_url(endpoint, **kw):
        return app.config["BASE_URL"] + url_for(endpoint, **kw)

    def dev_echo(label, value):
        if app.config["DEV_ECHO"]:
            flash(f"Development mode (no SMTP set): {label} - {value}", "dev")

    def notify(user_row_or_email, subject, body, user_id=None):
        to = user_row_or_email["email"] if hasattr(user_row_or_email, "keys") else user_row_or_email
        uid = user_row_or_email["id"] if hasattr(user_row_or_email, "keys") else user_id
        return mailer.send_email(to, subject, body, uid)

    def login_required(f):
        @wraps(f)
        def w(*a, **k):
            if not g.user:
                flash("Please log in to continue.", "info")
                return redirect(url_for("login", next=request.full_path.rstrip("?")))
            return f(*a, **k)
        return w

    def role_required(*roles):
        def deco(f):
            @wraps(f)
            @login_required
            def w(*a, **k):
                if g.user["role"] not in roles:
                    abort(403)
                return f(*a, **k)
            return w
        return deco

    def paginate(sql, args, page):
        total = q(f"SELECT COUNT(*) c FROM ({sql})", args, one=True)["c"]
        pages = max(1, -(-total // PAGE))
        page = min(max(page, 1), pages)
        rows = q(f"{sql} LIMIT {PAGE} OFFSET {(page - 1) * PAGE}", args)
        return rows, {"page": page, "pages": pages, "total": total}

    def pnum():
        try:
            return int(request.args.get("page", 1))
        except ValueError:
            return 1

    def finish_login(user):
        session.clear()
        session["uid"] = user["id"]
        session.permanent = True
        sec.csrf_token()
        x("UPDATE users SET last_login=CURRENT_TIMESTAMP, ua_hash=? WHERE id=?", (ua_hash(), user["id"]))
        sec.audit(user["id"], "login")
        flash(f"Welcome back, {user['full_name'].split()[0]}!", "ok")

    def ua_hash():
        return hashlib.sha256((request.headers.get("User-Agent", "") + "|device").encode()).hexdigest()[:16]

    def start_otp(user, purpose, payload="", send_to=None, why=""):
        code = sec.create_otp(user["id"], purpose, payload)
        notify(send_to or user["email"], "Your verification code",
               f"Hello {user['full_name']},\n\nYour verification code is: {code}\n\n{why}\n"
               "It expires in 10 minutes. If you did not request this, change your password immediately.",
               user["id"])
        session["otp_user"], session["otp_purpose"] = user["id"], purpose
        dev_echo("verification code", code)
        return redirect(url_for("verify_code"))

    # ------------------------------------------------------------ request hooks
    @app.before_request
    def load_user():
        g.user = None
        uid = session.get("uid")
        if uid:
            u = q("SELECT * FROM users WHERE id=? AND is_active=1", (uid,), one=True)
            if u:
                g.user = u
            else:
                session.clear()
        if request.method == "POST" and not sec.csrf_ok():
            abort(400, "Your form expired or was invalid. Please go back, refresh the page and try again.")

    @app.after_request
    def headers(resp):
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; style-src 'self'; "
                                                   "script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if g.get("user"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.context_processor
    def inject():
        unread = 0
        if g.get("user"):
            unread = q("SELECT COUNT(*) c FROM messages WHERE recipient_id=? AND read_at IS NULL", (g.user["id"],), one=True)["c"]
        return dict(csrf_token=sec.csrf_token, me=g.get("user"), categories=CATEGORIES, unread=unread,
                    pw_rules=sec.rules_json(), pw_labels=sec.RULES, today=date.today().isoformat())

    @app.template_filter("money")
    def money(v):
        return "-" if v is None else f"R {v:,.2f}"

    @app.template_filter("day")
    def day(v):
        return str(v or "")[:10]

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(413)
    @app.errorhandler(429)
    def err(e):
        msgs = {400: "Something about that request was not valid.", 403: "You do not have access to this page.",
                404: "We could not find that page.", 413: "That request was too large.", 429: "Too many requests. Please wait a bit."}
        return render_template("error.html", code=e.code, message=getattr(e, "description", None) if e.code == 400 else msgs.get(e.code)), e.code

    # ------------------------------------------------------------ public pages
    @app.route("/")
    def index():
        counts = {r["category"]: r["n"] for r in q(
            "SELECT category, COUNT(*) n FROM profiles p JOIN users u ON u.id=p.user_id "
            "WHERE p.status='approved' AND u.is_active=1 AND u.is_verified=1 GROUP BY category")}
        jobs = q("SELECT * FROM jobs WHERE status='open' ORDER BY id DESC LIMIT 3")
        return render_template("index.html", counts=counts, jobs=jobs)

    @app.route("/terms")
    def terms():
        return render_template("terms.html")

    @app.route("/contact", methods=["GET", "POST"])
    def contact():
        if request.method == "POST":
            f = request.form
            if f.get("website"):                        # honeypot
                abort(400)
            name, em, msg = sec.clean(f.get("name"), 80), sec.clean(f.get("email"), 120).lower(), sec.clean(f.get("message"), 2000)
            errs = []
            if not sec.valid_name(name): errs.append("Please enter your name.")
            if not sec.valid_email(em): errs.append("Please enter a valid e-mail address.")
            if len(msg) < 10: errs.append("Your message should be at least 10 characters.")
            if not sec.throttle(f"contact:{request.remote_addr}", 5, 3600): errs.append("You have sent several messages recently. Please try again later.")
            if errs:
                for e in errs: flash(e, "error")
                return render_template("contact.html", form=f), 400
            x("INSERT INTO emails(direction,to_addr,from_addr,subject,body,status) VALUES('in',?,?,?,?,'received')",
              (app.config["ADMIN_EMAIL"], f"{name} <{em}>", "Contact form message", msg))
            notify(app.config["ADMIN_EMAIL"], f"Contact form: {name}", f"From: {name} <{em}>\n\n{msg}")
            notify(em, "We received your message", f"Hi {name},\n\nThanks for contacting Household Skills Marketplace. We will reply soon.\n")
            flash("Thank you - your message was sent. We will reply by e-mail.", "ok")
            return redirect(url_for("contact"))
        return render_template("contact.html", form={})

    # ------------------------------------------------------------ registration / verification
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if g.user:
            return redirect(url_for("dashboard"))
        role = request.values.get("role", "provider")
        role = role if role in ("client", "provider") else "provider"
        if request.method == "POST":
            f = request.form
            if f.get("website"):
                abort(400)
            name, em = sec.clean(f.get("full_name"), 80), sec.clean(f.get("email"), 120).lower()
            phone, pw, pw2 = sec.clean(f.get("phone"), 20), f.get("password", ""), f.get("confirm", "")
            errs = []
            if not sec.valid_name(name): errs.append("Enter your full name (letters, spaces, - ' . only).")
            if not sec.valid_email(em): errs.append("Enter a valid e-mail address.")
            if not sec.valid_phone(phone): errs.append("Enter a valid phone number (digits, spaces, +, -, brackets).")
            bad = sec.password_errors(pw, em, name)
            if bad: errs.append("Your password is missing: " + "; ".join(bad) + ".")
            if pw != pw2: errs.append("The two passwords do not match.")
            if not f.get("terms"): errs.append("Please accept the terms to continue.")
            if not sec.throttle(f"reg:{request.remote_addr}", 10, 3600): errs.append("Too many sign-ups from this network. Try later.")
            if errs:
                for e in errs: flash(e, "error")
                return render_template("register.html", role=role, form=f), 400
            existing = q("SELECT * FROM users WHERE email=?", (em,), one=True)
            if existing:     # do not reveal that the address is registered
                notify(existing, "Sign-up attempt on your account",
                       f"Someone tried to register with this e-mail address. If it was you, log in or reset your password:\n{abs_url('forgot')}")
            else:
                uid = x("INSERT INTO users(email,password_hash,full_name,phone,role) VALUES(?,?,?,?,?)",
                        (em, generate_password_hash(pw), name, phone, role))
                link = abs_url("verify_email", token=sec.make_token("verify", uid))
                notify(em, "Confirm your e-mail address",
                       f"Hi {name},\n\nWelcome! Please confirm your e-mail address to activate your account:\n{link}\n\nThe link is valid for 48 hours.", uid)
                sec.audit(uid, "register", role)
                dev_echo("verification link", link)
            flash("Almost there! We sent a confirmation link to your e-mail. Open it to activate your account.", "ok")
            return redirect(url_for("login"))
        return render_template("register.html", role=role, form={})

    @app.route("/verify/<token>")
    def verify_email(token):
        uid = sec.read_token("verify", token, 48 * 3600)
        u = q("SELECT * FROM users WHERE id=?", (uid,), one=True) if uid else None
        if not u:
            flash("That confirmation link is invalid or has expired. Request a new one below.", "error")
            return redirect(url_for("resend_verification"))
        x("UPDATE users SET is_verified=1 WHERE id=?", (u["id"],))
        sec.audit(u["id"], "verified_email")
        flash("E-mail confirmed. You can log in now.", "ok")
        return redirect(url_for("login"))

    @app.route("/resend-verification", methods=["GET", "POST"])
    def resend_verification():
        if request.method == "POST":
            em = sec.clean(request.form.get("email"), 120).lower()
            if sec.throttle(f"resend:{request.remote_addr}", 5, 3600):
                u = q("SELECT * FROM users WHERE email=? AND is_verified=0", (em,), one=True)
                if u:
                    link = abs_url("verify_email", token=sec.make_token("verify", u["id"]))
                    notify(u, "Confirm your e-mail address", f"Confirm your account here:\n{link}")
                    dev_echo("verification link", link)
            flash("If that address needs confirming, a new link is on its way.", "info")
            return redirect(url_for("login"))
        return render_template("simple_email_form.html", title="Resend confirmation link", action=url_for("resend_verification"), button="Send link")

    # ------------------------------------------------------------ login / logout / reset
    @app.route("/login", methods=["GET", "POST"])
    def login():
        nxt = sec.safe_next(request.values.get("next"))
        if g.user:
            return redirect(nxt or url_for("dashboard"))
        if request.method == "POST":
            em, pw, ip = sec.clean(request.form.get("email"), 120).lower(), request.form.get("password", ""), request.remote_addr
            if sec.locked_out(em, ip):
                flash("Too many failed attempts. Please wait 15 minutes or reset your password.", "error")
                return render_template("login.html", next=nxt), 429
            u = q("SELECT * FROM users WHERE email=?", (em,), one=True)
            good = check_password_hash(u["password_hash"] if u else DUMMY_HASH, pw) and u is not None
            if not good or not u["is_active"]:
                x("INSERT INTO login_attempts(email,ip,success) VALUES(?,?,0)", (em, ip))
                flash("Incorrect e-mail or password.", "error")
                return render_template("login.html", next=nxt), 401
            if not u["is_verified"]:
                flash("Please confirm your e-mail address first. Did not get the e-mail? Use 'Resend confirmation link'.", "error")
                return render_template("login.html", next=nxt), 403
            x("DELETE FROM login_attempts WHERE email=?", (em,))
            if u["ua_hash"] and u["ua_hash"] != ua_hash():      # new browser/device -> verify by e-mail code
                session["after_login"] = nxt
                return start_otp(u, "login", why="We noticed a login from a new browser or device.")
            finish_login(u)
            return redirect(nxt or url_for("dashboard"))
        return render_template("login.html", next=nxt)

    @app.post("/logout")
    def logout():
        session.clear()
        flash("You have been logged out.", "info")
        return redirect(url_for("index"))

    @app.route("/verify-code", methods=["GET", "POST"])
    def verify_code():
        uid, purpose = session.get("otp_user"), session.get("otp_purpose")
        if not uid or not purpose:
            return redirect(url_for("login"))
        u = q("SELECT * FROM users WHERE id=?", (uid,), one=True)
        if purpose != "login" and (not g.user or g.user["id"] != uid):
            return redirect(url_for("login"))
        if request.method == "POST":
            if not sec.throttle(f"otp:{request.remote_addr}", 15, 600):
                abort(429)
            ok, payload, msg = sec.check_otp(uid, purpose, request.form.get("code", ""))
            if not ok:
                flash(msg, "error")
                return render_template("verify_code.html", purpose=purpose), 400
            nxt = session.get("after_login")
            for k in ("otp_user", "otp_purpose"):
                session.pop(k, None)
            if purpose == "login":
                finish_login(u)
                return redirect(sec.safe_next(nxt) or url_for("dashboard"))
            data = json.loads(payload)
            if purpose == "email_change":
                if q("SELECT 1 FROM users WHERE email=? AND id!=?", (data["email"], uid), one=True):
                    flash("That e-mail address is already in use.", "error")
                    return redirect(url_for("account"))
                old = u["email"]
                x("UPDATE users SET email=? WHERE id=?", (data["email"], uid))
                notify(old, "Your e-mail address was changed", f"The e-mail on your account was changed to {data['email']}. If this was not you, contact us immediately.")
                flash("E-mail address updated.", "ok")
            elif purpose == "password_change":
                x("UPDATE users SET password_hash=? WHERE id=?", (data["hash"], uid))
                notify(u, "Your password was changed", "Your password was just changed. If this was not you, reset it immediately.")
                flash("Password updated.", "ok")
            sec.audit(uid, purpose)
            return redirect(url_for("account"))
        return render_template("verify_code.html", purpose=purpose)

    @app.post("/verify-code/resend")
    def resend_code():
        uid, purpose = session.get("otp_user"), session.get("otp_purpose")
        u = q("SELECT * FROM users WHERE id=?", (uid,), one=True) if uid else None
        if not u:
            return redirect(url_for("login"))
        if not sec.throttle(f"otpresend:{uid}", 3, 600):
            flash("Please wait a few minutes before requesting another code.", "error")
            return redirect(url_for("verify_code"))
        payload = sec.last_otp_payload(uid, purpose)
        target = json.loads(payload)["email"] if purpose == "email_change" and payload else u["email"]
        return start_otp(u, purpose, payload, send_to=target)

    @app.route("/forgot", methods=["GET", "POST"])
    def forgot():
        if request.method == "POST":
            em = sec.clean(request.form.get("email"), 120).lower()
            if sec.throttle(f"forgot:{request.remote_addr}", 5, 3600):
                u = q("SELECT * FROM users WHERE email=? AND is_active=1", (em,), one=True)
                if u:
                    tok = sec.make_token("reset", [u["id"], u["password_hash"][-12:]])
                    link = abs_url("reset", token=tok)
                    notify(u, "Reset your password", f"Use this link within 1 hour to choose a new password:\n{link}\n\nIf you did not ask for this, ignore this e-mail.")
                    dev_echo("reset link", link)
            flash("If that e-mail is registered, a reset link has been sent.", "info")
            return redirect(url_for("login"))
        return render_template("simple_email_form.html", title="Forgot your password?", action=url_for("forgot"), button="Send reset link")

    @app.route("/reset/<token>", methods=["GET", "POST"])
    def reset(token):
        data = sec.read_token("reset", token, 3600)
        u = q("SELECT * FROM users WHERE id=?", (data[0],), one=True) if data else None
        if not u or u["password_hash"][-12:] != data[1]:            # single use: hash changes after reset
            flash("This reset link is invalid, already used, or has expired.", "error")
            return redirect(url_for("forgot"))
        if request.method == "POST":
            pw, pw2 = request.form.get("password", ""), request.form.get("confirm", "")
            bad = sec.password_errors(pw, u["email"], u["full_name"])
            if bad or pw != pw2:
                flash("Your password is missing: " + "; ".join(bad) + "." if bad else "The two passwords do not match.", "error")
                return render_template("reset.html", token=token, email=u["email"], name=u["full_name"]), 400
            x("UPDATE users SET password_hash=?, is_verified=1, ua_hash=NULL WHERE id=?", (generate_password_hash(pw), u["id"]))
            x("DELETE FROM login_attempts WHERE email=?", (u["email"],))
            notify(u, "Your password was reset", "Your password was reset. If this was not you, contact us immediately.")
            sec.audit(u["id"], "password_reset")
            flash("Password updated. Please log in.", "ok")
            return redirect(url_for("login"))
        return render_template("reset.html", token=token, email=u["email"], name=u["full_name"])

    # ------------------------------------------------------------ account (changes require verification)
    @app.route("/account")
    @login_required
    def account():
        return render_template("account.html")

    @app.post("/account/details")
    @login_required
    def account_details():
        name, phone = sec.clean(request.form.get("full_name"), 80), sec.clean(request.form.get("phone"), 20)
        if not sec.valid_name(name) or not sec.valid_phone(phone):
            flash("Please enter a valid name and phone number.", "error")
            return redirect(url_for("account"))
        x("UPDATE users SET full_name=?, phone=? WHERE id=?", (name, phone, g.user["id"]))
        flash("Details saved.", "ok")
        return redirect(url_for("account"))

    @app.post("/account/email")
    @login_required
    def account_email():
        new = sec.clean(request.form.get("email"), 120).lower()
        if not check_password_hash(g.user["password_hash"], request.form.get("current", "")):
            flash("Your current password was incorrect.", "error")
        elif not sec.valid_email(new) or new == g.user["email"].lower():
            flash("Enter a different, valid e-mail address.", "error")
        elif q("SELECT 1 FROM users WHERE email=?", (new,), one=True):
            flash("That e-mail address cannot be used.", "error")
        else:
            return start_otp(g.user, "email_change", json.dumps({"email": new}), send_to=new,
                             why="Enter this code to confirm your new e-mail address.")
        return redirect(url_for("account"))

    @app.post("/account/password")
    @login_required
    def account_password():
        pw, pw2 = request.form.get("password", ""), request.form.get("confirm", "")
        bad = sec.password_errors(pw, g.user["email"], g.user["full_name"])
        if not check_password_hash(g.user["password_hash"], request.form.get("current", "")):
            flash("Your current password was incorrect.", "error")
        elif bad:
            flash("Your new password is missing: " + "; ".join(bad) + ".", "error")
        elif pw != pw2:
            flash("The two new passwords do not match.", "error")
        else:
            return start_otp(g.user, "password_change", json.dumps({"hash": generate_password_hash(pw)}),
                             why="Enter this code to confirm your password change.")
        return redirect(url_for("account"))

    # ------------------------------------------------------------ dashboard
    @app.route("/dashboard")
    @login_required
    def dashboard():
        u = g.user
        if u["role"] == "admin":
            return redirect(url_for("admin_home"))
        d = {"bookings": q("SELECT COUNT(*) c FROM bookings WHERE %s=? AND status IN ('requested','accepted')" % ("client_id" if u["role"] == "client" else "provider_id"), (u["id"],), one=True)["c"]}
        prof = q("SELECT * FROM profiles WHERE user_id=?", (u["id"],), one=True)
        d["profile"] = prof
        if u["role"] == "provider":
            d["matching_jobs"] = q("SELECT * FROM jobs WHERE status='open' AND category=? ORDER BY id DESC LIMIT 4", (prof["category"],)) if prof else []
            d["applications"] = q("SELECT COUNT(*) c FROM applications WHERE provider_id=?", (u["id"],), one=True)["c"]
        else:
            d["jobs"] = q("SELECT j.*, (SELECT COUNT(*) FROM applications a WHERE a.job_id=j.id) apps FROM jobs j WHERE client_id=? ORDER BY id DESC LIMIT 4", (u["id"],))
        return render_template("dashboard.html", d=d)

    # ------------------------------------------------------------ provider profile + search
    @app.route("/profile", methods=["GET", "POST"])
    @role_required("provider")
    def profile_edit():
        prof = q("SELECT * FROM profiles WHERE user_id=?", (g.user["id"],), one=True)
        if request.method == "POST":
            f = request.form
            cat, head, bio = f.get("category", ""), sec.clean(f.get("headline"), 100), sec.clean(f.get("bio"), 1500)
            loc, avail = sec.clean(f.get("location"), 80), sec.clean(f.get("availability"), 100)
            errs = []
            if cat not in CATEGORIES: errs.append("Choose a skill category.")
            if len(head) < 10: errs.append("Headline should be at least 10 characters.")
            if len(bio) < 30: errs.append("Tell clients a little more about you (at least 30 characters).")
            if len(loc) < 2: errs.append("Enter your suburb or town.")
            try:
                rate = sec.to_money(f.get("hourly_rate"))
            except ValueError:
                rate = None; errs.append("Hourly rate must be a number between 0 and 1,000,000.")
            if errs:
                for e in errs: flash(e, "error")
                return render_template("profile_form.html", p=f), 400
            if prof:
                x("UPDATE profiles SET category=?,headline=?,bio=?,location=?,hourly_rate=?,availability=?,updated_at=CURRENT_TIMESTAMP WHERE user_id=?",
                  (cat, head, bio, loc, rate, avail, g.user["id"]))
                flash("Profile saved.", "ok")
            else:
                x("INSERT INTO profiles(user_id,category,headline,bio,location,hourly_rate,availability) VALUES(?,?,?,?,?,?,?)",
                  (g.user["id"], cat, head, bio, loc, rate, avail))
                notify(app.config["ADMIN_EMAIL"], "New provider profile awaiting review", f"{g.user['full_name']} created a {cat} profile.\n{abs_url('admin_moderation')}")
                flash("Profile created! An administrator will review it shortly, then it appears in search.", "ok")
            return redirect(url_for("dashboard"))
        return render_template("profile_form.html", p=dict(prof) if prof else {})

    @app.route("/providers")
    def providers():
        cat, loc, term = request.args.get("category", ""), sec.clean(request.args.get("location"), 60), sec.clean(request.args.get("q"), 60)
        sql = ("SELECT u.id, u.full_name, p.* FROM profiles p JOIN users u ON u.id=p.user_id "
               "WHERE p.status='approved' AND u.is_active=1 AND u.is_verified=1")
        args = []
        esc = lambda s: s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        if cat in CATEGORIES:
            sql += " AND p.category=?"; args.append(cat)
        if loc:
            sql += " AND p.location LIKE ? ESCAPE '\\'"; args.append(f"%{esc(loc)}%")
        if term:
            sql += " AND (p.headline LIKE ? ESCAPE '\\' OR p.bio LIKE ? ESCAPE '\\' OR u.full_name LIKE ? ESCAPE '\\')"; args += [f"%{esc(term)}%"] * 3
        rows, pg = paginate(sql + " ORDER BY p.updated_at DESC", args, pnum())
        return render_template("providers.html", rows=rows, pg=pg, cat=cat, loc=loc, term=term)

    @app.route("/providers/<int:uid>")
    def provider_detail(uid):
        p = q("SELECT u.id, u.full_name, u.phone, p.* FROM profiles p JOIN users u ON u.id=p.user_id WHERE u.id=? AND u.is_active=1 AND u.is_verified=1", (uid,), one=True)
        if not p or (p["status"] != "approved" and not (g.user and (g.user["id"] == uid or g.user["role"] == "admin"))):
            abort(404)
        return render_template("provider_detail.html", p=p)

    # ------------------------------------------------------------ messaging
    def can_message(me, other):
        if not other or other["id"] == me["id"] or not other["is_active"] or "admin" in (me["role"], other["role"]) or me["role"] == other["role"]:
            return False
        if q("SELECT 1 FROM messages WHERE (sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?) LIMIT 1", (me["id"], other["id"], other["id"], me["id"]), one=True):
            return True
        if other["role"] == "provider":
            return bool(q("SELECT 1 FROM profiles WHERE user_id=? AND status='approved'", (other["id"],), one=True))
        return bool(q("SELECT 1 FROM bookings WHERE client_id=? AND provider_id=? UNION SELECT 1 FROM jobs j JOIN applications a ON a.job_id=j.id WHERE j.client_id=? AND a.provider_id=?", (other["id"], me["id"], other["id"], me["id"]), one=True))

    @app.route("/messages")
    @login_required
    def inbox():
        rows = q("""SELECT u.id, u.full_name, u.role, m.body, m.created_at,
                    (SELECT COUNT(*) FROM messages WHERE sender_id=u.id AND recipient_id=:me AND read_at IS NULL) unread
                    FROM users u JOIN messages m ON m.id=(SELECT MAX(id) FROM messages
                      WHERE (sender_id=:me AND recipient_id=u.id) OR (sender_id=u.id AND recipient_id=:me))
                    WHERE u.id!=:me ORDER BY m.id DESC""", {"me": g.user["id"]})
        return render_template("inbox.html", rows=rows)

    @app.route("/messages/<int:uid>", methods=["GET", "POST"])
    @login_required
    def thread(uid):
        other = q("SELECT id, full_name, role, is_active FROM users WHERE id=?", (uid,), one=True)
        if not other or not can_message(g.user, other):
            abort(404 if not other else 403)
        if request.method == "POST":
            body = sec.clean(request.form.get("body"), 2000)
            if not body:
                flash("Type a message first.", "error")
            elif not sec.throttle(f"msg:{g.user['id']}", 30, 600):
                flash("You are sending messages very quickly. Please slow down.", "error")
            else:
                first_unread = not q("SELECT 1 FROM messages WHERE sender_id=? AND recipient_id=? AND read_at IS NULL", (g.user["id"], uid), one=True)
                x("INSERT INTO messages(sender_id,recipient_id,body) VALUES(?,?,?)", (g.user["id"], uid, body))
                if first_unread:
                    full = q("SELECT * FROM users WHERE id=?", (uid,), one=True)
                    notify(full, f"New message from {g.user['full_name']}", f"{g.user['full_name']} sent you a message on Household Skills Marketplace.\nRead and reply: {abs_url('thread', uid=g.user['id'])}")
                flash("Message sent.", "ok")
            return redirect(url_for("thread", uid=uid) + "#end")
        x("UPDATE messages SET read_at=CURRENT_TIMESTAMP WHERE sender_id=? AND recipient_id=? AND read_at IS NULL", (uid, g.user["id"]))
        msgs = q("SELECT * FROM messages WHERE (sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?) ORDER BY id", (g.user["id"], uid, uid, g.user["id"]))
        return render_template("thread.html", other=other, msgs=msgs)

    # ------------------------------------------------------------ bookings + receipts
    BK = ("SELECT b.*, c.full_name client_name, c.email client_email, p.full_name provider_name, p.email provider_email, pr.category "
          "FROM bookings b JOIN users c ON c.id=b.client_id JOIN users p ON p.id=b.provider_id LEFT JOIN profiles pr ON pr.user_id=b.provider_id ")

    @app.post("/providers/<int:uid>/book")
    @role_required("client")
    def book(uid):
        p = q("SELECT u.*, pr.status FROM users u JOIN profiles pr ON pr.user_id=u.id WHERE u.id=? AND pr.status='approved' AND u.is_active=1", (uid,), one=True)
        if not p: abort(404)
        when, desc = sec.clean(request.form.get("service_date"), 10), sec.clean(request.form.get("description"), 1000)
        errs = []
        try:
            if datetime.strptime(when, "%Y-%m-%d").date() < date.today(): errs.append("Choose today or a future date.")
        except ValueError:
            errs.append("Choose a valid date.")
        if len(desc) < 10: errs.append("Describe the work in at least 10 characters.")
        try:
            quote = sec.to_money(request.form.get("quoted_amount"))
        except ValueError:
            quote = None; errs.append("Budget must be a valid amount.")
        if errs:
            for e in errs: flash(e, "error")
            return redirect(url_for("provider_detail", uid=uid) + "#book")
        bid = x("INSERT INTO bookings(client_id,provider_id,service_date,description,quoted_amount) VALUES(?,?,?,?,?)", (g.user["id"], uid, when, desc, quote))
        notify(p, "New booking request", f"{g.user['full_name']} would like to book you on {when}.\n\n{desc}\n\nRespond here: {abs_url('bookings')}")
        flash("Booking request sent. You will be e-mailed when the provider responds.", "ok")
        return redirect(url_for("bookings"))

    @app.route("/bookings")
    @login_required
    def bookings():
        if g.user["role"] == "admin":
            rows = q(BK + "ORDER BY b.id DESC LIMIT 200")
        else:
            col = "client_id" if g.user["role"] == "client" else "provider_id"
            rows = q(BK + f"WHERE b.{col}=? ORDER BY b.id DESC", (g.user["id"],))
        return render_template("bookings.html", rows=rows)

    @app.post("/bookings/<int:bid>/<action>")
    @login_required
    def booking_action(bid, action):
        b = q(BK + "WHERE b.id=?", (bid,), one=True)
        if not b or g.user["id"] not in (b["client_id"], b["provider_id"]): abort(404)
        is_prov, st = g.user["id"] == b["provider_id"], b["status"]
        if action in ("accept", "decline") and is_prov and st == "requested":
            new = "accepted" if action == "accept" else "declined"
            x("UPDATE bookings SET status=? WHERE id=?", (new, bid))
            notify(b["client_email"], f"Your booking was {new}", f"{b['provider_name']} {new} your booking for {b['service_date']}.\n{abs_url('bookings')}")
        elif action == "cancel" and not is_prov and st in ("requested", "accepted"):
            x("UPDATE bookings SET status='cancelled' WHERE id=?", (bid,))
            notify(b["provider_email"], "A booking was cancelled", f"{b['client_name']} cancelled the booking for {b['service_date']}.")
        elif action == "complete" and is_prov and st == "accepted":
            try:
                final = sec.to_money(request.form.get("final_amount"))
            except ValueError:
                final = None
            if final is None:
                flash("Enter the final amount to complete the job and issue the receipt.", "error")
                return redirect(url_for("bookings"))
            rno = f"HSM-{date.today().year}-{bid:06d}"
            x("UPDATE bookings SET status='completed', final_amount=?, receipt_no=?, completed_at=CURRENT_TIMESTAMP WHERE id=?", (final, rno, bid))
            link = abs_url("receipt", bid=bid)
            for em in (b["client_email"], b["provider_email"]):
                notify(em, f"Receipt {rno}", f"Job completed. Receipt {rno} for R {final:,.2f}.\nView or download: {link}")
        else:
            flash("That action is not available for this booking.", "error")
            return redirect(url_for("bookings"))
        flash("Booking updated.", "ok")
        return redirect(url_for("bookings"))

    def receipt_row(bid):
        b = q(BK + "WHERE b.id=?", (bid,), one=True)
        if not b or b["status"] != "completed" or not g.user or g.user["id"] not in (b["client_id"], b["provider_id"]) and g.user["role"] != "admin":
            abort(404)
        return b

    @app.route("/receipts/<int:bid>")
    @login_required
    def receipt(bid):
        return render_template("receipt.html", b=receipt_row(bid))

    @app.route("/receipts/<int:bid>.pdf")
    @login_required
    def receipt_pdf(bid):
        b = receipt_row(bid)
        import io
        return send_file(io.BytesIO(reports.receipt_pdf(b)), mimetype="application/pdf", download_name=f"{b['receipt_no']}.pdf")

    # ------------------------------------------------------------ jobs (job posts + applications)
    @app.route("/jobs")
    def jobs():
        cat = request.args.get("category", "")
        sql, args = "SELECT j.*, u.full_name poster, (SELECT COUNT(*) FROM applications a WHERE a.job_id=j.id) apps FROM jobs j JOIN users u ON u.id=j.client_id WHERE j.status='open'", []
        if cat in CATEGORIES:
            sql += " AND j.category=?"; args.append(cat)
        rows, pg = paginate(sql + " ORDER BY j.id DESC", args, pnum())
        return render_template("jobs.html", rows=rows, pg=pg, cat=cat)

    @app.route("/jobs/new", methods=["GET", "POST"])
    @role_required("client")
    def job_new():
        if request.method == "POST":
            f = request.form
            title, cat, loc, desc = sec.clean(f.get("title"), 100), f.get("category", ""), sec.clean(f.get("location"), 80), sec.clean(f.get("description"), 2000)
            errs = []
            if len(title) < 5: errs.append("Give the job a title (at least 5 characters).")
            if cat not in CATEGORIES: errs.append("Choose a category.")
            if len(loc) < 2: errs.append("Enter the job location.")
            if len(desc) < 20: errs.append("Describe the job (at least 20 characters).")
            try:
                budget = sec.to_money(f.get("budget"))
            except ValueError:
                budget = None; errs.append("Budget must be a valid amount.")
            if errs:
                for e in errs: flash(e, "error")
                return render_template("job_form.html", f=f), 400
            jid = x("INSERT INTO jobs(client_id,title,category,location,description,budget) VALUES(?,?,?,?,?,?)", (g.user["id"], title, cat, loc, desc, budget))
            # e-mail matching job-seekers
            matches = q("SELECT u.* FROM users u JOIN profiles p ON p.user_id=u.id WHERE p.status='approved' AND p.category=? AND u.is_active=1 AND u.is_verified=1 LIMIT 50", (cat,))
            for m in matches:
                notify(m, f"New {cat} job: {title}", f"Hi {m['full_name']},\n\nA new job matches your skills.\n\n{title}\nLocation: {loc}\nBudget: {budget and f'R {budget:,.2f}' or 'not stated'}\n\nView and apply: {abs_url('job_detail', jid=jid)}")
            flash(f"Job posted. {len(matches)} matching provider(s) were e-mailed.", "ok")
            return redirect(url_for("job_detail", jid=jid))
        return render_template("job_form.html", f={})

    @app.route("/jobs/<int:jid>")
    def job_detail(jid):
        j = q("SELECT j.*, u.full_name poster FROM jobs j JOIN users u ON u.id=j.client_id WHERE j.id=?", (jid,), one=True)
        if not j: abort(404)
        apps, mine = [], None
        if g.user and (g.user["id"] == j["client_id"] or g.user["role"] == "admin"):
            apps = q("SELECT a.*, u.full_name, p.headline FROM applications a JOIN users u ON u.id=a.provider_id LEFT JOIN profiles p ON p.user_id=u.id WHERE a.job_id=? ORDER BY a.id", (jid,))
        if g.user and g.user["role"] == "provider":
            mine = q("SELECT * FROM applications WHERE job_id=? AND provider_id=?", (jid, g.user["id"]), one=True)
        return render_template("job_detail.html", j=j, apps=apps, mine=mine, share=abs_url("job_detail", jid=jid), apply_link=abs_url("job_apply", jid=jid))

    @app.route("/jobs/<int:jid>/apply", methods=["GET", "POST"])
    @role_required("provider")
    def job_apply(jid):
        j = q("SELECT j.*, u.email poster_email, u.full_name poster FROM jobs j JOIN users u ON u.id=j.client_id WHERE j.id=?", (jid,), one=True)
        if not j: abort(404)
        if j["status"] != "open":
            flash("This job is no longer open.", "info"); return redirect(url_for("job_detail", jid=jid))
        if q("SELECT 1 FROM applications WHERE job_id=? AND provider_id=?", (jid, g.user["id"]), one=True):
            flash("You have already applied for this job.", "info"); return redirect(url_for("job_detail", jid=jid))
        prof = q("SELECT * FROM profiles WHERE user_id=?", (g.user["id"],), one=True)
        if not prof or prof["status"] != "approved":
            flash("Your profile must be created and approved before you can apply.", "info"); return redirect(url_for("profile_edit"))
        if request.method == "POST":
            msg = sec.clean(request.form.get("message"), 1500)
            if len(msg) < 20:
                flash("Tell the client why you are a good fit (at least 20 characters).", "error")
                return render_template("apply.html", j=j, msg=msg), 400
            x("INSERT INTO applications(job_id,provider_id,message) VALUES(?,?,?)", (jid, g.user["id"], msg))
            notify(j["poster_email"], f"New application: {j['title']}", f"{g.user['full_name']} applied for your job.\n\n{msg}\n\nProfile: {abs_url('provider_detail', uid=g.user['id'])}\nManage: {abs_url('job_detail', jid=jid)}")
            notify(g.user, f"Application sent: {j['title']}", f"Your application for '{j['title']}' was sent to {j['poster']}. You will be e-mailed if you are shortlisted.")
            flash("Application sent. A confirmation e-mail is on its way.", "ok")
            return redirect(url_for("my_applications"))
        return render_template("apply.html", j=j, msg="")

    @app.route("/applications")
    @role_required("provider")
    def my_applications():
        rows = q("SELECT a.*, j.title, j.category, j.status job_status FROM applications a JOIN jobs j ON j.id=a.job_id WHERE a.provider_id=? ORDER BY a.id DESC", (g.user["id"],))
        return render_template("applications.html", rows=rows)

    @app.post("/jobs/<int:jid>/manage/<action>")
    @role_required("client", "admin")
    def job_manage(jid, action):
        j = q("SELECT * FROM jobs WHERE id=?", (jid,), one=True)
        if not j or (g.user["role"] != "admin" and j["client_id"] != g.user["id"]): abort(404)
        if action == "close":
            x("UPDATE jobs SET status='closed' WHERE id=?", (jid,)); flash("Job closed.", "ok")
        elif action == "reopen":
            x("UPDATE jobs SET status='open' WHERE id=?", (jid,)); flash("Job re-opened.", "ok")
        elif action in ("shortlist", "reject"):
            a = q("SELECT a.*, u.email, u.full_name, u.id uid FROM applications a JOIN users u ON u.id=a.provider_id WHERE a.id=? AND a.job_id=?", (request.form.get("app_id", type=int), jid), one=True)
            if not a: abort(404)
            st = "shortlisted" if action == "shortlist" else "rejected"
            x("UPDATE applications SET status=? WHERE id=?", (st, a["id"]))
            body = (f"Good news! You were shortlisted for '{j['title']}'. The client may contact you via the platform.\n{abs_url('inbox')}" if st == "shortlisted"
                    else f"Thank you for applying for '{j['title']}'. The client has decided not to proceed this time. Keep applying - more jobs are posted daily.")
            notify(a["email"], f"Application update: {j['title']}", body, a["uid"])
            flash(f"Applicant {st}; they were notified by e-mail.", "ok")
        else:
            abort(404)
        return redirect(url_for("job_detail", jid=jid))

    # ------------------------------------------------------------ admin
    admin_only = role_required("admin")

    @app.route("/admin")
    @admin_only
    def admin_home():
        a = reports.analytics()
        recent = q("SELECT l.*, u.email FROM audit_log l LEFT JOIN users u ON u.id=l.user_id ORDER BY l.id DESC LIMIT 8")
        return render_template("admin_home.html", a=a, recent=recent)

    @app.route("/admin/analytics.csv")
    @admin_only
    def analytics_csv():
        return Response(reports.analytics_csv(reports.analytics()), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=analytics.csv"})

    @app.route("/admin/analytics.pdf")
    @admin_only
    def analytics_pdf():
        import io
        return send_file(io.BytesIO(reports.analytics_pdf(reports.analytics())), mimetype="application/pdf", download_name="analytics-report.pdf")

    @app.route("/admin/users")
    @admin_only
    def admin_users():
        term = sec.clean(request.args.get("q"), 60)
        sql, args = "SELECT * FROM users", []
        if term:
            sql += " WHERE email LIKE ? ESCAPE '\\' OR full_name LIKE ? ESCAPE '\\'"
            e = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_"); args = [f"%{e}%"] * 2
        rows, pg = paginate(sql + " ORDER BY id DESC", args, pnum())
        return render_template("admin_users.html", rows=rows, pg=pg, term=term)

    @app.post("/admin/users/<int:uid>/<action>")
    @admin_only
    def admin_user_action(uid, action):
        u = q("SELECT * FROM users WHERE id=?", (uid,), one=True)
        if not u or u["id"] == g.user["id"]: abort(400, "You cannot change your own account here.")
        if action == "toggle":
            x("UPDATE users SET is_active=1-is_active WHERE id=?", (uid,))
        elif action == "verify":
            x("UPDATE users SET is_verified=1 WHERE id=?", (uid,))
        else:
            abort(404)
        sec.audit(g.user["id"], f"admin_{action}", f"user {uid}")
        flash("User updated.", "ok")
        return redirect(url_for("admin_users"))

    @app.route("/admin/moderation")
    @admin_only
    def admin_moderation():
        st = request.args.get("status", "pending")
        st = st if st in ("pending", "approved", "rejected", "suspended") else "pending"
        rows = q("SELECT u.id, u.full_name, u.email, p.* FROM profiles p JOIN users u ON u.id=p.user_id WHERE p.status=? ORDER BY p.updated_at DESC", (st,))
        return render_template("admin_moderation.html", rows=rows, st=st)

    @app.post("/admin/moderation/<int:uid>")
    @admin_only
    def admin_moderate(uid):
        action, note = request.form.get("action"), sec.clean(request.form.get("note"), 300)
        status = {"approve": "approved", "reject": "rejected", "suspend": "suspended"}.get(action)
        u = q("SELECT * FROM users WHERE id=?", (uid,), one=True)
        if not status or not u: abort(400)
        x("UPDATE profiles SET status=?, mod_note=? WHERE user_id=?", (status, note, uid))
        sec.audit(g.user["id"], f"profile_{status}", f"user {uid}")
        notify(u, f"Your profile was {status}", f"Your provider profile was {status}.\n{('Note: ' + note) if note else ''}\n{abs_url('dashboard')}")
        flash(f"Profile {status}; the provider was e-mailed.", "ok")
        return redirect(url_for("admin_moderation", status=request.form.get("back", "pending")))

    @app.route("/admin/emails", methods=["GET", "POST"])
    @admin_only
    def admin_emails():
        if request.method == "POST":
            op = request.form.get("op")
            if op == "fetch":
                n, e = mailer.fetch_inbound()
                flash(e or f"Inbox checked: {n} new message(s).", "error" if e else "ok")
            elif op == "send":
                aud, subj, body = request.form.get("audience", ""), sec.clean(request.form.get("subject"), 150), sec.clean(request.form.get("body"), 5000)
                if not subj or len(body) < 5:
                    flash("Enter a subject and a message.", "error")
                else:
                    if aud == "providers": rs = q("SELECT * FROM users WHERE role='provider' AND is_active=1 AND is_verified=1 LIMIT 500")
                    elif aud == "clients": rs = q("SELECT * FROM users WHERE role='client' AND is_active=1 AND is_verified=1 LIMIT 500")
                    elif aud.startswith("cat:") and aud[4:] in CATEGORIES:
                        rs = q("SELECT u.* FROM users u JOIN profiles p ON p.user_id=u.id WHERE p.category=? AND u.is_active=1 AND u.is_verified=1 LIMIT 500", (aud[4:],))
                    elif aud == "one":
                        em = sec.clean(request.form.get("to"), 120).lower()
                        rs = [{"email": em, "id": None}] if sec.valid_email(em) else []
                    else: rs = []
                    if not rs:
                        flash("No recipients matched.", "error")
                    else:
                        res = [notify(r["email"], subj, body, r["id"]) for r in rs]
                        flash(f"Sent to {len(rs)} recipient(s): {res.count('sent')} sent, {res.count('logged')} logged (dev mode), {res.count('failed')} failed.", "ok")
                        sec.audit(g.user["id"], "admin_email", f"{aud} x{len(rs)}")
            return redirect(url_for("admin_emails", tab=request.form.get("tab", "out")))
        tab = "in" if request.args.get("tab") == "in" else "out"
        rows, pg = paginate("SELECT * FROM emails WHERE direction=? ORDER BY id DESC", (tab,), pnum())
        return render_template("admin_emails.html", rows=rows, pg=pg, tab=tab, imap=bool(app.config["IMAP_HOST"]), smtp=bool(app.config["SMTP_HOST"]))

    @app.route("/admin/backups", methods=["GET", "POST"])
    @admin_only
    def admin_backups():
        c = app.config
        if request.method == "POST":
            op, name = request.form.get("op"), request.form.get("name", "")
            try:
                if op == "create":
                    flash(f"Backup created: {backup.create_backup(c['DATABASE'], c['BACKUP_DIR'], 'manual', c['BACKUP_KEEP'])}", "ok")
                elif op == "restore":
                    if request.form.get("confirm") != "RESTORE": raise ValueError("Type RESTORE to confirm.")
                    backup.restore_backup(c["DATABASE"], c["BACKUP_DIR"], name, c["BACKUP_KEEP"])
                    flash(f"Database restored from {name}. A safety backup of the previous state was kept.", "ok")
                elif op == "delete":
                    p = backup.backup_path(c["BACKUP_DIR"], name)
                    if not p: raise FileNotFoundError("Backup not found.")
                    p.unlink(); flash("Backup deleted.", "ok")
                sec.audit(g.user["id"], f"backup_{op}", name)
            except Exception as e:                                 # noqa: BLE001
                flash(str(e), "error")
            return redirect(url_for("admin_backups"))
        return render_template("admin_backups.html", backups=backup.list_backups(c["BACKUP_DIR"]), interval=c["BACKUP_INTERVAL_HOURS"], keep=c["BACKUP_KEEP"])

    @app.route("/admin/backups/download/<name>")
    @admin_only
    def backup_download(name):
        p = backup.backup_path(app.config["BACKUP_DIR"], name)
        if not p: abort(404)
        return send_file(p, as_attachment=True)

    start_scheduler(app)
    return app


def bootstrap_admin(app):
    """Create the first admin from ADMIN_EMAIL / ADMIN_PASSWORD (or a random password printed once)."""
    con = __import__("sqlite3").connect(app.config["DATABASE"])
    if not con.execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
        pw = app.config["ADMIN_PASSWORD"] or secrets.token_urlsafe(12) + "aA1!"
        con.execute("INSERT INTO users(email,password_hash,full_name,role,is_verified) VALUES(?,?,?,?,1)",
                    (app.config["ADMIN_EMAIL"], generate_password_hash(pw), "Site Administrator", "admin"))
        con.commit()
        if not app.config["ADMIN_PASSWORD"] and not app.config.get("TESTING"):
            print(f"\n*** First admin created: {app.config['ADMIN_EMAIL']}  password: {pw}\n*** Change it after logging in.\n")
    con.close()


def start_scheduler(app):
    h = app.config["BACKUP_INTERVAL_HOURS"]
    if h <= 0 or app.config.get("TESTING") or (os.environ.get("FLASK_DEBUG") == "1" and os.environ.get("WERKZEUG_RUN_MAIN") != "true"):
        return

    def loop():
        while True:
            time.sleep(h * 3600)
            try:
                backup.create_backup(app.config["DATABASE"], app.config["BACKUP_DIR"], "auto", app.config["BACKUP_KEEP"])
            except Exception as e:                                  # noqa: BLE001
                print("Scheduled backup failed:", e)
    threading.Thread(target=loop, daemon=True, name="backup-scheduler").start()


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=os.environ.get("FLASK_DEBUG") == "1")
