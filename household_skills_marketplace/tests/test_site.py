"""End-to-end tests + link checker.  Run:  python -m unittest tests.test_site -v"""
import os, re, sys, json, tempfile, unittest, zipfile
from html.parser import HTMLParser
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app import create_app
import db as dbm
from db import q

PW = "Sturdy!Pass2026"
CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')


class Links(HTMLParser):
    def __init__(self):
        super().__init__(); self.links, self.forms = set(), []
    def handle_starttag(self, tag, a):
        a = dict(a)
        if tag == "a" and a.get("href"): self.links.add(a["href"])
        if tag == "form": self.forms.append((a.get("action", ""), (a.get("method") or "get").upper()))
        if tag in ("link", "script") and (a.get("href") or a.get("src")): self.links.add(a.get("href") or a.get("src"))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app({"TESTING": True, "DATABASE": os.path.join(self.tmp.name, "t.db"), "BACKUP_DIR": os.path.join(self.tmp.name, "bk"),
                               "ADMIN_PASSWORD": PW, "THROTTLE": False, "DEV_ECHO": False, "BACKUP_INTERVAL_HOURS": 0})
        self.ctx = self.app.app_context(); self.ctx.push()

    def tearDown(self):
        self.ctx.pop(); self.tmp.cleanup()

    def client(self, ua="TestBrowser/1"):
        c = self.app.test_client(); c.environ_base["HTTP_USER_AGENT"] = ua
        return c

    def tok(self, c, path="/login"):
        return CSRF.search(c.get(path).get_data(as_text=True)).group(1)

    def post(self, c, path, data=None, page="/login", **kw):
        d = dict(data or {}); d["csrf_token"] = self.tok(c, page)
        return c.post(path, data=d, **kw)

    def make_user(self, role, email, name, verified=True):
        c = self.client()
        self.post(c, "/register", {"role": role, "full_name": name, "email": email, "password": PW, "confirm": PW, "terms": "on"}, "/register")
        if verified: dbm_exec("UPDATE users SET is_verified=1 WHERE email=?", email)

    def login(self, email, c=None):
        c = c or self.client()
        r = self.post(c, "/login", {"email": email, "password": PW})
        self.assertEqual(r.status_code, 302, r.get_data(as_text=True)[:300]); return c


def dbm_exec(sql, *a):
    dbm.x(sql, a)


class Flows(Base):
    def test_password_policy_server_side(self):
        c = self.client()
        for bad in ["short1!A", "alllowercase1!", "NoSpecial1234", "Has Space1!aaa", "Password123!", "Jane1234!!xx"]:
            r = self.post(c, "/register", {"role": "client", "full_name": "Jane Doe", "email": "jane@example.com", "password": bad, "confirm": bad, "terms": "on"}, "/register")
            self.assertEqual(r.status_code, 400, bad)
        self.assertIsNone(q("SELECT 1 FROM users WHERE email='jane@example.com'", one=True))

    def test_csrf_and_security_headers(self):
        c = self.client()
        self.assertEqual(c.post("/login", data={"email": "a@b.co", "password": "x"}).status_code, 400)
        h = c.get("/").headers
        self.assertIn("script-src 'self'", h["Content-Security-Policy"]); self.assertEqual(h["X-Frame-Options"], "DENY")

    def test_register_verify_login(self):
        c = self.client()
        r = self.post(c, "/register", {"role": "provider", "full_name": "Pat Provider", "email": "pat@example.com", "password": PW, "confirm": PW, "terms": "on"}, "/register")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.post(c, "/login", {"email": "pat@example.com", "password": PW}).status_code, 403)   # unverified
        mail = q("SELECT body FROM emails WHERE to_addr='pat@example.com' AND subject LIKE 'Confirm%'", one=True)["body"]
        link = re.search(r"http://127.0.0.1:5000(/verify/\S+)", mail).group(1)
        self.assertEqual(c.get(link).status_code, 302)
        self.login("pat@example.com", c)
        self.assertEqual(c.get("/verify/garbage").status_code, 302)       # bad link handled gracefully

    def test_lockout(self):
        self.make_user("client", "lock@example.com", "Lock Out")
        c = self.client()
        for _ in range(5): self.post(c, "/login", {"email": "lock@example.com", "password": "wrong"})
        r = self.post(c, "/login", {"email": "lock@example.com", "password": PW})
        self.assertEqual(r.status_code, 429)

    def test_new_device_requires_code_and_password_change_requires_code(self):
        self.make_user("client", "dev@example.com", "Dev Ice")
        c = self.login("dev@example.com")
        # change password -> needs OTP
        NEW = "Another!Pass2027"
        r = self.post(c, "/account/password", {"current": PW, "password": NEW, "confirm": NEW}, "/account")
        self.assertEqual(r.status_code, 302)
        self.assertTrue(check_pw("dev@example.com", PW))                   # unchanged until verified
        code = last_code("dev@example.com")
        self.assertEqual(self.post(c, "/verify-code", {"code": "000000"}, "/verify-code").status_code, 400)
        self.assertEqual(self.post(c, "/verify-code", {"code": code}, "/verify-code").status_code, 302)
        self.assertTrue(check_pw("dev@example.com", NEW))
        # login from a different browser -> code required
        other = self.client(ua="OtherBrowser/9")
        r = self.post(other, "/login", {"email": "dev@example.com", "password": NEW})
        self.assertIn("/verify-code", r.headers["Location"])
        self.assertEqual(other.get("/dashboard").status_code, 302)        # not logged in yet
        self.assertEqual(self.post(other, "/verify-code", {"code": last_code("dev@example.com")}, "/verify-code").status_code, 302)
        self.assertEqual(other.get("/dashboard").status_code, 200)

    def test_reset_link_single_use(self):
        self.make_user("client", "rst@example.com", "Reset Me")
        c = self.client(); self.post(c, "/forgot", {"email": "rst@example.com"}, "/forgot")
        link = re.search(r"http://127.0.0.1:5000(/reset/\S+)", q("SELECT body FROM emails WHERE subject='Reset your password'", one=True)["body"]).group(1)
        NEW = "Brand!New2028pw"
        self.assertEqual(c.get(link).status_code, 200)
        self.assertEqual(self.post(c, link, {"password": NEW, "confirm": NEW}, link).status_code, 302)
        self.assertEqual(c.get(link).status_code, 302)                    # already used

    def test_full_marketplace_flow_with_receipt_backup_reports(self):
        self.make_user("provider", "pro@example.com", "Priya Provider"); self.make_user("client", "cli@example.com", "Carl Client")
        pro = self.login("pro@example.com")
        prof = {"category": "Painting", "headline": "Careful interior painter", "bio": "Ten years painting homes across the city. Tidy and punctual.", "location": "Durban North", "hourly_rate": "150", "availability": "Weekdays"}
        self.assertEqual(self.post(pro, "/profile", prof, "/profile").status_code, 302)
        self.assertEqual(q("SELECT COUNT(*) c FROM emails WHERE subject LIKE 'New provider profile%'", one=True)["c"], 1)   # admin notified
        adm = self.login("admin@example.com")
        uid = q("SELECT id FROM users WHERE email='pro@example.com'", one=True)["id"]
        self.assertEqual(self.post(adm, f"/admin/moderation/{uid}", {"action": "approve"}, "/admin/moderation").status_code, 302)
        cli = self.login("cli@example.com")
        self.assertIn(b"Priya Provider", cli.get("/providers?category=Painting&location=durban").data)
        self.assertNotIn(b"Priya Provider", cli.get("/providers?category=Cleaning").data)
        self.assertEqual(self.post(cli, f"/providers/{uid}/book", {"service_date": "2099-01-01", "description": "Paint the lounge walls please", "quoted_amount": "1200"}, f"/providers/{uid}").status_code, 302)
        bid = q("SELECT id FROM bookings", one=True)["id"]
        self.assertEqual(self.post(pro, f"/bookings/{bid}/accept", {}, "/bookings").status_code, 302)
        self.assertEqual(self.post(pro, f"/bookings/{bid}/complete", {"final_amount": "1350.50"}, "/bookings").status_code, 302)
        self.assertIn(b"R 1,350.50", cli.get(f"/receipts/{bid}").data)
        pdf = cli.get(f"/receipts/{bid}.pdf"); self.assertTrue(pdf.data.startswith(b"%PDF"))
        self.assertEqual(self.client().get(f"/receipts/{bid}").status_code, 302)           # must be logged in
        # messaging
        self.assertEqual(self.post(cli, f"/messages/{uid}", {"body": "Hi, are you free Friday?"}, f"/messages/{uid}").status_code, 302)
        self.assertIn(b"free Friday", pro.get(f"/messages/{q('SELECT id FROM users WHERE email=?', ('cli@example.com',), one=True)['id']}").data)
        # job + application + emails to job seekers
        self.assertEqual(self.post(cli, "/jobs/new", {"title": "Paint a fence", "category": "Painting", "location": "Durban", "description": "Paint 20m of wooden fence, two coats.", "budget": "800"}, "/jobs/new").status_code, 302)
        self.assertEqual(q("SELECT COUNT(*) c FROM emails WHERE subject LIKE 'New Painting job%'", one=True)["c"], 1)
        jid = q("SELECT id FROM jobs", one=True)["id"]
        self.assertEqual(self.post(pro, f"/jobs/{jid}/apply", {"message": "I can do this on Saturday morning."}, f"/jobs/{jid}/apply").status_code, 302)
        self.assertEqual(self.post(cli, f"/jobs/{jid}/manage/shortlist", {"app_id": q("SELECT id FROM applications", one=True)["id"]}, f"/jobs/{jid}").status_code, 302)
        self.assertEqual(q("SELECT status FROM applications", one=True)["status"], "shortlisted")
        # access control
        self.assertEqual(cli.get("/admin").status_code, 403)
        # admin analytics / reports
        self.assertIn(b"Painting", adm.get("/admin").data)
        self.assertTrue(adm.get("/admin/analytics.pdf").data.startswith(b"%PDF")); self.assertIn(b"Totals", adm.get("/admin/analytics.csv").data)
        # contact form (inbound) + email centre
        c = self.client(); self.post(c, "/contact", {"name": "Visitor", "email": "v@example.com", "message": "Do you serve Umhlanga?"}, "/contact")
        self.assertIn(b"Umhlanga", adm.get("/admin/emails?tab=in").data)
        self.assertEqual(self.post(adm, "/admin/emails", {"op": "send", "audience": "providers", "subject": "New jobs", "body": "Check the jobs page today."}, "/admin/emails").status_code, 302)
        # backup -> modify -> restore
        self.post(adm, "/admin/backups", {"op": "create"}, "/admin/backups")
        name = os.listdir(self.app.config["BACKUP_DIR"])[0]
        with zipfile.ZipFile(Path(self.app.config["BACKUP_DIR"]) / name) as z: self.assertIn("MANIFEST.txt", z.namelist())
        dbm_exec("DELETE FROM bookings"); self.assertEqual(q("SELECT COUNT(*) c FROM bookings", one=True)["c"], 0)
        self.post(adm, "/admin/backups", {"op": "restore", "name": name, "confirm": "RESTORE"}, "/admin/backups")
        self.assertEqual(q("SELECT COUNT(*) c FROM bookings", one=True)["c"], 1)
        self.assertEqual(adm.get("/admin/backups/download/../../config.py").status_code, 404)   # traversal blocked
        self.assertEqual(adm.get("/admin/backups/download/evil.zip").status_code, 404)

    def test_links_work_for_every_role(self):
        """Crawl every internal link and form action reachable as each role; all must resolve (no 404/500)."""
        self.make_user("provider", "lp@example.com", "Link Provider"); self.make_user("client", "lc@example.com", "Link Client")
        pro = self.login("lp@example.com"); cli = self.login("lc@example.com")
        self.post(pro, "/profile", {"category": "Cleaning", "headline": "Thorough home cleaning", "bio": "Deep cleaning for homes and offices, supplies included.", "location": "Pinetown"}, "/profile")
        dbm_exec("UPDATE profiles SET status='approved'")
        self.post(cli, "/jobs/new", {"title": "Clean my flat", "category": "Cleaning", "location": "Pinetown", "description": "Two-bedroom flat deep clean before moving in."}, "/jobs/new")
        pid = q("SELECT id FROM users WHERE email='lp@example.com'", one=True)["id"]
        self.post(cli, f"/providers/{pid}/book", {"service_date": "2099-02-02", "description": "Clean the flat top to bottom"}, f"/providers/{pid}")
        self.post(cli, f"/messages/{pid}", {"body": "Hello there"}, f"/messages/{pid}")
        adm = self.login("admin@example.com")
        total = 0
        for who, c in (("anon", self.client()), ("provider", pro), ("client", cli), ("admin", adm)):
            seen, todo = set(), ["/"]
            while todo:
                path = todo.pop()
                if path in seen: continue
                seen.add(path)
                r = c.get(path)
                self.assertIn(r.status_code, (200, 302), f"[{who}] {path} -> {r.status_code}")
                if r.status_code == 302:
                    loc = r.headers["Location"].replace("http://localhost", "")
                    self.assertTrue(loc.startswith("/"), f"[{who}] {path} redirects off-site: {loc}")
                    self.assertTrue(self.app.url_map.bind("localhost").match(loc.split("?")[0].split("#")[0]), loc)
                    continue
                if "text/html" not in r.content_type: continue
                p = Links(); p.feed(r.get_data(as_text=True))
                for l in p.links:
                    l = l.split("#")[0]
                    if not l or l.startswith(("mailto:", "http")) and not l.startswith("http://localhost"): continue
                    l = l.replace("http://localhost", "")
                    if l.startswith("/") and "/logout" not in l: todo.append(l)
                for action, method in p.forms:                              # every form posts to a real route
                    a = (action or path).split("?")[0]
                    try: self.app.url_map.bind("localhost").match(a, method=method)
                    except Exception as e: self.fail(f"[{who}] form on {path} -> {method} {a} has no route ({e})")
            total += len(seen)
        self.assertGreater(total, 30)
        print(f"\n   link check: {total} pages crawled across 4 roles, 0 broken")


def check_pw(email, pw):
    from werkzeug.security import check_password_hash
    return check_password_hash(q("SELECT password_hash h FROM users WHERE email=?", (email,), one=True)["h"], pw)


def last_code(email):
    """Re-derive the OTP from the logged e-mail (tests run with no SMTP)."""
    body = q("SELECT body FROM emails WHERE to_addr=? AND subject='Your verification code' ORDER BY id DESC", (email,), one=True)["body"]
    return re.search(r"code is: (\d{6})", body).group(1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
