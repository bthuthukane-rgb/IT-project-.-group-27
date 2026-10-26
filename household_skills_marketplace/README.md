# Household Skills Marketplace (Version 1)

Web platform from the Phase One proposal that connects people offering household skills (painting, cleaning,
gardening, basic repairs...) with clients. **Stack:** HTML + CSS + JavaScript (front end), Python/Flask (back end),
SQLite (database). The proposal allows the stack to be substituted if agreed with the supervisor before development.

## Run it
```bash
pip install -r requirements.txt
python manage.py init          # creates the database + first admin (password printed once, or set ADMIN_PASSWORD)
python manage.py seed          # optional demo data (password: Demo!Pass2026x)
python app.py                  # http://127.0.0.1:5000
python -m unittest tests.test_site -v   # 8 end-to-end tests incl. the link checker
```
With no SMTP configured the site runs in **development mode**: e-mails are saved to the database (Admin > E-mail
centre) and verification links / codes are also shown on screen so you can demo everything offline.

## Requirement checklist
| Requirement | Where |
|---|---|
| Register, profile (<5 min), search/filter, messaging, bookings, admin moderation (proposal v1 scope) | `app.py`, `templates/` |
| **Send e-mail** to job seekers: verification, job alerts to matching providers, application updates, admin bulk mail | `mailer.send_email`, Admin > E-mail centre |
| **Receive e-mail**: contact form + IMAP inbox poll (`manage.py fetch-mail` / "Check inbox now") | `mailer.fetch_inbound` |
| **Validation**: server-side on every field + HTML5/JS client-side, honeypot, length limits | `security.py`, `static/js/app.js` |
| **Security**: scrypt password hashes, CSRF tokens, parameterised SQL, CSP + security headers, lockout after 5 failed logins, rate limiting, signed expiring links, session timeout, role checks, audit log, no user enumeration | `security.py`, `app.py` |
| **Login verification on changes**: e-mail confirmation at sign-up; 6-digit e-mailed code for login from a new browser/device, e-mail change (sent to the new address) and password change | `/verify-code` |
| **Form links that work**: verification, reset, shareable job link + direct application-form link (copy buttons), login `next=` redirects (open-redirect safe). The link checker crawls every link and form action as visitor, provider, client and admin | `tests/test_site.py` |
| **System backups**: scheduled + on demand, consistent SQLite snapshot, SHA-256 manifest, retention, download, verified restore (safety backup first) | `backup.py`, Admin > Backups |
| **Reports**: receipt (screen/print + PDF), analytics dashboard with charts, CSV and PDF export | `reports.py`, Admin > Analytics |
| **User friendliness**: responsive, keyboard/skip-link accessible, plain-language errors, show/hide password, character counters, confirm dialogs, empty states | templates + CSS/JS |
| **Password requirements checklist**: live ticks + strength meter on sign-up, reset and change-password; same rules enforced on the server | `security.RULES`, `templates/_m.html` |

## Password rules (checklist)
- [ ] At least 10 characters  - [ ] Uppercase letter  - [ ] Lowercase letter  - [ ] Number
- [ ] Special character  - [ ] No spaces  - [ ] Not a common password  - [ ] Does not contain your name / e-mail name

## Going live
1. Set `SECRET_KEY`, `BASE_URL`, `HTTPS=1`, SMTP/IMAP settings in `.env` (see `.env.example`).
2. Serve behind HTTPS with a production server, e.g. `pip install waitress` then `waitress-serve --call app:create_app`.
3. Copy `backups/` off the server regularly. Use a different admin password from any demo one.

## Notes / limits (v1)
Payments, ratings and a mobile app are excluded per the proposal; receipts record the agreed amount only.
E-mail is sent synchronously (fine for hundreds of recipients; use a queue such as Celery for more).
SQLite suits a single-server deployment; the SQL is standard and can move to PostgreSQL later.
