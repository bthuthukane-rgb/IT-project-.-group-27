"""Send mail via SMTP and receive mail via IMAP. Every message is logged in the `emails` table.
With no SMTP_HOST configured the app runs in development mode: mail is logged, not sent."""
import smtplib, ssl, imaplib, email as pyemail
from email.message import EmailMessage
from email.policy import default as default_policy
from email.utils import parseaddr
from flask import current_app
from db import q, x


def send_email(to, subject, body, user_id=None):
    """Returns 'sent' | 'logged' | 'failed'. Never raises."""
    cfg = current_app.config
    subject = " ".join(str(subject).split())[:150]          # no header injection
    status, err = "logged", None
    if cfg["SMTP_HOST"]:
        try:
            msg = EmailMessage()
            msg["From"], msg["To"], msg["Subject"] = cfg["MAIL_FROM"], to, subject
            msg.set_content(body)
            if cfg["SMTP_SSL"]:
                s = smtplib.SMTP_SSL(cfg["SMTP_HOST"], cfg["SMTP_PORT"],
                                     context=ssl.create_default_context(), timeout=15)
            else:
                s = smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=15)
                if cfg["SMTP_TLS"]:
                    s.starttls(context=ssl.create_default_context())
            if cfg["SMTP_USER"]:
                s.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])
            s.send_message(msg)
            s.quit()
            status = "sent"
        except Exception as e:
            print("EMAIL ERROR:", e)                                  # noqa: BLE001
            status, err = "failed", str(e)[:300]
    elif not cfg.get("TESTING"):
        print(f"\n--- DEV MAIL to {to} ---\n{subject}\n{body}\n---------------------------\n")
    x("INSERT INTO emails(direction,to_addr,from_addr,subject,body,status,error,user_id) VALUES('out',?,?,?,?,?,?,?)",
      (to, cfg["MAIL_FROM"], subject, body, status, err, user_id))
    print("EMAIL STATUS:", status)
    return status


def fetch_inbound(limit=50):
    """Pull UNSEEN messages from the IMAP inbox into the `emails` table. -> (count, error)."""
    cfg = current_app.config
    if not cfg["IMAP_HOST"]:
        return 0, "IMAP is not configured (set IMAP_HOST, IMAP_USER, IMAP_PASSWORD)."
    n = 0
    try:
        m = imaplib.IMAP4_SSL(cfg["IMAP_HOST"])
        m.login(cfg["IMAP_USER"], cfg["IMAP_PASSWORD"])
        m.select("INBOX")
        _, data = m.search(None, "UNSEEN")
        for num in data[0].split()[:limit]:
            _, parts = m.fetch(num, "(RFC822)")
            msg = pyemail.message_from_bytes(parts[0][1], policy=default_policy)
            mid = (msg["Message-ID"] or f"imap-{num.decode()}").strip()[:200]
            if q("SELECT 1 FROM emails WHERE message_id=?", (mid,), one=True):
                continue
            sender = parseaddr(msg["From"] or "")[1].lower()
            part = msg.get_body(preferencelist=("plain",))
            text = (part.get_content() if part else "(no text body)")[:5000]
            u = q("SELECT id FROM users WHERE email=?", (sender,), one=True)
            x("INSERT INTO emails(direction,to_addr,from_addr,subject,body,status,user_id,message_id) "
              "VALUES('in',?,?,?,?, 'received',?,?)",
              (cfg["IMAP_USER"], sender, (msg["Subject"] or "(no subject)")[:150], text,
               u["id"] if u else None, mid))
            n += 1
        m.logout()
        return n, None
    except Exception as e:                                      # noqa: BLE001
        return n, f"Could not read inbox: {e}"
