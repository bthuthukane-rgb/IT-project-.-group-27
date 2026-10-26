"""Command-line helper:  python manage.py <command>
  init        create the database and the first admin account
  seed        add demo providers, clients, jobs (local testing only)
  backup      take a backup now
  restore F   restore from backup file name F
  fetch-mail  pull new mail from the IMAP inbox
"""
import sys
from werkzeug.security import generate_password_hash
import db as dbm
from app import create_app
from db import q, x
import backup as bk

DEMO_PW = "Demo!Pass2026x"
PROVIDERS = [
    ("Thandi Mkhize", "thandi@example.com", "Painting", "Neat interior & exterior painter", "Umlazi, Durban", 180, "I have eight years of painting houses, offices and fences. Clean edges, tidy work and fair quotes."),
    ("Sipho Dlamini", "sipho@example.com", "Gardening", "Lawns, hedges and garden clean-ups", "Pinetown, Durban", 150, "Reliable gardener available weekdays. I bring my own tools and remove all garden waste."),
    ("Nomsa Zulu", "nomsa@example.com", "Cleaning", "Deep cleaning for homes and rentals", "Chatsworth, Durban", 120, "Move-in and move-out deep cleans, weekly home cleaning, and spring cleaning with my own supplies."),
    ("Ayanda Naidoo", "ayanda@example.com", "Basic Repairs", "Handy with leaks, locks and shelves", "Westville, Durban", 200, "Fixing dripping taps, hanging shelves, repairing doors and other small jobs around the house."),
]


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    app = create_app()
    with app.app_context():
        if cmd == "init":
            print("Database ready at", app.config["DATABASE"])
        elif cmd == "seed":
            for n, e, c, h, l, r, b in PROVIDERS:
                if q("SELECT 1 FROM users WHERE email=?", (e,), one=True): continue
                uid = x("INSERT INTO users(email,password_hash,full_name,role,is_verified) VALUES(?,?,?,'provider',1)", (e, generate_password_hash(DEMO_PW), n))
                x("INSERT INTO profiles(user_id,category,headline,bio,location,hourly_rate,status) VALUES(?,?,?,?,?,?,'approved')", (uid, c, h, b, l, r))
            if not q("SELECT 1 FROM users WHERE email='client@example.com'", one=True):
                cid = x("INSERT INTO users(email,password_hash,full_name,role,is_verified) VALUES('client@example.com',?,'Chris Client','client',1)", (generate_password_hash(DEMO_PW),))
                x("INSERT INTO jobs(client_id,title,category,location,description,budget) VALUES(?,?,?,?,?,?)", (cid, "Paint two bedrooms", "Painting", "Durban North", "Two bedrooms of about 12 square metres each need two coats of white paint. Paint will be supplied.", 2500))
            print(f"Demo accounts added. Password for all of them: {DEMO_PW}\n  client@example.com, thandi@example.com, sipho@example.com, ...")
        elif cmd == "backup":
            c = app.config
            print("Created", bk.create_backup(c["DATABASE"], c["BACKUP_DIR"], "manual", c["BACKUP_KEEP"]))
        elif cmd == "restore" and len(sys.argv) > 2:
            c = app.config
            bk.restore_backup(c["DATABASE"], c["BACKUP_DIR"], sys.argv[2], c["BACKUP_KEEP"]); print("Restored", sys.argv[2])
        elif cmd == "fetch-mail":
            from mailer import fetch_inbound
            n, e = fetch_inbound(); print(e or f"{n} new message(s)")
        else:
            print(__doc__)


if __name__ == "__main__":
    main()
