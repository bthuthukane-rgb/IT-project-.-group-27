"""SQLite access layer: schema, helpers. All queries are parameterised."""
import sqlite3
from flask import g, current_app

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL,
  phone TEXT DEFAULT '',
  role TEXT NOT NULL CHECK(role IN ('client','provider','admin')),
  is_verified INTEGER NOT NULL DEFAULT 0,
  is_active INTEGER NOT NULL DEFAULT 1,
  ua_hash TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login TEXT
);
CREATE TABLE IF NOT EXISTS profiles(
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  category TEXT NOT NULL, headline TEXT NOT NULL, bio TEXT NOT NULL,
  location TEXT NOT NULL, hourly_rate REAL, availability TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','suspended')),
  mod_note TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body TEXT NOT NULL, read_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS bookings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER NOT NULL REFERENCES users(id),
  provider_id INTEGER NOT NULL REFERENCES users(id),
  service_date TEXT NOT NULL, description TEXT NOT NULL,
  quoted_amount REAL, final_amount REAL,
  status TEXT NOT NULL DEFAULT 'requested'
    CHECK(status IN ('requested','accepted','declined','completed','cancelled')),
  receipt_no TEXT UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, completed_at TEXT
);
CREATE TABLE IF NOT EXISTS jobs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL, category TEXT NOT NULL, location TEXT NOT NULL,
  description TEXT NOT NULL, budget REAL,
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS applications(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  provider_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'sent' CHECK(status IN ('sent','shortlisted','rejected')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(job_id, provider_id)
);
CREATE TABLE IF NOT EXISTS otps(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL, code_hash TEXT NOT NULL, payload TEXT DEFAULT '',
  expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS login_attempts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, ip TEXT, success INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS emails(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  direction TEXT NOT NULL CHECK(direction IN ('out','in')),
  to_addr TEXT, from_addr TEXT, subject TEXT, body TEXT,
  status TEXT NOT NULL, error TEXT, user_id INTEGER, message_id TEXT UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT NOT NULL,
  detail TEXT DEFAULT '', ip TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_profiles_cat ON profiles(category, status);
CREATE INDEX IF NOT EXISTS ix_msg_pair ON messages(sender_id, recipient_id);
CREATE INDEX IF NOT EXISTS ix_login_email ON login_attempts(email, created_at);
"""


def init_db(path):
    con = sqlite3.connect(path)
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(SCHEMA)
    con.commit()
    con.close()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"], timeout=15)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


def close_db(_=None):
    d = g.pop("db", None)
    if d is not None:
        d.close()


def q(sql, args=(), one=False):
    rows = get_db().execute(sql, args).fetchall()
    if one:
        return rows[0] if rows else None
    return rows


def x(sql, args=()):
    con = get_db()
    cur = con.execute(sql, args)
    con.commit()
    return cur.lastrowid
