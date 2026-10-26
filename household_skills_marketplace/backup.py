"""Consistent SQLite backups (zip + SHA-256 manifest), retention, verified restore."""
import sqlite3, zipfile, hashlib, re, tempfile
from datetime import datetime
from pathlib import Path

NAME_RE = re.compile(r"^backup_\d{8}_\d{6}_[a-z\-]{3,12}\.zip$")


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _integrity(path):
    con = sqlite3.connect(path)
    try:
        return con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        con.close()


def create_backup(db_path, backup_dir, label="manual", keep=14):
    d = Path(backup_dir)
    d.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = f"backup_{ts}_{label}.zip"
    with tempfile.TemporaryDirectory() as tmp:
        snap = Path(tmp) / "marketplace.db"
        src, dst = sqlite3.connect(db_path), sqlite3.connect(snap)
        src.backup(dst)                                   # safe while the site is running
        dst.close(); src.close()
        if not _integrity(snap):
            raise RuntimeError("Backup failed its integrity check.")
        with zipfile.ZipFile(d / name, "w", zipfile.ZIP_DEFLATED) as z:
            z.write(snap, "marketplace.db")
            z.writestr("MANIFEST.txt", f"sha256 {_sha(snap)}\ncreated {datetime.now().isoformat()}\n")
    prune(d, keep)
    return name


def list_backups(backup_dir):
    d = Path(backup_dir)
    if not d.exists():
        return []
    out = []
    for p in sorted(d.glob("backup_*.zip"), reverse=True):
        if NAME_RE.match(p.name):
            out.append({"name": p.name, "size_kb": round(p.stat().st_size / 1024, 1),
                        "created": datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                        "kind": p.name.split("_")[-1][:-4]})
    return out


def prune(backup_dir, keep):
    for b in list_backups(backup_dir)[keep:]:
        (Path(backup_dir) / b["name"]).unlink(missing_ok=True)


def backup_path(backup_dir, name):
    if not NAME_RE.match(name or ""):
        return None
    p = (Path(backup_dir) / name).resolve()
    return p if p.parent == Path(backup_dir).resolve() and p.exists() else None


def restore_backup(db_path, backup_dir, name, keep=14):
    """Verify checksum + integrity, take a safety backup, then copy into the live DB."""
    p = backup_path(backup_dir, name)
    if not p:
        raise FileNotFoundError("Backup not found.")
    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(p) as z:
            data = z.read("marketplace.db")
            manifest = z.read("MANIFEST.txt").decode()
        snap = Path(tmp) / "restore.db"
        snap.write_bytes(data)
        if f"sha256 {_sha(snap)}" not in manifest:
            raise ValueError("Checksum mismatch - this backup is corrupted.")
        if not _integrity(snap):
            raise ValueError("Backup failed its integrity check.")
        create_backup(db_path, backup_dir, "prerestore", keep + 1)
        src, dst = sqlite3.connect(snap), sqlite3.connect(db_path)
        src.backup(dst)
        dst.close(); src.close()
