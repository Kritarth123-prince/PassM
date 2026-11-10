"""
Vaultic API — Python/Flask backend backed by Neon (PostgreSQL).

A zero-knowledge replacement for the PHP /api endpoints, serving the exact wire
contract the Android app already speaks (prelogin.php / setup.php / login.php /
items.php / logout.php). The server only ever stores ciphertext, KDF parameters
and bcrypt(auth_hash); it can never read a vault.

Run (dev):   DATABASE_URL=... python app.py
Run (prod):  gunicorn -b 0.0.0.0:$PORT app:app
"""
import os
import secrets
import hashlib
import datetime
from functools import wraps

from flask import Flask, request, jsonify
import psycopg
from psycopg_pool import ConnectionPool
import bcrypt

DATABASE_URL = os.environ.get("DATABASE_URL", "")
TOKEN_TTL_DAYS = 30
DEFAULT_ITER = 600000

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL env var is required (your Neon connection string).")

# A small pool is friendly to Neon's pooler endpoint and to a 512 MB free dyno.
pool = ConnectionPool(DATABASE_URL, min_size=1, max_size=5, kwargs={"autocommit": True})

app = Flask(__name__)

# ---------------------------------------------------------------- schema

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS accounts (
        id            SERIAL PRIMARY KEY,
        email         TEXT UNIQUE NOT NULL,
        twofa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
        twofa_secret  TEXT,
        created_at    TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
    )""",
    """CREATE TABLE IF NOT EXISTS vault_accounts (
        user_id       INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
        kdf_salt      TEXT NOT NULL,
        kdf_iter      INTEGER NOT NULL DEFAULT 600000,
        auth_hash     TEXT NOT NULL,
        protected_key TEXT NOT NULL,
        updated_at    TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
    )""",
    """CREATE TABLE IF NOT EXISTS vault_items (
        id         SERIAL PRIMARY KEY,
        user_id    INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        item_uuid  TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        deleted    SMALLINT NOT NULL DEFAULT 0,
        updated_at TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
        UNIQUE (user_id, item_uuid)
    )""",
    """CREATE TABLE IF NOT EXISTS api_tokens (
        token      TEXT PRIMARY KEY,
        user_id    INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        created_at TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
        expires_at TIMESTAMP NOT NULL
    )""",
]


def init_db():
    with pool.connection() as conn:
        for stmt in SCHEMA:
            conn.execute(stmt)


# ---------------------------------------------------------------- helpers

def err(msg, code=400):
    return jsonify({"error": msg}), code


def dummy_salt(email: str) -> str:
    return hashlib.sha256(("pm-dummy|" + email).encode()).hexdigest()[:32]


def new_token() -> str:
    return secrets.token_hex(32)


def utc_now():
    return datetime.datetime.utcnow()


@app.after_request
def cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


def require_auth():
    """Return user_id for a valid Bearer token, or None."""
    hdr = request.headers.get("Authorization", "")
    if not hdr.lower().startswith("bearer "):
        return None
    token = hdr[7:].strip()
    if not token:
        return None
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT user_id FROM api_tokens WHERE token = %s AND expires_at > (now() AT TIME ZONE 'utc')",
            (token,),
        ).fetchone()
    return row[0] if row else None


def auth_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        uid = require_auth()
        if uid is None:
            return err("invalid_token", 401)
        return fn(uid, *a, **kw)
    return wrapper


# ---------------------------------------------------------------- endpoints

@app.route("/prelogin.php", methods=["GET", "OPTIONS"])
def prelogin():
    if request.method == "OPTIONS":
        return ("", 204)
    email = (request.args.get("email") or "").strip().lower()
    if not email:
        return err("email_required")
    with pool.connection() as conn:
        row = conn.execute(
            """SELECT v.kdf_salt, v.kdf_iter
               FROM accounts a LEFT JOIN vault_accounts v ON v.user_id = a.id
               WHERE a.email = %s""",
            (email,),
        ).fetchone()
    if not row:
        return jsonify({
            "account_exists": False, "vault_ready": False,
            "kdf_salt": dummy_salt(email), "kdf_iter": DEFAULT_ITER,
        })
    ready = row[0] is not None
    return jsonify({
        "account_exists": True,
        "vault_ready": ready,
        "kdf_salt": row[0] if ready else dummy_salt(email),
        "kdf_iter": row[1] if ready else DEFAULT_ITER,
    })


@app.route("/setup.php", methods=["POST", "OPTIONS"])
def setup():
    if request.method == "OPTIONS":
        return ("", 204)
    d = request.get_json(silent=True) or {}
    email = (d.get("email") or "").strip().lower()
    kdf_salt = str(d.get("kdf_salt") or "")
    kdf_iter = int(d.get("kdf_iter") or DEFAULT_ITER)
    auth_hash = str(d.get("auth_hash") or "")
    protected_key = str(d.get("protected_key") or "")
    # NOTE: d["password"] (raw master password) is intentionally ignored — never stored.

    if not email or not kdf_salt or not auth_hash or not protected_key:
        return err("missing_fields")
    if kdf_iter < 100000:
        return err("kdf_iter_too_low")

    ah = bcrypt.hashpw(auth_hash.encode(), bcrypt.gensalt()).decode()
    with pool.connection() as conn:
        # Create the account if it's new.
        uid = conn.execute(
            """INSERT INTO accounts (email) VALUES (%s)
               ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
               RETURNING id""",
            (email,),
        ).fetchone()[0]
        # Refuse to clobber an already-enrolled vault (would orphan existing data).
        exists = conn.execute(
            "SELECT 1 FROM vault_accounts WHERE user_id = %s", (uid,)
        ).fetchone()
        if exists:
            return err("already_enrolled", 409)
        conn.execute(
            """INSERT INTO vault_accounts (user_id, kdf_salt, kdf_iter, auth_hash, protected_key, updated_at)
               VALUES (%s, %s, %s, %s, %s, (now() AT TIME ZONE 'utc'))""",
            (uid, kdf_salt, kdf_iter, ah, protected_key),
        )
    return jsonify({"success": True})


@app.route("/login.php", methods=["POST", "OPTIONS"])
def login():
    if request.method == "OPTIONS":
        return ("", 204)
    d = request.get_json(silent=True) or {}
    email = (d.get("email") or "").strip().lower()
    auth_hash = str(d.get("auth_hash") or "")
    if not email or not auth_hash:
        return err("missing_fields")

    with pool.connection() as conn:
        row = conn.execute(
            """SELECT a.id, v.auth_hash, v.kdf_salt, v.kdf_iter, v.protected_key
               FROM accounts a JOIN vault_accounts v ON v.user_id = a.id
               WHERE a.email = %s""",
            (email,),
        ).fetchone()
        if not row or not bcrypt.checkpw(auth_hash.encode(), row[1].encode()):
            return err("invalid_credentials", 401)
        uid, _, kdf_salt, kdf_iter, protected_key = row
        token = new_token()
        exp = utc_now() + datetime.timedelta(days=TOKEN_TTL_DAYS)
        conn.execute(
            "INSERT INTO api_tokens (token, user_id, expires_at) VALUES (%s, %s, %s)",
            (token, uid, exp),
        )
    return jsonify({
        "token": token,
        "expires_at": exp.strftime("%Y-%m-%d %H:%M:%S"),
        "protected_key": protected_key,
        "kdf_salt": kdf_salt,
        "kdf_iter": kdf_iter,
    })


@app.route("/items.php", methods=["GET", "POST", "DELETE", "OPTIONS"])
def items():
    if request.method == "OPTIONS":
        return ("", 204)
    uid = require_auth()
    if uid is None:
        return err("invalid_token", 401)

    if request.method == "GET":
        since = (request.args.get("since") or "").strip()
        with pool.connection() as conn:
            if since:
                rows = conn.execute(
                    """SELECT item_uuid, ciphertext, deleted,
                              to_char(updated_at, 'YYYY-MM-DD HH24:MI:SS')
                       FROM vault_items
                       WHERE user_id = %s AND updated_at > %s::timestamp
                       ORDER BY updated_at""",
                    (uid, since),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT item_uuid, ciphertext, deleted,
                              to_char(updated_at, 'YYYY-MM-DD HH24:MI:SS')
                       FROM vault_items WHERE user_id = %s ORDER BY updated_at""",
                    (uid,),
                ).fetchall()
            server_time = conn.execute(
                "SELECT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS')"
            ).fetchone()[0]
        items_out = [
            {"uuid": r[0], "ciphertext": r[1], "deleted": int(r[2]), "updated_at": r[3]}
            for r in rows
        ]
        return jsonify({"items": items_out, "server_time": server_time})

    if request.method == "POST":
        d = request.get_json(silent=True) or {}
        incoming = d.get("items") or []
        with pool.connection() as conn:
            for it in incoming:
                uuid = str(it.get("uuid") or "")
                ct = str(it.get("ciphertext") or "")
                if not uuid or not ct:
                    continue
                conn.execute(
                    """INSERT INTO vault_items (user_id, item_uuid, ciphertext, deleted, updated_at)
                       VALUES (%s, %s, %s, 0, (now() AT TIME ZONE 'utc'))
                       ON CONFLICT (user_id, item_uuid)
                       DO UPDATE SET ciphertext = EXCLUDED.ciphertext, deleted = 0,
                                     updated_at = (now() AT TIME ZONE 'utc')""",
                    (uid, uuid, ct),
                )
            server_time = conn.execute(
                "SELECT to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD HH24:MI:SS')"
            ).fetchone()[0]
        return jsonify({"success": True, "server_time": server_time})

    # DELETE — tombstone so other devices remove it on their next pull.
    d = request.get_json(silent=True) or {}
    uuid = str(d.get("uuid") or "")
    if not uuid:
        return err("missing_fields")
    with pool.connection() as conn:
        conn.execute(
            """UPDATE vault_items SET deleted = 1, updated_at = (now() AT TIME ZONE 'utc')
               WHERE user_id = %s AND item_uuid = %s""",
            (uid, uuid),
        )
    return jsonify({"success": True})


@app.route("/logout.php", methods=["POST", "OPTIONS"])
def logout():
    if request.method == "OPTIONS":
        return ("", 204)
    uid = require_auth()
    if uid is None:
        return err("invalid_token", 401)
    hdr = request.headers.get("Authorization", "")
    token = hdr[7:].strip()
    with pool.connection() as conn:
        conn.execute("DELETE FROM api_tokens WHERE token = %s", (token,))
    return jsonify({"success": True})


@app.route("/", methods=["GET"])
def health():
    return jsonify({"service": "vaultic-api", "status": "ok"})


def start_self_ping():
    """Keep a free Render instance from spinning down by pinging our own public URL.
    Render injects RENDER_EXTERNAL_URL automatically; or set SELF_PING_URL yourself.
    Default every 10 min (Render sleeps after ~15 min idle). A background daemon thread.
    NOTE: this only keeps an *already-awake* instance warm — it can't wake one that has
    fully slept (e.g. after a deploy/crash). For that, also add an external monitor
    (UptimeRobot / cron-job.org) hitting the URL.
    """
    base = os.environ.get("SELF_PING_URL") or os.environ.get("RENDER_EXTERNAL_URL")
    if not base:
        return
    import threading
    import time
    import urllib.request
    url = base.rstrip("/") + "/"
    interval = int(os.environ.get("SELF_PING_SECONDS", "600"))

    def loop():
        while True:
            time.sleep(interval)
            try:
                urllib.request.urlopen(url, timeout=10).read()
            except Exception:
                pass

    threading.Thread(target=loop, daemon=True).start()


# Create tables on startup (idempotent), then start the keep-warm pinger.
init_db()
start_self_ping()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
