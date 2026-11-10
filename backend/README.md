# Vaultic API — Python + Neon (PostgreSQL)

A zero-knowledge backend for the **Vaultic** Android app, written in Flask and backed
by **Neon** (serverless PostgreSQL). It serves the exact endpoints the app already
calls, so only the app's base URL needs to change.

It exists because **byethost can't reach Neon** (its PHP has no PostgreSQL driver) and
byethost's anti-bot page blocks the app anyway. A small Python service on a normal host
(e.g. **Enzonic's Python app hosting**) solves both: Python talks to Neon fine, and a
plain host serves the app without an interstitial.

```
Vaultic app  ──HTTPS──▶  this Flask API (Enzonic)  ──▶  Neon PostgreSQL
```

## Endpoints (unchanged wire contract)

| Method | Path | Purpose |
|---|---|---|
| GET  | `/prelogin.php?email=` | KDF params + whether a vault exists |
| POST | `/setup.php` | Create account + enrol vault (registration) |
| POST | `/login.php` | Zero-knowledge login → bearer token |
| GET  | `/items.php?since=` | Pull vault items changed since a cursor |
| POST | `/items.php` | Push (upsert) encrypted items |
| DELETE | `/items.php` | Tombstone an item |
| POST | `/logout.php` | Revoke the token |
| GET  | `/` | Health check |

The server stores only ciphertext, KDF parameters and `bcrypt(auth_hash)`. The raw master
password is **never sent in a usable way and never stored** — `setup` ignores it.

## Account model (read this)

This is a **fresh** account store in Neon. "First time here? Set up my vault" in the app
now **creates** the account. Your existing **byethost** website accounts are a *separate*
MySQL database and are **not** carried over — migrating them is a later, optional step
(it would mean exporting the `members` table and translating it into `accounts`).

## 1. Create the Neon database

1. <https://neon.tech> → your project → **SQL/Tables** (any empty database works; the app
   auto-creates its tables on first start).
2. **Connection Details** → copy the **pooled** connection string. It looks like:
   `postgresql://USER:PASSWORD@ep-xxx-pooler.REGION.aws.neon.tech/DB?sslmode=require&channel_binding=require`

## 2. Run locally (optional sanity check)

```bash
cd backend
python -m venv .venv && . .venv/Scripts/activate   # (Windows); use .venv/bin/activate on Linux/Mac
pip install -r requirements.txt
cp .env.example .env            # then paste your DATABASE_URL into .env
# load .env into your shell, or just:
DATABASE_URL="postgresql://...neon.tech/DB?sslmode=require" python app.py
curl "http://localhost:8080/prelogin.php?email=test@example.com"   # -> JSON
```

## 3. Deploy to Render (recommended)

Render runs Python natively, gives free HTTPS, and serves API clients with no bot-check.

1. Push this repo to GitHub (the `backend/` folder must be included).
2. Render dashboard → **New → Web Service** → connect the repo.
3. Settings:
   - **Root Directory:** `backend`
   - **Runtime:** Python 3 (auto-detected)
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app --bind 0.0.0.0:$PORT`
   - **Instance Type:** Free
4. **Environment →** add `DATABASE_URL` = your Neon pooled connection string.
   (Optional: `SELF_PING_SECONDS=600` to tune the keep-warm interval.)
5. **Create Web Service.** Render builds and gives you `https://YOUR-APP.onrender.com`.
   Verify: `curl https://YOUR-APP.onrender.com/prelogin.php?email=test@x.com` → JSON.

**Avoiding spin-down (free tier sleeps after ~15 min idle):**
- The app **self-pings** automatically — Render sets `RENDER_EXTERNAL_URL`, and `app.py`
  hits it every 10 min to stay warm. Nothing to configure.
- That can't wake an instance that already fully slept (after a deploy/crash). For
  belt-and-braces, also point a free external monitor
  (**UptimeRobot** or **cron-job.org**) at `https://YOUR-APP.onrender.com/` every ~10 min.
- Note: keeping one free Web Service always-on uses ~730 of Render's ~750 free
  instance-hours/month — fine for a single service; don't run a second always-on free one.

## 3b. Deploy to Enzonic (Python app hosting) — alternative

In the **Enzonic Cloud** panel create a **Python** app server (the free Node.js/Python
"web app" tier), then:

1. **Upload** the `backend/` files (`app.py`, `requirements.txt`).
2. **Install deps** — set the install/build command to `pip install -r requirements.txt`
   (or run it from the console).
3. **Environment variable:** add `DATABASE_URL` = your Neon pooled connection string.
   (Set it in the panel's variables — do **not** hard-code it in `app.py`.)
4. **Startup command:** `gunicorn -b 0.0.0.0:$PORT app:app`
   (Enzonic injects `$PORT`; `app.py` also falls back to 8080 for local runs.)
5. Note the server's **public HTTPS URL** (Enzonic gives a subdomain with TLS). Confirm it
   returns JSON:
   ```bash
   curl "https://YOUR-APP.enzonic-domain/prelogin.php?email=test@example.com"
   ```
   If that's JSON (not an HTML page), an API client can reach it. 

> If Enzonic's free Python tier can't expose a public **HTTPS** URL, put a free
> **Cloudflare Tunnel** in front of it (same approach as `HOSTING.md`), or use a VPS.

## 4. Point the app at it

Give the final base URL (e.g. `https://YOUR-APP.enzonic-domain/`) to your builder and
rebuild — `API_BASE_URL` in `android/app/build.gradle.kts` changes to that URL (keep the
trailing slash). Then in Vaultic: **Set up my vault** creates your account, and **Log in**
works thereafter.

## Security

- **Rotate the Neon password** if it has ever been shared in plaintext.
- `DATABASE_URL` lives only in the host's environment / a local `.env` (git-ignored) —
  never commit it.
- Tokens are random 256-bit, 30-day expiry, revoked on logout.
