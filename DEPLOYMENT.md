# Deployment Guide

## 1) Environment
Set these variables in production:

- `TRAINER_APP_ENV=production`
- `TRAINER_APP_SECRET_KEY=<long-random-secret>`
- `TRAINER_DATABASE_URI=sqlite:///trainer.db` (or a managed DB URI)
- `SESSION_COOKIE_SECURE=1`
- `FORCE_HTTPS=1`
- `SESSION_COOKIE_SAMESITE=Lax`
- `TRUST_PROXY=1` (if behind reverse proxy)
- `FLASK_DEBUG=0`

## 2) App Server
Use a production WSGI server with `wsgi:app`.

### Waitress (Windows-friendly)
```powershell
venv\Scripts\pip.exe install waitress
venv\Scripts\waitress-serve.exe --listen=127.0.0.1:8000 wsgi:app
```

### Gunicorn (Linux)
```bash
pip install gunicorn
gunicorn -w 3 -b 127.0.0.1:8000 wsgi:app
```

## 3) Database Migrations (Flask-Migrate)
Run migrations before starting/restarting production instances:

```powershell
venv\Scripts\flask.exe --app app db upgrade
```

When models change:

```powershell
venv\Scripts\flask.exe --app app db migrate -m "describe change"
venv\Scripts\flask.exe --app app db upgrade
```

For an already-existing database that predates migrations (one-time):

```powershell
venv\Scripts\flask.exe --app app db stamp head
```

## 4) Reverse Proxy (Nginx/Caddy)
- Terminate TLS/HTTPS at proxy
- Forward to `127.0.0.1:8000`
- Set `X-Forwarded-Proto=https`
- Restrict direct public access to app server port

## 5) Operations
- Keep periodic DB backups (you already have export + DB backup tools)
- Rotate `TRAINER_APP_SECRET_KEY` carefully (forces re-login)
- Monitor logs for repeated login lockouts and security events

## 6) Pre-Deploy Checks
Run this before deploying:

```powershell
venv\Scripts\python.exe scripts\ci_check.py
```

This executes:
- unit tests
- migration drift check (`flask db check`)

Or run the full prep script (install deps + checks + migrations):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\deploy_prep.ps1
```

## 7) Railway
See `RAILWAY.md` for Railway-specific setup and migration commands.
