# Railway Deployment

## 1) Create services
- Create a new Railway project from this repo.
- Add a **PostgreSQL** service in the same project.

## 2) Configure app variables
Set these in your app service:

- `TRAINER_APP_ENV=production`
- `TRAINER_APP_SECRET_KEY=<long-random-secret>`
- `SESSION_COOKIE_SECURE=1`
- `FORCE_HTTPS=1`
- `SESSION_COOKIE_SAMESITE=Lax`
- `TRUST_PROXY=1`
- `FLASK_DEBUG=0`

Database URL:
- Preferred: set `TRAINER_DATABASE_URI` to Railway Postgres connection string.
- Alternative: rely on Railway `DATABASE_URL` (already supported by app code).

## 3) Build/start
Railway will install `requirements.txt`.
Start command is read from `Procfile`:

`web: gunicorn wsgi:app --workers 2 --bind 0.0.0.0:${PORT}`

## 4) Run migrations
Before first production use, run in Railway app shell:

```bash
python -m flask --app app db upgrade
```

If this DB existed before migrations:

```bash
python -m flask --app app db stamp head
```

## 5) Verify
- Open `/ping` and confirm `PING OK`
- Log in with admin
- Verify add/edit/session/payment flows
