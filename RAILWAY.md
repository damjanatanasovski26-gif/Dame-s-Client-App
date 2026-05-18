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

Optional nutrition/OCR variables:
- `USDA_API_KEY=<your USDA FoodData Central key>`
- `GOOGLE_VISION_API_KEY=<your Google Cloud Vision API key>` (preferred production OCR)
- `GOOGLE_VISION_FEATURE_TYPE=DOCUMENT_TEXT_DETECTION`
- `GOOGLE_VISION_LANGUAGE_HINTS=en,mk,sq`
- `TESSERACT_CMD=/usr/bin/tesseract` (already set in the Docker image, only override if needed)
- `TESSERACT_LANGS=eng+mkd+sqi` (English, Macedonian, Albanian; already set in the Docker image)

## 3) Build/start
Railway should build from the included `Dockerfile`.
That image installs:
- Python dependencies from `requirements.txt`
- `tesseract-ocr`
- English OCR data
- Macedonian OCR data
- Albanian OCR data

The container start command automatically runs:
- `flask db upgrade`
- `flask seed-admin`
- `gunicorn`

## 4) Manual one-time checks
After the first deploy:

- Verify the app service is actually using the `Dockerfile`
- Confirm your PostgreSQL variables are attached
- If this database existed before migrations, run once in the Railway shell:

```bash
python -m flask --app app db stamp head
```

## 5) Verify
- Open `/ping` and confirm `PING OK`
- Log in with admin
- Verify add/edit/session/payment flows
- Verify USDA import works in the Nutrition tab
- Verify label scan works in the Nutrition tab
