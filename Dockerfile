FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        tesseract-ocr \
        tesseract-ocr-eng \
        tesseract-ocr-mkd \
        tesseract-ocr-sqi \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .

ENV TRAINER_APP_ENV=production \
    FLASK_APP=app \
    TESSERACT_CMD=/usr/bin/tesseract \
    TESSERACT_LANGS=eng+mkd+sqi

EXPOSE 8080

CMD ["sh", "-c", "python -m flask --app app db upgrade && python -m flask --app app seed-admin && gunicorn wsgi:app --workers 2 --bind 0.0.0.0:${PORT:-8080} --timeout", "180""]
