web: sh -c "python -m flask --app app db upgrade && gunicorn wsgi:app --workers 2 --bind 0.0.0.0:${PORT}"
