web: sh -c "python -m flask --app app db upgrade && python -m flask --app app seed-admin && gunicorn wsgi:app --workers 2 --bind 0.0.0.0:${PORT}"
