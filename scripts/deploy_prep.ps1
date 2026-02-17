$ErrorActionPreference = "Stop"

Write-Host "==> Installing dependencies"
venv\Scripts\pip.exe install -r requirements.txt

Write-Host "==> Running pre-deploy checks"
venv\Scripts\python.exe scripts\ci_check.py

Write-Host "==> Applying migrations"
venv\Scripts\flask.exe --app app db upgrade

Write-Host ""
Write-Host "Deployment prep complete."
Write-Host "Start server with:"
Write-Host "venv\Scripts\waitress-serve.exe --listen=127.0.0.1:8000 wsgi:app"
