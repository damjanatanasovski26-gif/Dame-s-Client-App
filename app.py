from flask import Flask, render_template, request, redirect, url_for, session, Response, send_file, abort
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
import click
from datetime import datetime, date, timedelta, timezone
import calendar
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
import csv
import hmac
import io
import json
import os
import secrets
import re
from math import ceil
from werkzeug.utils import secure_filename
import uuid

app = Flask(__name__)
APP_ENV = os.environ.get("TRAINER_APP_ENV", os.environ.get("FLASK_ENV", "development")).lower()
IS_PROD = APP_ENV == "production"

secret_key = os.environ.get("TRAINER_APP_SECRET_KEY") or os.environ.get("SECRET_KEY")
if IS_PROD and not secret_key:
    raise RuntimeError("Missing TRAINER_APP_SECRET_KEY/SECRET_KEY in production.")
app.config["SECRET_KEY"] = secret_key or os.urandom(32)

database_uri = (
    os.environ.get("TRAINER_DATABASE_URI")
    or os.environ.get("DATABASE_URL")
    or "sqlite:///trainer.db"
)
# Railway Postgres URLs can use postgres://, but SQLAlchemy expects postgresql://.
if database_uri.startswith("postgres://"):
    database_uri = database_uri.replace("postgres://", "postgresql://", 1)
# Prefer psycopg v3 driver on PostgreSQL to avoid psycopg2/libpq runtime issues.
if database_uri.startswith("postgresql://"):
    database_uri = database_uri.replace("postgresql://", "postgresql+psycopg://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = database_uri
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["CSRF_ENABLED"] = True

# Session cookie hardening (production-safe, dev-friendly)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
app.config["SESSION_COOKIE_NAME"] = os.environ.get("SESSION_COOKIE_NAME", "trainer_session")
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("SESSION_COOKIE_SECURE", "1" if IS_PROD else "0").lower() in ("1", "true", "yes", "on")
)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
    days=int(os.environ.get("REMEMBER_ME_DAYS", "30"))
)
app.config["FORCE_HTTPS"] = (
    os.environ.get("FORCE_HTTPS", "1" if IS_PROD else "0").lower() in ("1", "true", "yes", "on")
)
app.config["ENABLE_SECURITY_HEADERS"] = True
app.config["LOGIN_MAX_ATTEMPTS"] = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "5"))
app.config["LOGIN_WINDOW_SECONDS"] = int(os.environ.get("LOGIN_WINDOW_SECONDS", "300"))
app.config["LOGIN_LOCK_SECONDS"] = int(os.environ.get("LOGIN_LOCK_SECONDS", "600"))
app.config["UPLOAD_PROGRESS_DIR"] = os.environ.get(
    "UPLOAD_PROGRESS_DIR",
    os.path.join(app.root_path, "static", "uploads", "progress")
)

os.makedirs(app.config["UPLOAD_PROGRESS_DIR"], exist_ok=True)

if os.environ.get("TRUST_PROXY", "1").lower() in ("1", "true", "yes", "on"):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

db = SQLAlchemy(app)
migrate = Migrate(app, db)


@app.route("/manifest.webmanifest")
def pwa_manifest():
    return app.send_static_file("manifest.webmanifest")


@app.route("/service-worker.js")
def pwa_service_worker():
    resp = app.send_static_file("service-worker.js")
    resp.headers["Content-Type"] = "application/javascript; charset=utf-8"
    resp.headers["Cache-Control"] = "no-cache"
    return resp


def utc_now():
    # Use naive UTC timestamps because DB DateTime columns are timezone-naive.
    return datetime.utcnow()


def get_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def truthy(v: str):
    return (v or "").lower() in ("1", "true", "yes", "on")


def log_security_event(action: str, details: str = ""):
    user = session.get("user_id")
    role = session.get("role")
    app.logger.info("[security] action=%s user_id=%s role=%s ip=%s details=%s", action, user, role, request.remote_addr, details)


def humanize_last_seen(ts: datetime | None):
    if not ts:
        return "-"
    dt = ts
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    delta = utc_now() - dt
    seconds = int(max(delta.total_seconds(), 0))
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        mins = seconds // 60
        return f"{mins} min ago"
    if seconds < 86400:
        hours = seconds // 3600
        return f"{hours}h ago"
    if seconds < 604800:
        days = seconds // 86400
        return f"{days}d ago"
    return dt.strftime("%d/%m/%Y %H:%M UTC")


def login_throttle_keys(username: str):
    ip = (request.remote_addr or "unknown").strip()
    normalized_username = (username or "").strip().lower() or "*"
    return [f"{ip}::{normalized_username}", f"{ip}::*"]


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": get_csrf_token}


@app.before_request
def touch_last_seen():
    uid = session.get("user_id")
    if not uid:
        return
    if request.endpoint == "static":
        return
    user = db.session.get(User, uid)
    if not user:
        return
    now = utc_now()
    if user.last_seen_at and (now - user.last_seen_at).total_seconds() < 60:
        return
    user.last_seen_at = now
    db.session.commit()


@app.before_request
def csrf_protect():
    if not app.config.get("CSRF_ENABLED", True):
        return
    if request.method != "POST":
        return

    expected = session.get("_csrf_token")
    provided = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not expected or not provided or not hmac.compare_digest(expected, provided):
        abort(400, description="Invalid CSRF token.")


@app.before_request
def enforce_https():
    if not app.config.get("FORCE_HTTPS"):
        return
    if app.testing:
        return
    if request.path.startswith("/ping"):
        return
    is_https = request.is_secure or request.headers.get("X-Forwarded-Proto", "").lower() == "https"
    if not is_https:
        return redirect(request.url.replace("http://", "https://", 1), code=301)


@app.after_request
def apply_security_headers(resp):
    if not app.config.get("ENABLE_SECURITY_HEADERS", True):
        return resp
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if app.config.get("SESSION_COOKIE_SECURE"):
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    resp.headers["Content-Security-Policy"] = csp
    return resp

# =========================
# Models
# =========================
class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(50))
    plan = db.Column(db.String(50))

    # fallback if no payments exist
    weekly_sessions = db.Column(db.Integer, default=0)

    created_at = db.Column(db.DateTime, default=utc_now)

    # rollover system
    rollover_bonus = db.Column(db.Integer, default=0)  # bonus sessions for a specific next week
    rollover_for_week = db.Column(db.Date, nullable=True)  # week_start date for which rollover applies
    last_transfer_week = db.Column(db.Date, nullable=True)  # prevent multiple transfers per week


class Measurement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("client.id"), nullable=False)

    date = db.Column(db.DateTime, default=utc_now)

    weight = db.Column(db.Float)
    chest = db.Column(db.Float)
    waist = db.Column(db.Float)
    stomach = db.Column(db.Float)
    glutes = db.Column(db.Float)
    arm_left = db.Column(db.Float)
    arm_right = db.Column(db.Float)
    quad_left = db.Column(db.Float)
    quad_right = db.Column(db.Float)
    calf_left = db.Column(db.Float)
    calf_right = db.Column(db.Float)


class SessionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("client.id"), nullable=False)
    date = db.Column(db.DateTime, default=utc_now)
    note = db.Column(db.String(200))


class ClientNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("client.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    text = db.Column(db.String(500), nullable=False)
    is_private = db.Column(db.Boolean, nullable=False, default=False)
    created_by_role = db.Column(db.String(20), nullable=False, default="admin")


class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("client.id"), nullable=False, index=True)
    scheduled_for = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), nullable=False, default="requested")  # requested/confirmed/completed/cancelled
    note = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    created_by_role = db.Column(db.String(20), nullable=False, default="client")


class ProgressPhoto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("client.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    note = db.Column(db.String(200))
    uploaded_by_role = db.Column(db.String(20), nullable=False, default="client")


class ClientGoal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("client.id"), nullable=False, index=True)
    title = db.Column(db.String(120), nullable=False)
    target_value = db.Column(db.Float, nullable=True)
    current_value = db.Column(db.Float, nullable=True)
    target_date = db.Column(db.Date, nullable=True)
    status = db.Column(db.String(20), nullable=False, default="active")  # active/completed/paused
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    note = db.Column(db.String(300))


class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("client.id"), nullable=False)

    paid_on = db.Column(db.DateTime, default=utc_now)

    # start date of coverage (DD/MM/YYYY from form)
    start_date = db.Column(db.Date, nullable=False)

    months = db.Column(db.Integer, nullable=False, default=1)
    sessions_per_week = db.Column(db.Integer, nullable=False, default=3)

    # monthly price used (5000 or 7000)
    monthly_price = db.Column(db.Integer, nullable=False, default=5000)

    # total paid (e.g. 10000)
    amount_paid = db.Column(db.Integer, nullable=False, default=0)

    note = db.Column(db.String(200))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    # "admin" or "client"
    role = db.Column(db.String(20), default="client", nullable=False)

    # client users link to a Client profile
    client_id = db.Column(db.Integer, db.ForeignKey("client.id"), nullable=True)
    must_change_password = db.Column(db.Boolean, nullable=False, default=False)
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_seen_at = db.Column(db.DateTime, nullable=True)


class LoginThrottle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(255), unique=True, nullable=False, index=True)
    count = db.Column(db.Integer, nullable=False, default=0)
    first_ts = db.Column(db.DateTime, nullable=False, default=utc_now)
    lock_until = db.Column(db.DateTime, nullable=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=utc_now, onupdate=utc_now)


# =========================
# Helpers
# =========================
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def is_admin():
    return session.get("role") == "admin"


def current_client_id():
    return session.get("client_id")


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return User.query.filter_by(id=uid).first()


def parse_ddmmyyyy(s: str):
    s = (s or "").strip()
    # expects DD/MM/YYYY
    try:
        dd, mm, yy = s.split("/")
        return date(int(yy), int(mm), int(dd))
    except Exception:
        return None


def to_float(value):
    value = (value or "").strip().replace(",", ".")
    if value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


MEASUREMENT_FIELDS = [
    "weight",
    "chest",
    "waist",
    "stomach",
    "glutes",
    "arm_left",
    "arm_right",
    "quad_left",
    "quad_right",
    "calf_left",
    "calf_right",
]


def parse_measurement_form(form_data):
    parsed = {}
    invalid_fields = []
    for field in MEASUREMENT_FIELDS:
        raw = (form_data.get(field) or "").strip().replace(",", ".")
        if raw == "":
            parsed[field] = None
            continue
        try:
            parsed[field] = float(raw)
        except ValueError:
            invalid_fields.append(field.replace("_", " "))

    if invalid_fields:
        return None, f"Invalid number for: {', '.join(invalid_fields)}."
    if all(v is None for v in parsed.values()):
        return None, "Enter at least one measurement value."
    return parsed, None


def is_weight_goal(goal: ClientGoal) -> bool:
    text = f"{goal.title or ''} {goal.note or ''}".lower()
    markers = ("kg", "kilo", "weight", "tezina", "тежина")
    return any(marker in text for marker in markers)


def get_latest_weight_value(client_id: int):
    latest_weight = (
        Measurement.query.filter_by(client_id=client_id)
        .filter(Measurement.weight.isnot(None))
        .order_by(Measurement.date.desc(), Measurement.id.desc())
        .first()
    )
    return latest_weight.weight if latest_weight else None


def sync_weight_goal_progress(client_id: int):
    latest_weight = get_latest_weight_value(client_id)
    if latest_weight is None:
        return 0

    goals = (
        ClientGoal.query.filter_by(client_id=client_id)
        .filter(ClientGoal.status != "completed")
        .all()
    )
    updated = 0
    for goal in goals:
        if not is_weight_goal(goal):
            continue
        if goal.current_value != latest_weight:
            goal.current_value = latest_weight
            updated += 1
    return updated


def to_int(value, default=0):
    value = (value or "").strip()
    if value == "":
        return default
    try:
        return int(value)
    except ValueError:
        return default


def parse_datetime_local(value: str):
    value = (value or "").strip()
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(value, fmt)
        except Exception:
            continue
    return None


def parse_iso_date(value: str):
    value = (value or "").strip()
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except Exception:
        return None


def allowed_photo_file(filename: str):
    name = (filename or "").lower()
    return name.endswith(".jpg") or name.endswith(".jpeg") or name.endswith(".png") or name.endswith(".webp")


def parse_phone(value):
    phone = (value or "").strip()
    if phone == "":
        return ""
    if not re.fullmatch(r"\+?\d+", phone):
        return None
    return phone


def build_session_calendar(sessions: list[SessionLog], target_date: date | None = None):
    target = target_date or date.today()
    year = target.year
    month = target.month
    month_name = calendar.month_name[month]

    first_weekday, days_in_month = calendar.monthrange(year, month)  # Mon=0
    offset = first_weekday

    session_counts = {}
    for s in sessions:
        d = s.date.date()
        if d.year == year and d.month == month:
            session_counts[d.day] = session_counts.get(d.day, 0) + 1

    cells = []
    for _ in range(offset):
        cells.append({"day": None, "count": 0, "is_today": False})
    for day_num in range(1, days_in_month + 1):
        today = date.today()
        cells.append({
            "day": day_num,
            "count": session_counts.get(day_num, 0),
            "is_today": today.year == year and today.month == month and today.day == day_num,
        })
    while len(cells) % 7 != 0:
        cells.append({"day": None, "count": 0, "is_today": False})

    return {
        "year": year,
        "month": month,
        "month_name": month_name,
        "weekday_labels": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        "cells": cells,
    }


def week_start(d: date) -> date:
    # Monday start
    return d - timedelta(days=d.weekday())


def add_months(d: date, months: int) -> date:
    # add months keeping day if possible (simple safe method)
    year = d.year + (d.month - 1 + months) // 12
    month = (d.month - 1 + months) % 12 + 1
    day = d.day

    # clamp day to month length
    # month lengths with leap year check
    def days_in_month(y, m):
        if m in (1, 3, 5, 7, 8, 10, 12):
            return 31
        if m in (4, 6, 9, 11):
            return 30
        # feb
        leap = (y % 4 == 0 and y % 100 != 0) or (y % 400 == 0)
        return 29 if leap else 28

    dim = days_in_month(year, month)
    if day > dim:
        day = dim

    return date(year, month, day)


def seed_admin():
    existing = User.query.filter_by(username="admin").first()
    if not existing:
        default_admin_username = os.environ.get("ADMIN_DEFAULT_USERNAME", "admin")
        default_admin_password = os.environ.get("ADMIN_DEFAULT_PASSWORD", "admin123")
        u = User(
            username=default_admin_username,
            password_hash=generate_password_hash(default_admin_password),
            role="admin",
            client_id=None,
        )
        db.session.add(u)
        db.session.commit()
        print(f"Created default admin: {default_admin_username} / {default_admin_password}")


@app.cli.command("seed-admin")
def seed_admin_command():
    """Create default admin user if it doesn't exist."""
    seed_admin()
    click.echo("seed-admin complete")


def get_current_plan(client_id: int):
    """Returns (sessions_per_week, current_status dict or None) based on latest payment."""
    today = date.today()

    latest_payment = (
        Payment.query.filter_by(client_id=client_id)
        .order_by(Payment.start_date.desc(), Payment.paid_on.desc(), Payment.id.desc())
        .first()
    )

    if not latest_payment:
        return None, None

    paid_until = add_months(latest_payment.start_date, latest_payment.months)
    days_left = (paid_until - today).days

    status = {
        "amount_paid": latest_payment.amount_paid,
        "start_date": latest_payment.start_date,
        "months": latest_payment.months,
        "paid_until": paid_until,
        "days_left": days_left,
        "sessions_per_week": latest_payment.sessions_per_week,
    }
    return latest_payment.sessions_per_week, status


def compute_sessions(client: Client, sessions_per_week: int):
    """Compute used/remaining for current week including rollover."""
    today = date.today()
    ws = week_start(today)

    used_this_week = (
        SessionLog.query.filter_by(client_id=client.id)
        .filter(SessionLog.date >= datetime(ws.year, ws.month, ws.day, tzinfo=timezone.utc))
        .count()
    )

    bonus = 0
    if client.rollover_for_week == ws and (client.rollover_bonus or 0) > 0:
        bonus = client.rollover_bonus

    allowed = max((sessions_per_week or 0) + bonus, 0)
    remaining = max(allowed - used_this_week, 0)

    return used_this_week, remaining, bonus, allowed


def csv_download_response(filename: str, headers: list[str], rows: list[list]):
    output = io.StringIO()
    output.write("\ufeff")  # UTF-8 BOM for spreadsheet compatibility.
    writer = csv.writer(output)
    writer.writerow(headers)
    writer.writerows(rows)
    return Response(
        output.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


def resolve_db_file_path():
    db_path = db.engine.url.database
    if not db_path:
        return None

    candidates = []
    if os.path.isabs(db_path):
        candidates.append(db_path)
    else:
        candidates.append(os.path.join(app.instance_path, db_path))
        candidates.append(os.path.join(app.root_path, db_path))
        candidates.append(os.path.abspath(db_path))

    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def get_or_404(model, object_id):
    obj = db.session.get(model, object_id)
    if obj is None:
        abort(404)
    return obj


def login_throttle_status(keys: list[str]):
    now = utc_now()
    max_seconds_left = 0
    window_seconds = app.config["LOGIN_WINDOW_SECONDS"]

    for key in keys:
        state = LoginThrottle.query.filter_by(key=key).first()
        if not state:
            continue

        lock_until = state.lock_until
        if lock_until and lock_until.tzinfo is not None:
            lock_until = lock_until.astimezone(timezone.utc).replace(tzinfo=None)
        if lock_until and lock_until > now:
            seconds_left = ceil((lock_until - now).total_seconds())
            if seconds_left > max_seconds_left:
                max_seconds_left = seconds_left
            continue

        first_ts = state.first_ts
        if first_ts.tzinfo is not None:
            first_ts = first_ts.astimezone(timezone.utc).replace(tzinfo=None)
        if (now - first_ts).total_seconds() > window_seconds:
            db.session.delete(state)

    if db.session.deleted:
        db.session.commit()

    return max_seconds_left > 0, max_seconds_left


def login_throttle_failed(keys: list[str]):
    now = utc_now()
    window_seconds = app.config["LOGIN_WINDOW_SECONDS"]
    max_attempts = app.config["LOGIN_MAX_ATTEMPTS"]
    lock_seconds = app.config["LOGIN_LOCK_SECONDS"]

    for key in keys:
        state = LoginThrottle.query.filter_by(key=key).first()
        if not state:
            state = LoginThrottle(key=key, count=0, first_ts=now, lock_until=None)
            db.session.add(state)
        else:
            first_ts = state.first_ts
            if first_ts.tzinfo is not None:
                first_ts = first_ts.astimezone(timezone.utc).replace(tzinfo=None)
            if (now - first_ts).total_seconds() > window_seconds:
                state.count = 0
                state.first_ts = now
                state.lock_until = None

        state.count += 1
        if state.count >= max_attempts:
            state.lock_until = now + timedelta(seconds=lock_seconds)

    db.session.commit()


def login_throttle_success(keys: list[str]):
    states = LoginThrottle.query.filter(LoginThrottle.key.in_(keys)).all()
    if not states:
        return
    for state in states:
        db.session.delete(state)
    db.session.commit()


# =========================
# Auth Routes
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", err=None, lock_seconds=None)

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    remember_me = truthy(request.form.get("remember_me", "0"))
    throttle_keys = login_throttle_keys(username)
    locked, seconds_left = login_throttle_status(throttle_keys)
    if locked:
        return render_template("login.html", err="Too many attempts.", lock_seconds=seconds_left)

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        login_throttle_failed(throttle_keys)
        return render_template("login.html", err="Invalid username or password.", lock_seconds=None)
    if user.role == "disabled":
        login_throttle_failed(throttle_keys)
        return render_template("login.html", err="Account is deactivated. Please contact your coach.", lock_seconds=None)
    login_throttle_success(throttle_keys)

    now = utc_now()
    user.last_login_at = now
    user.last_seen_at = now
    db.session.commit()

    session["user_id"] = user.id
    session["role"] = user.role
    session["client_id"] = user.client_id
    session.permanent = remember_me

    if user.role == "admin":
        return redirect(url_for("index"))
    if user.must_change_password:
        return redirect(url_for(
            "client_profile",
            client_id=user.client_id,
            tab="info",
            err="You must set a new password before using other tabs."
        ))
    return redirect(url_for("client_profile", client_id=user.client_id, tab="info"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# =========================
# Main Routes
# =========================
@app.route("/")
@login_required
def index():
    if not is_admin():
        # client users go straight to their profile
        cid = current_client_id()
        return redirect(url_for("client_profile", client_id=cid, tab="info"))

    clients = Client.query.order_by(Client.created_at.desc()).all()
    payment_alerts = []
    for c in clients:
        _spw, status = get_current_plan(c.id)
        if not status:
            continue
        days_left = status["days_left"]
        if days_left < 0:
            payment_alerts.append({
                "client": c,
                "tone": "overdue",
                "label": f"Overdue by {abs(days_left)} day(s)",
                "days_left": days_left,
            })
        elif days_left <= 7:
            payment_alerts.append({
                "client": c,
                "tone": "due-soon",
                "label": f"Due in {days_left} day(s)",
                "days_left": days_left,
            })
    payment_alerts.sort(key=lambda x: x["days_left"])
    err = request.args.get("err")
    msg = request.args.get("msg")
    return render_template("index.html", clients=clients, err=err, msg=msg, payment_alerts=payment_alerts)


@app.route("/client/<int:client_id>")
@login_required
def client_profile(client_id):
    # access control
    if not is_admin():
        if current_client_id() != client_id:
            return "Forbidden", 403

    client = get_or_404(Client, client_id)
    tab = request.args.get("tab", "info")
    err = request.args.get("err")
    msg = request.args.get("msg")
    viewer = current_user()
    # Keep client navigation on allowed tabs only.
    if not is_admin() and tab == "payments":
        return redirect(url_for("client_profile", client_id=client.id, tab="info"))
    if not is_admin() and viewer and viewer.must_change_password and tab != "info":
        return redirect(url_for(
            "client_profile",
            client_id=client.id,
            tab="info",
            err="You must set a new password before using other tabs."
        ))

    # Stats
    all_measurements = (
        Measurement.query.filter_by(client_id=client.id)
        .order_by(Measurement.date.desc())
        .all()
    )

    def has_body_measurements(m: Measurement) -> bool:
        return any(
            v is not None
            for v in (
                m.chest, m.waist, m.stomach, m.glutes,
                m.arm_left, m.arm_right, m.quad_left, m.quad_right,
                m.calf_left, m.calf_right,
            )
        )

    measurements = [m for m in all_measurements if has_body_measurements(m)]
    latest = measurements[0] if measurements else None

    # Weight-only/weight history data
    weight_points_asc = (
        Measurement.query.filter_by(client_id=client.id)
        .filter(Measurement.weight.isnot(None))
        .order_by(Measurement.date.asc())
        .all()
    )
    weight_labels = [m.date.strftime("%d/%m") for m in weight_points_asc]
    weight_values = [m.weight for m in weight_points_asc]
    weight_latest = weight_points_asc[-1] if weight_points_asc else None
    weight_measurements = list(reversed(weight_points_asc))
    weight_change = None
    if len(weight_points_asc) >= 2:
        weight_change = round(weight_points_asc[-1].weight - weight_points_asc[0].weight, 1)

    # Sessions / Payments Plan
    sessions_per_week_from_payments, current_status = get_current_plan(client.id)
    sessions_per_week = (
        sessions_per_week_from_payments
        if sessions_per_week_from_payments is not None
        else (client.weekly_sessions or 0)
    )

    used_this_week, remaining, bonus, allowed = compute_sessions(client, sessions_per_week)

    payment_status_label = None
    payment_status_tone = None
    if current_status:
        days_left = current_status["days_left"]
        if days_left < 0:
            payment_status_label = "Overdue"
            payment_status_tone = "overdue"
        elif days_left <= 7:
            payment_status_label = "Due soon"
            payment_status_tone = "due-soon"
        else:
            payment_status_label = "Active"
            payment_status_tone = "active"

    sessions = (
        SessionLog.query.filter_by(client_id=client.id)
        .order_by(SessionLog.date.desc())
        .limit(50)
        .all()
    )
    session_calendar = build_session_calendar(sessions)
    total_sessions = SessionLog.query.filter_by(client_id=client.id).count()
    thirty_days_ago_dt = utc_now() - timedelta(days=30)
    sessions_30d = (
        SessionLog.query.filter_by(client_id=client.id)
        .filter(SessionLog.date >= thirty_days_ago_dt)
        .count()
    )
    target_30d = max((sessions_per_week or 0) * 4, 1)
    adherence_30d = min(int((sessions_30d / target_30d) * 100), 100)
    weight_30d_points = (
        Measurement.query.filter_by(client_id=client.id)
        .filter(Measurement.weight.isnot(None))
        .filter(Measurement.date >= thirty_days_ago_dt)
        .order_by(Measurement.date.asc())
        .all()
    )
    weight_change_30d = None
    if len(weight_30d_points) >= 2:
        weight_change_30d = round(weight_30d_points[-1].weight - weight_30d_points[0].weight, 1)

    # Payments view
    payments = (
        Payment.query.filter_by(client_id=client.id)
        .order_by(Payment.start_date.desc(), Payment.paid_on.desc(), Payment.id.desc())
        .all()
    )

    today = date.today()
    payments_view = []
    for idx, p in enumerate(payments):
        due = add_months(p.start_date, p.months)
        days_left = (due - today).days
        payments_view.append({
            "p": p,
            "due": due,
            "days_left": days_left,
            "is_current": idx == 0,
        })

    client_user = (
        User.query
        .filter_by(client_id=client.id)
        .filter(User.role != "admin")
        .order_by(User.id.desc())
        .first()
    )
    client_online_now = False
    client_last_seen_display = "-"
    client_last_login_display = "-"
    if client_user:
        client_last_seen_display = humanize_last_seen(client_user.last_seen_at)
        if client_user.last_login_at:
            client_last_login_display = client_user.last_login_at.strftime("%d/%m/%Y %H:%M UTC")
        if client_user.last_seen_at and client_user.role != "disabled":
            seen_at = client_user.last_seen_at
            if seen_at.tzinfo is not None:
                seen_at = seen_at.astimezone(timezone.utc).replace(tzinfo=None)
            client_online_now = (utc_now() - seen_at).total_seconds() <= 300
    appointments = (
        Appointment.query.filter_by(client_id=client.id)
        .order_by(Appointment.scheduled_for.asc(), Appointment.id.asc())
        .all()
    )
    pending_today_appointments = []
    today = date.today()
    if not is_admin():
        pending_today_appointments = [
            a for a in appointments
            if a.status == "requested" and a.scheduled_for.date() == today
        ]
    photos = (
        ProgressPhoto.query.filter_by(client_id=client.id)
        .order_by(ProgressPhoto.created_at.desc(), ProgressPhoto.id.desc())
        .all()
    )
    goals = (
        ClientGoal.query.filter_by(client_id=client.id)
        .order_by(ClientGoal.created_at.desc(), ClientGoal.id.desc())
        .all()
    )
    if is_admin():
        notes = (
            ClientNote.query.filter_by(client_id=client.id)
            .order_by(ClientNote.created_at.desc(), ClientNote.id.desc())
            .all()
        )
    else:
        notes = (
            ClientNote.query.filter_by(client_id=client.id, is_private=False)
            .order_by(ClientNote.created_at.desc(), ClientNote.id.desc())
            .all()
        )

    must_change_password = bool(client_user.must_change_password) if client_user else False
    milestones = []
    if total_sessions >= 10:
        milestones.append("10+ sessions completed")
    if total_sessions >= 25:
        milestones.append("25+ sessions consistency")
    if weight_change is not None and weight_change <= -2:
        milestones.append(f"Weight down {abs(weight_change):.1f} kg")
    if not milestones:
        milestones.append("First milestone pending")

    return render_template(
        "client.html",
        client=client,
        tab=tab,
        err=err,
        msg=msg,
        is_admin=is_admin(),

        # stats
        measurements=measurements,
        latest=latest,
        weight_latest=weight_latest,
        weight_measurements=weight_measurements,
        weight_change=weight_change,
        weight_labels=weight_labels,
        weight_values=weight_values,

        # sessions
        sessions=sessions,
        session_calendar=session_calendar,
        total_sessions=total_sessions,
        sessions_30d=sessions_30d,
        adherence_30d=adherence_30d,
        weight_change_30d=weight_change_30d,
        used_this_week=used_this_week,
        remaining=remaining,
        bonus=bonus,
        allowed=allowed,
        sessions_per_week=sessions_per_week,

        # payments
        payments_view=payments_view,
        current_status=current_status,
        payment_status_label=payment_status_label,
        payment_status_tone=payment_status_tone,
        notes=notes,
        appointments=appointments,
        pending_today_appointments=pending_today_appointments,
        photos=photos,
        goals=goals,
        client_user=client_user,
        client_online_now=client_online_now,
        client_last_seen_display=client_last_seen_display,
        client_last_login_display=client_last_login_display,
        must_change_password=must_change_password,
        milestones=milestones,
    )


@app.route("/export/clients.csv")
@login_required
def export_clients_csv():
    if not is_admin():
        return "Forbidden", 403

    clients = Client.query.order_by(Client.created_at.desc()).all()
    log_security_event("export_clients_csv", f"rows={len(clients)}")
    rows = [
        [
            c.id,
            c.name,
            c.phone or "",
            c.plan or "",
            c.weekly_sessions or 0,
            c.created_at.strftime("%Y-%m-%d %H:%M:%S") if c.created_at else "",
        ]
        for c in clients
    ]
    return csv_download_response(
        "clients_export.csv",
        ["id", "name", "phone", "plan", "weekly_sessions", "created_at"],
        rows,
    )


@app.route("/export/sessions.csv")
@login_required
def export_sessions_csv():
    if not is_admin():
        return "Forbidden", 403

    clients = {c.id: c.name for c in Client.query.all()}
    sessions = SessionLog.query.order_by(SessionLog.date.desc()).all()
    log_security_event("export_sessions_csv", f"rows={len(sessions)}")
    rows = [
        [
            s.id,
            s.client_id,
            clients.get(s.client_id, ""),
            s.date.strftime("%Y-%m-%d %H:%M:%S") if s.date else "",
            s.note or "",
        ]
        for s in sessions
    ]
    return csv_download_response(
        "sessions_export.csv",
        ["id", "client_id", "client_name", "date", "note"],
        rows,
    )


@app.route("/export/payments.csv")
@login_required
def export_payments_csv():
    if not is_admin():
        return "Forbidden", 403

    clients = {c.id: c.name for c in Client.query.all()}
    payments = Payment.query.order_by(Payment.start_date.desc()).all()
    log_security_event("export_payments_csv", f"rows={len(payments)}")
    rows = []
    for p in payments:
        due = add_months(p.start_date, p.months)
        rows.append([
            p.id,
            p.client_id,
            clients.get(p.client_id, ""),
            p.start_date.strftime("%Y-%m-%d") if p.start_date else "",
            p.months,
            p.sessions_per_week,
            p.monthly_price,
            p.amount_paid,
            due.strftime("%Y-%m-%d"),
            p.note or "",
            p.paid_on.strftime("%Y-%m-%d %H:%M:%S") if p.paid_on else "",
        ])

    return csv_download_response(
        "payments_export.csv",
        [
            "id",
            "client_id",
            "client_name",
            "start_date",
            "months",
            "sessions_per_week",
            "monthly_price",
            "amount_paid",
            "due_date",
            "note",
            "paid_on",
        ],
        rows,
    )


@app.route("/backup/database")
@login_required
def backup_database():
    if not is_admin():
        return "Forbidden", 403

    db_file_path = resolve_db_file_path()
    if not db_file_path:
        return "Database file not found.", 404

    log_security_event("backup_database", f"path={db_file_path}")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return send_file(
        db_file_path,
        as_attachment=True,
        download_name=f"trainer_backup_{timestamp}.db",
        mimetype="application/octet-stream",
    )


@app.route("/client/<int:client_id>/report.pdf")
@login_required
def export_client_report_pdf(client_id):
    if not is_admin() and current_client_id() != client_id:
        return "Forbidden", 403

    client = get_or_404(Client, client_id)
    sessions_per_week_from_payments, current_status = get_current_plan(client.id)
    sessions_per_week = (
        sessions_per_week_from_payments
        if sessions_per_week_from_payments is not None
        else (client.weekly_sessions or 0)
    )
    used_this_week, remaining, bonus, allowed = compute_sessions(client, sessions_per_week)

    latest_weight = (
        Measurement.query.filter_by(client_id=client.id)
        .filter(Measurement.weight.isnot(None))
        .order_by(Measurement.date.desc())
        .first()
    )
    total_sessions = SessionLog.query.filter_by(client_id=client.id).count()

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except Exception:
        return "PDF export requires reportlab package.", 500

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y = height - 40

    def line(text, dy=20):
        nonlocal y
        c.drawString(40, y, text)
        y -= dy
        if y < 60:
            c.showPage()
            y = height - 40

    c.setFont("Helvetica-Bold", 15)
    line(f"Client Report - {client.name}", 26)
    c.setFont("Helvetica", 11)
    line(f"Phone: {client.phone or '-'}")
    line(f"Plan: {client.plan or '-'}")
    line(f"Sessions/week: {sessions_per_week} | Used this week: {used_this_week}/{allowed} | Remaining: {remaining}")
    line(f"Total sessions logged: {total_sessions}")
    if latest_weight:
        line(f"Latest weight: {latest_weight.weight} kg ({latest_weight.date.strftime('%d/%m/%Y')})")
    else:
        line("Latest weight: -")

    if current_status:
        line(
            f"Payment status: paid {current_status['amount_paid']} MKD | start {current_status['start_date'].strftime('%d/%m/%Y')} | due {current_status['paid_until'].strftime('%d/%m/%Y')} | days left {current_status['days_left']}"
        )
    else:
        line("Payment status: no active payment")

    notes = (
        ClientNote.query.filter_by(client_id=client.id)
        .order_by(ClientNote.created_at.desc())
        .limit(8)
        .all()
    )
    line("Recent notes:", 24)
    for n in notes:
        privacy = "Private" if n.is_private else "Shared"
        line(f"- [{privacy}] {n.created_at.strftime('%d/%m/%Y %H:%M')} - {n.text}", 16)

    c.save()
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"client_report_{client.id}.pdf",
        mimetype="application/pdf",
    )


# =========================
# Admin: Add/Delete Client
# =========================
@app.route("/admin/change-credentials", methods=["POST"])
@login_required
def change_admin_credentials():
    if not is_admin():
        return "Forbidden", 403

    admin_user = User.query.filter_by(id=session.get("user_id"), role="admin").first()
    if not admin_user:
        return redirect(url_for("index", err="Admin user not found."))

    current_password = request.form.get("current_password") or ""
    new_username = (request.form.get("new_username") or "").strip()
    new_password = request.form.get("new_password") or ""
    confirm_password = request.form.get("confirm_password") or ""

    if not check_password_hash(admin_user.password_hash, current_password):
        return redirect(url_for("index", err="Current password is incorrect."))

    if not new_username:
        return redirect(url_for("index", err="New username is required."))
    if len(new_username) > 80:
        return redirect(url_for("index", err="Username is too long."))
    if not re.fullmatch(r"[A-Za-z0-9._-]+", new_username):
        return redirect(url_for("index", err="Username can only contain letters, numbers, dot, underscore, and hyphen."))

    existing_username = User.query.filter_by(username=new_username).first()
    if existing_username and existing_username.id != admin_user.id:
        return redirect(url_for("index", err="Username is already taken."))

    changing_password = bool(new_password or confirm_password)
    if changing_password:
        if len(new_password) < 6:
            return redirect(url_for("index", err="New password must be at least 6 characters."))
        if new_password != confirm_password:
            return redirect(url_for("index", err="New password and confirmation do not match."))
        admin_user.password_hash = generate_password_hash(new_password)

    admin_user.username = new_username
    db.session.commit()

    return redirect(url_for("index", msg="Admin credentials updated."))


@app.route("/add", methods=["POST"])
@login_required
def add_client():
    if not is_admin():
        return "Forbidden", 403

    name = request.form["name"].strip()
    phone = parse_phone(request.form.get("phone", ""))
    if phone is None:
        return redirect(url_for("index", err="Phone can contain only digits and an optional leading +."))
    plan = request.form.get("plan", "").strip()

    new_client = Client(name=name, phone=phone, plan=plan, weekly_sessions=0)
    db.session.add(new_client)
    db.session.commit()
    return redirect(url_for("index"))


@app.route("/delete/<int:client_id>", methods=["POST"])
@login_required
def delete_client(client_id):
    if not is_admin():
        return "Forbidden", 403

    client = get_or_404(Client, client_id)
    db.session.delete(client)
    db.session.commit()
    return redirect(url_for("index"))


# =========================
# Client updates
# =========================
@app.route("/client/<int:client_id>/update-admin", methods=["POST"])
@login_required
def update_client_admin(client_id):
    if not is_admin():
        return "Forbidden", 403

    client = get_or_404(Client, client_id)
    client.name = request.form.get("name", client.name).strip()
    phone = parse_phone(request.form.get("phone", client.phone or ""))
    if phone is None:
        return redirect(url_for("client_profile", client_id=client.id, tab="info", err="Phone can contain only digits and an optional leading +."))
    client.phone = phone
    client.plan = request.form.get("plan", client.plan or "").strip()
    client.weekly_sessions = to_int(request.form.get("weekly"), default=0)

    db.session.commit()
    return redirect(url_for("client_profile", client_id=client.id, tab="info", msg="Saved"))


@app.route("/client/<int:client_id>/update-phone", methods=["POST"])
@login_required
def update_client_phone(client_id):
    # client can only update own phone, admin can update any
    if not is_admin() and current_client_id() != client_id:
        return "Forbidden", 403

    client = get_or_404(Client, client_id)
    phone = parse_phone(request.form.get("phone"))
    if phone is None:
        return redirect(url_for("client_profile", client_id=client.id, tab="info", err="Phone can contain only digits and an optional leading +."))
    client.phone = phone
    db.session.commit()
    return redirect(url_for("client_profile", client_id=client.id, tab="info", msg="Phone updated"))


@app.route("/client/<int:client_id>/update", methods=["POST"], endpoint="update_client")
@login_required
def update_client_alias(client_id):
    # Backwards compatible endpoint name.
    # Admin can update everything, clients only phone.
    if is_admin():
        return update_client_admin(client_id)
    return update_client_phone(client_id)


@app.route("/client/<int:client_id>/notes/add", methods=["POST"])
@login_required
def add_client_note(client_id):
    if not is_admin() and current_client_id() != client_id:
        return "Forbidden", 403

    client = get_or_404(Client, client_id)
    text = (request.form.get("text") or "").strip()
    is_private = truthy(request.form.get("is_private", "0"))
    if not text:
        return redirect(url_for("client_profile", client_id=client.id, tab="info", err="Note cannot be empty."))
    if len(text) > 500:
        return redirect(url_for("client_profile", client_id=client.id, tab="info", err="Note is too long (max 500 chars)."))
    if not is_admin():
        is_private = False

    note = ClientNote(
        client_id=client.id,
        text=text,
        is_private=is_private,
        created_by_role="admin" if is_admin() else "client",
    )
    db.session.add(note)
    db.session.commit()
    return redirect(url_for("client_profile", client_id=client.id, tab="info", msg="Note added."))


@app.route("/client/<int:client_id>/notes/delete/<int:note_id>", methods=["POST"])
@login_required
def delete_client_note(client_id, note_id):
    if not is_admin():
        return "Forbidden", 403
    note = get_or_404(ClientNote, note_id)
    if note.client_id != client_id:
        abort(404)
    db.session.delete(note)
    db.session.commit()
    return redirect(url_for("client_profile", client_id=client_id, tab="info", msg="Note deleted."))


@app.route("/client/<int:client_id>/goals/add", methods=["POST"])
@login_required
def add_client_goal(client_id):
    if not is_admin():
        return "Forbidden", 403
    client = get_or_404(Client, client_id)
    title = (request.form.get("title") or "").strip()
    if not title:
        return redirect(url_for("client_profile", client_id=client.id, tab="info", err="Goal title is required."))
    target_value = to_float(request.form.get("target_value"))
    current_value = to_float(request.form.get("current_value"))
    target_date = None
    target_date_raw = (request.form.get("target_date") or "").strip()
    if target_date_raw:
        try:
            target_date = datetime.strptime(target_date_raw, "%Y-%m-%d").date()
        except Exception:
            return redirect(url_for("client_profile", client_id=client.id, tab="info", err="Invalid goal target date."))
    note = (request.form.get("note") or "").strip()
    if current_value is None:
        temp_goal = ClientGoal(title=title, note=note)
        if is_weight_goal(temp_goal):
            current_value = get_latest_weight_value(client.id)
    g = ClientGoal(
        client_id=client.id,
        title=title,
        target_value=target_value,
        current_value=current_value,
        target_date=target_date,
        status="active",
        note=note,
    )
    db.session.add(g)
    db.session.commit()
    return redirect(url_for("client_profile", client_id=client.id, tab="info", msg="Goal added."))


@app.route("/client/<int:client_id>/goals/update/<int:goal_id>", methods=["POST"])
@login_required
def update_client_goal(client_id, goal_id):
    if not is_admin():
        return "Forbidden", 403
    g = get_or_404(ClientGoal, goal_id)
    if g.client_id != client_id:
        abort(404)
    g.current_value = to_float(request.form.get("current_value"))
    status = (request.form.get("status") or "active").strip().lower()
    if status not in ("active", "completed", "paused"):
        status = "active"
    g.status = status
    g.note = (request.form.get("note") or "").strip()
    db.session.commit()
    return redirect(url_for("client_profile", client_id=client_id, tab="info", msg="Goal updated."))


@app.route("/client/<int:client_id>/goals/delete/<int:goal_id>", methods=["POST"])
@login_required
def delete_client_goal(client_id, goal_id):
    if not is_admin():
        return "Forbidden", 403
    g = get_or_404(ClientGoal, goal_id)
    if g.client_id != client_id:
        abort(404)
    db.session.delete(g)
    db.session.commit()
    return redirect(url_for("client_profile", client_id=client_id, tab="info", msg="Goal deleted."))


@app.route("/client/<int:client_id>/change-password", methods=["POST"], endpoint="change_client_password")
@login_required
def change_client_password(client_id):
    # self-service for client accounts only
    if is_admin():
        return "Forbidden", 403
    if current_client_id() != client_id:
        return "Forbidden", 403

    user = User.query.filter_by(
        id=session.get("user_id"),
        role="client",
        client_id=client_id
    ).first()
    if not user:
        return redirect(url_for("client_profile", client_id=client_id, tab="info", err="Client user not found."))

    current_password = request.form.get("current_password") or ""
    new_password = request.form.get("new_password") or ""
    confirm_password = request.form.get("confirm_password") or ""

    if not current_password or not new_password or not confirm_password:
        return redirect(url_for("client_profile", client_id=client_id, tab="info", err="All password fields are required."))

    if not check_password_hash(user.password_hash, current_password):
        return redirect(url_for("client_profile", client_id=client_id, tab="info", err="Current password is incorrect."))

    if len(new_password) < 6:
        return redirect(url_for("client_profile", client_id=client_id, tab="info", err="New password must be at least 6 characters."))

    if new_password != confirm_password:
        return redirect(url_for("client_profile", client_id=client_id, tab="info", err="New password and confirmation do not match."))

    user.password_hash = generate_password_hash(new_password)
    user.must_change_password = False
    db.session.commit()

    return redirect(url_for("client_profile", client_id=client_id, tab="info", msg="Password updated."))



# =========================
# Stats
# =========================
@app.route("/client/<int:client_id>/stats/add", methods=["POST"], endpoint="add_measurement")
@login_required
def add_measurement(client_id):
    # client can add stats to self, admin can add to any
    if not is_admin() and current_client_id() != client_id:
        return "Forbidden", 403

    client = get_or_404(Client, client_id)

    parsed_values, err = parse_measurement_form(request.form)
    if err:
        return redirect(url_for("client_profile", client_id=client.id, tab="stats", err=err))

    m = Measurement(client_id=client.id, **parsed_values)

    db.session.add(m)
    db.session.commit()
    updated_goals = 0
    if parsed_values.get("weight") is not None:
        updated_goals = sync_weight_goal_progress(client.id)
        if updated_goals:
            db.session.commit()

    msg = "Measurement saved."
    if updated_goals:
        msg += f" Goal progress updated ({updated_goals})."
    return redirect(url_for("client_profile", client_id=client.id, tab="stats", msg=msg))


@app.route("/client/<int:client_id>/stats/update/<int:measurement_id>", methods=["POST"], endpoint="update_measurement")
@login_required
def update_measurement(client_id, measurement_id):
    if not is_admin() and current_client_id() != client_id:
        return "Forbidden", 403

    client = get_or_404(Client, client_id)
    m = get_or_404(Measurement, measurement_id)
    if m.client_id != client.id:
        abort(404)

    parsed_values, err = parse_measurement_form(request.form)
    if err:
        return redirect(url_for("client_profile", client_id=client.id, tab="stats", err=err))

    for field, value in parsed_values.items():
        setattr(m, field, value)

    db.session.commit()
    updated_goals = 0
    if parsed_values.get("weight") is not None:
        updated_goals = sync_weight_goal_progress(client.id)
        if updated_goals:
            db.session.commit()

    msg = "Measurement updated."
    if updated_goals:
        msg += f" Goal progress updated ({updated_goals})."
    return redirect(url_for("client_profile", client_id=client.id, tab="stats", msg=msg))


@app.route("/client/<int:client_id>/stats/delete/<int:measurement_id>", methods=["POST"], endpoint="delete_measurement")
@login_required
def delete_measurement(client_id, measurement_id):
    if not is_admin():
        return "Forbidden", 403

    m = get_or_404(Measurement, measurement_id)
    if m.client_id != client_id:
        abort(404)
    db.session.delete(m)
    db.session.commit()
    return redirect(url_for("client_profile", client_id=client_id, tab="stats"))


@app.route("/client/<int:client_id>/photos/upload", methods=["POST"])
@login_required
def upload_progress_photo(client_id):
    if not is_admin() and current_client_id() != client_id:
        return "Forbidden", 403
    client = get_or_404(Client, client_id)
    f = request.files.get("photo")
    if not f or not f.filename:
        return redirect(url_for("client_profile", client_id=client.id, tab="stats", err="Please choose a photo file."))
    if not allowed_photo_file(f.filename):
        return redirect(url_for("client_profile", client_id=client.id, tab="stats", err="Allowed formats: .jpg, .jpeg, .png, .webp"))
    ext = os.path.splitext(f.filename)[1].lower()
    safe_name = secure_filename(f.filename)
    unique_name = f"{client.id}_{uuid.uuid4().hex}_{safe_name}"
    if ext and not unique_name.lower().endswith(ext):
        unique_name += ext
    target_path = os.path.join(app.config["UPLOAD_PROGRESS_DIR"], unique_name)
    f.save(target_path)
    note = (request.form.get("note") or "").strip()
    p = ProgressPhoto(
        client_id=client.id,
        file_name=unique_name,
        note=note,
        uploaded_by_role="admin" if is_admin() else "client",
    )
    db.session.add(p)
    db.session.commit()
    return redirect(url_for("client_profile", client_id=client.id, tab="stats", msg="Photo uploaded."))


@app.route("/client/<int:client_id>/photos/delete/<int:photo_id>", methods=["POST"])
@login_required
def delete_progress_photo(client_id, photo_id):
    if not is_admin() and current_client_id() != client_id:
        return "Forbidden", 403
    photo = get_or_404(ProgressPhoto, photo_id)
    if photo.client_id != client_id:
        abort(404)
    if not is_admin() and photo.uploaded_by_role != "client":
        return "Forbidden", 403
    path = os.path.join(app.config["UPLOAD_PROGRESS_DIR"], photo.file_name)
    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass
    db.session.delete(photo)
    db.session.commit()
    return redirect(url_for("client_profile", client_id=client_id, tab="stats", msg="Photo deleted."))


# =========================
# Sessions
# =========================
@app.route("/client/<int:client_id>/appointments/add", methods=["POST"])
@login_required
def add_appointment(client_id):
    if not is_admin() and current_client_id() != client_id:
        return "Forbidden", 403
    client = get_or_404(Client, client_id)
    dt = parse_datetime_local(request.form.get("scheduled_for"))
    if not dt:
        return redirect(url_for("client_profile", client_id=client.id, tab="sessions", err="Invalid appointment date/time."))
    note = (request.form.get("note") or "").strip()
    a = Appointment(
        client_id=client.id,
        scheduled_for=dt,
        status="requested",
        note=note,
        created_by_role="admin" if is_admin() else "client",
    )
    db.session.add(a)
    db.session.commit()
    return redirect(url_for("client_profile", client_id=client.id, tab="sessions", msg="Appointment saved."))


@app.route("/client/<int:client_id>/appointments/respond/<int:appointment_id>", methods=["POST"])
@login_required
def respond_appointment(client_id, appointment_id):
    if is_admin() or current_client_id() != client_id:
        return "Forbidden", 403

    a = get_or_404(Appointment, appointment_id)
    if a.client_id != client_id:
        abort(404)

    status = (request.form.get("status") or "").strip().lower()
    if status not in ("confirmed", "cancelled"):
        return redirect(url_for("client_profile", client_id=client_id, tab="info", err="Invalid appointment response."))
    if a.status != "requested":
        return redirect(url_for("client_profile", client_id=client_id, tab="info", err="Appointment is not awaiting response."))

    cancel_reason = (request.form.get("cancel_reason") or "").strip()
    if status == "cancelled":
        if not cancel_reason:
            return redirect(url_for("client_profile", client_id=client_id, tab="info", err="Please provide a cancellation reason."))
        reason_note = f"Client cancellation reason: {cancel_reason}"
        if a.note:
            a.note = f"{a.note} | {reason_note}"
        else:
            a.note = reason_note

    a.status = status
    db.session.commit()
    return redirect(url_for("client_profile", client_id=client_id, tab="info", msg=f"Appointment {status}."))


@app.route("/client/<int:client_id>/appointments/status/<int:appointment_id>", methods=["POST"])
@login_required
def update_appointment_status(client_id, appointment_id):
    if not is_admin():
        return "Forbidden", 403
    a = get_or_404(Appointment, appointment_id)
    if a.client_id != client_id:
        abort(404)
    status = (request.form.get("status") or "").strip().lower()
    if status not in ("requested", "confirmed", "completed", "cancelled"):
        return redirect(url_for("client_profile", client_id=client_id, tab="sessions", err="Invalid appointment status."))
    a.status = status
    db.session.commit()
    return redirect(url_for("client_profile", client_id=client_id, tab="sessions", msg="Appointment status updated."))


@app.route("/client/<int:client_id>/appointments/delete/<int:appointment_id>", methods=["POST"])
@login_required
def delete_appointment(client_id, appointment_id):
    if not is_admin():
        return "Forbidden", 403
    a = get_or_404(Appointment, appointment_id)
    if a.client_id != client_id:
        abort(404)
    db.session.delete(a)
    db.session.commit()
    return redirect(url_for("client_profile", client_id=client_id, tab="sessions", msg="Appointment deleted."))


@app.route("/client/<int:client_id>/sessions/add", methods=["POST"], endpoint="add_session")
@login_required
def add_session(client_id):
    # client can add sessions to self, admin can add to any
    if not is_admin() and current_client_id() != client_id:
        return "Forbidden", 403

    client = get_or_404(Client, client_id)

    sessions_per_week_from_payments, _status = get_current_plan(client.id)
    sessions_per_week = (
        sessions_per_week_from_payments
        if sessions_per_week_from_payments is not None
        else (client.weekly_sessions or 0)
    )

    session_date_raw = (request.form.get("session_date") or "").strip()
    session_day = parse_iso_date(session_date_raw) if session_date_raw else date.today()
    if not session_day:
        return redirect(url_for(
            "client_profile",
            client_id=client.id,
            tab="sessions",
            err="Invalid session date."
        ))
    if session_day > date.today():
        return redirect(url_for(
            "client_profile",
            client_id=client.id,
            tab="sessions",
            err="Session date cannot be in the future."
        ))

    target_week_start = week_start(session_day)
    used_this_week = (
        SessionLog.query.filter_by(client_id=client.id)
        .filter(SessionLog.date >= datetime(target_week_start.year, target_week_start.month, target_week_start.day))
        .filter(SessionLog.date < datetime(target_week_start.year, target_week_start.month, target_week_start.day) + timedelta(days=7))
        .count()
    )
    bonus = 0
    if client.rollover_for_week == target_week_start and (client.rollover_bonus or 0) > 0:
        bonus = client.rollover_bonus
    allowed = max((sessions_per_week or 0) + bonus, 0)
    remaining = max(allowed - used_this_week, 0)

    if remaining <= 0:
        return redirect(url_for(
            "client_profile",
            client_id=client.id,
            tab="sessions",
            err=f"Weekly limit reached for week of {target_week_start.strftime('%d/%m/%Y')} ({used_this_week}/{allowed})."
        ))

    note = (request.form.get("note") or "").strip()
    session_dt = datetime(session_day.year, session_day.month, session_day.day, 12, 0, 0)
    s = SessionLog(client_id=client.id, note=note, date=session_dt)
    db.session.add(s)
    db.session.commit()

    return redirect(
        url_for(
            "client_profile",
            client_id=client.id,
            tab="sessions",
            msg=f"Session logged for {session_day.strftime('%d/%m/%Y')}"
        )
    )


@app.route("/client/<int:client_id>/sessions/delete/<int:session_id>", methods=["POST"], endpoint="delete_session")
@login_required
def delete_session(client_id, session_id):
    if not is_admin():
        return "Forbidden", 403

    s = get_or_404(SessionLog, session_id)
    if s.client_id != client_id:
        abort(404)
    db.session.delete(s)
    db.session.commit()
    return redirect(url_for("client_profile", client_id=client_id, tab="sessions"))


@app.route("/client/<int:client_id>/sessions/transfer", methods=["POST"], endpoint="transfer_sessions")
@login_required
def transfer_sessions(client_id):
    # trainer action only (admin)
    if not is_admin():
        return "Forbidden", 403

    client = get_or_404(Client, client_id)

    sessions_per_week_from_payments, _status = get_current_plan(client.id)
    sessions_per_week = (
        sessions_per_week_from_payments
        if sessions_per_week_from_payments is not None
        else (client.weekly_sessions or 0)
    )

    today = date.today()
    ws = week_start(today)

    if client.last_transfer_week == ws:
        return redirect(url_for(
            "client_profile", client_id=client.id, tab="sessions",
            err="Transfer already done for this week."
        ))

    used_this_week, remaining, bonus, allowed = compute_sessions(client, sessions_per_week)

    # remaining is what can be transferred
    transfer_amount = remaining

    # apply bonus to NEXT week
    next_week = ws + timedelta(days=7)
    client.rollover_bonus = transfer_amount
    client.rollover_for_week = next_week
    client.last_transfer_week = ws

    db.session.commit()

    return redirect(url_for(
        "client_profile", client_id=client.id, tab="sessions",
        msg=f"Transferred {transfer_amount} unused session(s) to next week."
    ))


# =========================
# Payments
# =========================
@app.route("/client/<int:client_id>/payments/add", methods=["POST"], endpoint="add_payment")
@login_required
def add_payment(client_id):
    if not is_admin():
        return "Forbidden", 403

    client = get_or_404(Client, client_id)

    start = parse_ddmmyyyy(request.form.get("start_date"))
    if not start:
        return redirect(url_for("client_profile", client_id=client.id, tab="payments", err="Invalid start date. Use DD/MM/YYYY."))

    amount_paid = to_int(request.form.get("amount_paid"), default=0)
    note = (request.form.get("note") or "").strip()

    if amount_paid <= 0:
        return redirect(url_for("client_profile", client_id=client.id, tab="payments", err="Enter a valid amount."))

    # Rules:
    # 5000 => 1 month, 3/week
    # 7000 => 1 month, 5/week
    if amount_paid % 5000 == 0 and amount_paid % 7000 != 0:
        monthly_price = 5000
        sessions_per_week = 3
        months = amount_paid // 5000
    elif amount_paid % 7000 == 0 and amount_paid % 5000 != 0:
        monthly_price = 7000
        sessions_per_week = 5
        months = amount_paid // 7000
    elif amount_paid % 5000 == 0 and amount_paid % 7000 == 0:
        # if divisible by both (e.g. 35000), prefer 7000 plan by default
        monthly_price = 7000
        sessions_per_week = 5
        months = amount_paid // 7000
    else:
        return redirect(url_for(
            "client_profile", client_id=client.id, tab="payments",
            err=f"Amount must be divisible by 5000 or 7000. (Received: {amount_paid})"
        ))

    p = Payment(
        client_id=client.id,
        start_date=start,
        months=months,
        monthly_price=monthly_price,
        sessions_per_week=sessions_per_week,
        amount_paid=amount_paid,
        note=note
    )

    db.session.add(p)
    db.session.commit()

    return redirect(url_for("client_profile", client_id=client.id, tab="payments", msg="Payment saved"))


@app.route("/client/<int:client_id>/payments/delete/<int:payment_id>", methods=["POST"], endpoint="delete_payment")
@login_required
def delete_payment(client_id, payment_id):
    if not is_admin():
        return "Forbidden", 403

    p = get_or_404(Payment, payment_id)
    if p.client_id != client_id:
        abort(404)
    db.session.delete(p)
    db.session.commit()
    return redirect(url_for("client_profile", client_id=client_id, tab="payments"))


# =========================
# Admin: Create client login
# =========================
@app.route("/client/<int:client_id>/create-login", methods=["POST"], endpoint="create_client_login")
@login_required
def create_client_login(client_id):
    if not is_admin():
        return "Forbidden", 403

    client = get_or_404(Client, client_id)
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if not username or not password:
        return redirect(url_for("client_profile", client_id=client.id, tab="info", err="Username and password required."))

    if User.query.filter_by(username=username).first():
        return redirect(url_for("client_profile", client_id=client.id, tab="info", err="Username already taken."))
    if User.query.filter_by(client_id=client.id).filter(User.role != "admin").first():
        return redirect(url_for("client_profile", client_id=client.id, tab="info", err="Client login already exists. Use reset/deactivate tools."))

    u = User(
        username=username,
        password_hash=generate_password_hash(password),
        role="client",
        client_id=client.id,
        must_change_password=True,
    )
    db.session.add(u)
    db.session.commit()

    return redirect(url_for("client_profile", client_id=client.id, tab="info", msg="Client login created."))


@app.route("/client/<int:client_id>/login/reset-password", methods=["POST"], endpoint="admin_reset_client_password")
@login_required
def admin_reset_client_password(client_id):
    if not is_admin():
        return "Forbidden", 403

    client = get_or_404(Client, client_id)
    user = (
        User.query
        .filter_by(client_id=client.id)
        .filter(User.role != "admin")
        .order_by(User.id.desc())
        .first()
    )
    if not user:
        return redirect(url_for("client_profile", client_id=client.id, tab="info", err="Client login does not exist yet."))

    new_password = request.form.get("new_password") or ""
    if len(new_password) < 6:
        return redirect(url_for("client_profile", client_id=client.id, tab="info", err="Temporary password must be at least 6 characters."))

    user.password_hash = generate_password_hash(new_password)
    user.must_change_password = True
    db.session.commit()
    return redirect(url_for("client_profile", client_id=client.id, tab="info", msg="Client password reset."))


@app.route("/client/<int:client_id>/login/deactivate", methods=["POST"], endpoint="deactivate_client_login")
@login_required
def deactivate_client_login(client_id):
    if not is_admin():
        return "Forbidden", 403

    client = get_or_404(Client, client_id)
    user = (
        User.query
        .filter_by(client_id=client.id)
        .filter(User.role != "admin")
        .order_by(User.id.desc())
        .first()
    )
    if not user:
        return redirect(url_for("client_profile", client_id=client.id, tab="info", err="Client login does not exist yet."))
    if user.role == "disabled":
        return redirect(url_for("client_profile", client_id=client.id, tab="info", msg="Client login is already deactivated."))

    user.role = "disabled"
    db.session.commit()
    return redirect(url_for("client_profile", client_id=client.id, tab="info", msg="Client login deactivated."))


@app.route("/client/<int:client_id>/login/reactivate", methods=["POST"], endpoint="reactivate_client_login")
@login_required
def reactivate_client_login(client_id):
    if not is_admin():
        return "Forbidden", 403

    client = get_or_404(Client, client_id)
    user = (
        User.query
        .filter_by(client_id=client.id)
        .filter(User.role != "admin")
        .order_by(User.id.desc())
        .first()
    )
    if not user:
        return redirect(url_for("client_profile", client_id=client.id, tab="info", err="Client login does not exist yet."))
    if user.role != "disabled":
        return redirect(url_for("client_profile", client_id=client.id, tab="info", msg="Client login is already active."))

    user.role = "client"
    db.session.commit()
    return redirect(url_for("client_profile", client_id=client.id, tab="info", msg="Client login reactivated."))


# =========================
# Debug
# =========================
@app.route("/routes")
@login_required
def show_routes():
    if not is_admin():
        return "Forbidden", 403
    return "<br>".join(sorted([f"{r.endpoint} -> {r.rule}" for r in app.url_map.iter_rules()]))


@app.route("/ping")
def ping():
    return "PING OK"


# =========================
# Start
# =========================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        seed_admin()

    debug_mode = truthy(os.environ.get("FLASK_DEBUG", "0")) and not IS_PROD
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=host, port=port, debug=debug_mode, use_reloader=debug_mode)
