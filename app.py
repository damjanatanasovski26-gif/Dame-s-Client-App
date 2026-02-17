from flask import Flask, render_template, request, redirect, url_for, session, Response, send_file, abort
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
import click
from datetime import datetime, date, timedelta, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
import csv
import hmac
import io
import json
import os
import secrets
import threading
import time
import re

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
app.config["FORCE_HTTPS"] = (
    os.environ.get("FORCE_HTTPS", "1" if IS_PROD else "0").lower() in ("1", "true", "yes", "on")
)
app.config["ENABLE_SECURITY_HEADERS"] = True
app.config["LOGIN_MAX_ATTEMPTS"] = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "5"))
app.config["LOGIN_WINDOW_SECONDS"] = int(os.environ.get("LOGIN_WINDOW_SECONDS", "300"))
app.config["LOGIN_LOCK_SECONDS"] = int(os.environ.get("LOGIN_LOCK_SECONDS", "600"))

if os.environ.get("TRUST_PROXY", "1").lower() in ("1", "true", "yes", "on"):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
failed_login_state = {}
failed_login_lock = threading.Lock()


def utc_now():
    return datetime.now(timezone.utc)


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


def login_throttle_key(username: str):
    return f"{(request.remote_addr or 'unknown').strip()}::{(username or '').strip().lower()}"


def login_throttle_status(key: str):
    now = time.time()
    with failed_login_lock:
        state = failed_login_state.get(key)
        if not state:
            return False, 0
        lock_until = state.get("lock_until", 0)
        if lock_until > now:
            return True, int(lock_until - now)
        if now - state.get("first_ts", now) > app.config["LOGIN_WINDOW_SECONDS"]:
            failed_login_state.pop(key, None)
    return False, 0


def login_throttle_failed(key: str):
    now = time.time()
    with failed_login_lock:
        state = failed_login_state.get(key)
        if not state or now - state.get("first_ts", now) > app.config["LOGIN_WINDOW_SECONDS"]:
            state = {"count": 0, "first_ts": now, "lock_until": 0}
            failed_login_state[key] = state
        state["count"] += 1
        if state["count"] >= app.config["LOGIN_MAX_ATTEMPTS"]:
            state["lock_until"] = now + app.config["LOGIN_LOCK_SECONDS"]


def login_throttle_success(key: str):
    with failed_login_lock:
        failed_login_state.pop(key, None)


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": get_csrf_token}


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


def to_int(value, default=0):
    value = (value or "").strip()
    if value == "":
        return default
    try:
        return int(value)
    except ValueError:
        return default


def parse_phone(value):
    phone = (value or "").strip()
    if phone == "":
        return ""
    if not re.fullmatch(r"\+?\d+", phone):
        return None
    return phone


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
        .order_by(Payment.start_date.desc())
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


# =========================
# Auth Routes
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", err=None)

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    throttle_key = login_throttle_key(username)
    locked, seconds_left = login_throttle_status(throttle_key)
    if locked:
        return render_template("login.html", err=f"Too many attempts. Try again in {seconds_left}s.")

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        login_throttle_failed(throttle_key)
        return render_template("login.html", err="Invalid username or password.")
    if user.role == "disabled":
        login_throttle_failed(throttle_key)
        return render_template("login.html", err="Account is deactivated. Please contact your coach.")
    login_throttle_success(throttle_key)

    session["user_id"] = user.id
    session["role"] = user.role
    session["client_id"] = user.client_id

    if user.role == "admin":
        return redirect(url_for("index"))
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
    err = request.args.get("err")
    msg = request.args.get("msg")
    return render_template("index.html", clients=clients, err=err, msg=msg)


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
    # Keep client navigation on allowed tabs only.
    if not is_admin() and tab == "payments":
        return redirect(url_for("client_profile", client_id=client.id, tab="info"))

    # Stats
    measurements = (
        Measurement.query.filter_by(client_id=client.id)
        .order_by(Measurement.date.desc())
        .all()
    )
    latest = measurements[0] if measurements else None

    # Weight graph data (only weight)
    weight_points = (
        Measurement.query.filter_by(client_id=client.id)
        .filter(Measurement.weight.isnot(None))
        .order_by(Measurement.date.asc())
        .all()
    )
    weight_labels = [m.date.strftime("%d/%m") for m in weight_points]
    weight_values = [m.weight for m in weight_points]

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

    # Payments view
    payments = (
        Payment.query.filter_by(client_id=client.id)
        .order_by(Payment.start_date.desc())
        .all()
    )

    today = date.today()
    payments_view = []
    for p in payments:
        due = add_months(p.start_date, p.months)
        days_left = (due - today).days
        payments_view.append({"p": p, "due": due, "days_left": days_left})

    client_user = (
        User.query
        .filter_by(client_id=client.id)
        .filter(User.role != "admin")
        .order_by(User.id.desc())
        .first()
    )

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
        weight_labels=weight_labels,
        weight_values=weight_values,

        # sessions
        sessions=sessions,
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
        client_user=client_user,
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


# =========================
# Admin: Add/Delete Client
# =========================
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

    m = Measurement(
        client_id=client.id,
        weight=to_float(request.form.get("weight")),
        chest=to_float(request.form.get("chest")),
        waist=to_float(request.form.get("waist")),
        stomach=to_float(request.form.get("stomach")),
        glutes=to_float(request.form.get("glutes")),
        arm_left=to_float(request.form.get("arm_left")),
        arm_right=to_float(request.form.get("arm_right")),
        quad_left=to_float(request.form.get("quad_left")),
        quad_right=to_float(request.form.get("quad_right")),
        calf_left=to_float(request.form.get("calf_left")),
        calf_right=to_float(request.form.get("calf_right")),
    )

    db.session.add(m)
    db.session.commit()
    return redirect(url_for("client_profile", client_id=client.id, tab="stats"))


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


# =========================
# Sessions
# =========================
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

    used_this_week, remaining, bonus, allowed = compute_sessions(client, sessions_per_week)

    if remaining <= 0:
        return redirect(url_for(
            "client_profile",
            client_id=client.id,
            tab="sessions",
            err=f"Weekly limit reached ({used_this_week}/{allowed})."
        ))

    note = (request.form.get("note") or "").strip()
    s = SessionLog(client_id=client.id, note=note)
    db.session.add(s)
    db.session.commit()

    return redirect(url_for("client_profile", client_id=client.id, tab="sessions", msg="Session logged"))


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
        client_id=client.id
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
