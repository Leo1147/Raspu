import atexit
import calendar
import csv
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import shutil
import sqlite3
import tempfile
import threading
import time
import unicodedata
import uuid
import warnings
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from functools import wraps
from io import BytesIO
from pathlib import Path

from authlib.integrations.flask_client import OAuth
from authlib.jose import jwt
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, g, jsonify, redirect, request, send_file, send_from_directory, session
from PIL import Image, UnidentifiedImageError
import pytesseract
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    AuthenticationCredential,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)


BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "finance_app.db"
ENCRYPTION_KEY_PATH = DATA_DIR / ".encryption.key"
ALLOWED_EXTENSIONS = {
    "csv",
    "docx",
    "jpeg",
    "jpg",
    "pdf",
    "png",
    "txt",
    "xls",
    "xlsx",
}
MAX_UPLOAD_SIZE = 25 * 1024 * 1024
MAX_REQUEST_SIZE = MAX_UPLOAD_SIZE + 1024 * 1024
SESSION_LIFETIME = timedelta(days=7)
STORAGE_MARKER = b"FNC1"
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DOCUMENT_TYPES = {"factura", "recibo", "contrato", "estado_cuenta", "otro"}
EXPENSE_CATEGORIES = {
    "alimentacion",
    "transporte",
    "servicios",
    "salud",
    "compras",
    "vivienda",
    "educacion",
    "otros",
}
IMAGE_EXTENSIONS = {"jpeg", "jpg", "png"}
DATE_PATTERN = re.compile(
    r"\b(?P<day>\d{1,2})[./-](?P<month>\d{1,2})[./-](?P<year>\d{2,4})\b"
    r"|\b(?P<iso_year>20\d{2})-(?P<iso_month>\d{1,2})-(?P<iso_day>\d{1,2})\b"
)
AMOUNT_PATTERN = re.compile(
    r"(?<!\d)(?P<amount>(?:\d{1,3}(?:[., ]\d{3})+|\d+)(?:[.,]\d{2})?)(?!\d)"
)
TRANSACTION_TYPES = {"gasto", "costo"}
EXPENSE_NATURES = {"fijo", "variable"}
EXPENSE_CATEGORIES = {
    "renta",
    "servicios",
    "marketing",
    "administracion",
    "impuestos",
    "alimentacion",
    "transporte",
    "salud",
    "compras",
    "vivienda",
    "educacion",
    "otros",
}
TRANSACTION_EXPENSE_CATEGORIES = EXPENSE_CATEGORIES | {
    "seguros",
    "servicios_profesionales",
    "comisiones_bancarias",
    "suministros_oficina",
}
COST_TYPES = {"materia_prima", "mano_obra_directa", "adquisicion", "otros"}
RECURRENCE_FREQUENCIES = {"semanal", "mensual", "anual"}
BANK_IMPORT_MAX_BYTES = 5 * 1024 * 1024
RECURRENCE_INTERVAL_LIMIT = 24
RECURRENCE_CATCHUP_LIMIT = 1200
TRANSACTION_SOURCES = {"manual", "bank_csv", "recurring", "recibo"}
recurring_scheduler_started = False
recurring_scheduler_lock = threading.Lock()
recurring_scheduler_stop = threading.Event()

app = Flask(__name__)
app.config.update(
    MAX_CONTENT_LENGTH=MAX_REQUEST_SIZE,
    SECRET_KEY=os.environ.get("FINANCIA_SECRET_KEY") or secrets.token_urlsafe(48),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.environ.get("FINANCIA_COOKIE_SECURE") == "1"
        or os.environ.get("FLASK_ENV") == "production"
    ),
    PERMANENT_SESSION_LIFETIME=SESSION_LIFETIME,
)
if os.environ.get("FLASK_ENV") == "production":
    if not os.environ.get("FINANCIA_SECRET_KEY"):
        raise RuntimeError("FINANCIA_SECRET_KEY es obligatoria en producción.")
    if not os.environ.get("FINANCIA_ENCRYPTION_KEY"):
        raise RuntimeError("FINANCIA_ENCRYPTION_KEY es obligatoria en producción.")
UPLOAD_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)

oauth = OAuth(app)
oauth_providers = {}


def register_oauth_providers():
    google_id = os.environ.get("GOOGLE_CLIENT_ID")
    google_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
    if google_id and google_secret:
        oauth_providers["google"] = oauth.register(
            name="google",
            client_id=google_id,
            client_secret=google_secret,
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    apple_id = os.environ.get("APPLE_CLIENT_ID")
    apple_team_id = os.environ.get("APPLE_TEAM_ID")
    apple_key_id = os.environ.get("APPLE_KEY_ID")
    apple_private_key = os.environ.get("APPLE_PRIVATE_KEY", "").replace("\\n", "\n")
    if apple_id and apple_team_id and apple_key_id and apple_private_key:
        now = datetime.now(timezone.utc)
        client_secret = jwt.encode(
            {"alg": "ES256", "kid": apple_key_id},
            apple_private_key,
            {
                "iss": apple_team_id,
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(days=150)).timestamp()),
                "aud": "https://appleid.apple.com",
                "sub": apple_id,
            },
        ).decode("ascii")
        oauth_providers["apple"] = oauth.register(
            name="apple",
            client_id=apple_id,
            client_secret=client_secret,
            server_metadata_url="https://appleid.apple.com/.well-known/openid-configuration",
            token_endpoint_auth_method="client_secret_post",
            client_kwargs={"scope": "openid email"},
        )


register_oauth_providers()


def get_fernet():
    configured_key = os.environ.get("FINANCIA_ENCRYPTION_KEY")
    if configured_key:
        current_key = configured_key.encode("ascii")
        fallback_keys = []
        previous_key = os.environ.get("FINANCIA_PREVIOUS_ENCRYPTION_KEY")
        if previous_key:
            fallback_keys.append(previous_key.encode("ascii"))
        if ENCRYPTION_KEY_PATH.exists():
            fallback_keys.append(ENCRYPTION_KEY_PATH.read_bytes())
        fallback_keys = [key for key in fallback_keys if key != current_key]
        return Fernet(current_key), [Fernet(key) for key in dict.fromkeys(fallback_keys)]

    try:
        with ENCRYPTION_KEY_PATH.open("xb") as key_file:
            key_file.write(Fernet.generate_key())
    except FileExistsError:
        pass
    try:
        os.chmod(ENCRYPTION_KEY_PATH, 0o600)
    except OSError:
        app.logger.warning("No se pudieron restringir los permisos de la clave de cifrado local.")
    return Fernet(ENCRYPTION_KEY_PATH.read_bytes()), []


fernet, fallback_fernets = get_fernet()


@contextmanager
def get_db():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database():
    with get_db() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS user_sessions (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS oauth_identities (
                provider TEXT NOT NULL,
                subject TEXT NOT NULL,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                PRIMARY KEY (provider, subject)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS passkeys (
                credential_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                public_key TEXT NOT NULL,
                sign_count INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL UNIQUE,
                extension TEXT NOT NULL,
                size INTEGER NOT NULL,
                uploaded_at TEXT NOT NULL,
                owner_id TEXT REFERENCES users(id)
            )
            """
        )
        columns = {
            column["name"] for column in connection.execute("PRAGMA table_info(files)")
        }
        if "owner_id" not in columns:
            connection.execute("ALTER TABLE files ADD COLUMN owner_id TEXT")
        if "document_type" not in columns:
            connection.execute("ALTER TABLE files ADD COLUMN document_type TEXT NOT NULL DEFAULT 'otro'")
        if "ocr_status" not in columns:
            connection.execute("ALTER TABLE files ADD COLUMN ocr_status TEXT NOT NULL DEFAULT 'not_applicable'")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS expenses (
                id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                file_id TEXT NOT NULL UNIQUE REFERENCES files(id) ON DELETE CASCADE,
                amount REAL,
                expense_date TEXT,
                vendor TEXT,
                category TEXT NOT NULL DEFAULT 'otros',
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS recurring_transactions (
                id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                transaction_type TEXT NOT NULL CHECK (transaction_type IN ('gasto', 'costo')),
                amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
                category TEXT NOT NULL,
                nature TEXT,
                cost_type TEXT,
                vendor TEXT,
                description TEXT NOT NULL,
                frequency TEXT NOT NULL CHECK (frequency IN ('semanal', 'mensual', 'anual')),
                interval_count INTEGER NOT NULL DEFAULT 1 CHECK (interval_count BETWEEN 1 AND 24),
                start_date TEXT NOT NULL,
                next_run_date TEXT NOT NULL,
                occurrence_count INTEGER NOT NULL DEFAULT 0,
                active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS transactions (
                id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                transaction_type TEXT NOT NULL CHECK (transaction_type IN ('gasto', 'costo')),
                amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
                transaction_date TEXT NOT NULL,
                category TEXT NOT NULL,
                nature TEXT,
                cost_type TEXT,
                vendor TEXT,
                description TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'manual',
                external_id TEXT,
                file_id TEXT REFERENCES files(id) ON DELETE SET NULL,
                recurring_id TEXT REFERENCES recurring_transactions(id) ON DELETE SET NULL,
                created_at TEXT NOT NULL,
                UNIQUE (owner_id, external_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS budgets (
                id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                transaction_type TEXT NOT NULL CHECK (transaction_type IN ('gasto', 'costo')),
                category TEXT NOT NULL,
                limit_cents INTEGER NOT NULL CHECK (limit_cents > 0),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (owner_id, transaction_type, category)
            )
            """
        )
        expense_columns = {
            column["name"] for column in connection.execute("PRAGMA table_info(expenses)")
        }
        if "transaction_id" not in expense_columns:
            connection.execute("ALTER TABLE expenses ADD COLUMN transaction_id TEXT")
        connection.execute(
            """
            INSERT OR IGNORE INTO transactions (
                id, owner_id, transaction_type, amount_cents, transaction_date, category,
                nature, cost_type, vendor, description, source, external_id, file_id,
                created_at
            )
            SELECT 'receipt-' || e.id, e.owner_id, 'gasto',
                   CAST(ROUND(e.amount * 100) AS INTEGER), COALESCE(e.expense_date, DATE(e.created_at)),
                   CASE WHEN e.category IN (
                       'renta', 'servicios', 'marketing', 'administracion', 'impuestos',
                       'alimentacion', 'transporte', 'salud', 'compras', 'vivienda',
                       'educacion', 'otros'
                   ) THEN e.category ELSE 'otros' END,
                   'variable', NULL, e.vendor, 'Gasto asociado al recibo ' || f.original_name,
                   'recibo', 'legacy-receipt:' || e.id, e.file_id, e.created_at
            FROM expenses AS e
            LEFT JOIN files AS f ON f.id = e.file_id
            WHERE e.owner_id IS NOT NULL AND e.amount IS NOT NULL AND e.amount > 0
            """
        )
        connection.execute(
            """
            UPDATE expenses
            SET transaction_id = 'receipt-' || id
            WHERE transaction_id IS NULL
              AND EXISTS (
                  SELECT 1 FROM transactions
                  WHERE transactions.id = 'receipt-' || expenses.id
              )
            """
        )


def parse_transaction_date(value):
    if not isinstance(value, str):
        raise ValueError("La fecha debe usar el formato AAAA-MM-DD.")
    value = value.strip()
    for date_format in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%m/%d/%Y"):
        try:
            return datetime.strptime(value, date_format).date().isoformat()
        except ValueError:
            continue
    raise ValueError("La fecha debe usar el formato AAAA-MM-DD.")


def parse_amount_cents(value):
    if isinstance(value, bool) or value is None:
        raise ValueError("Escribe un monto válido.")
    if isinstance(value, (int, float)):
        parsed = float(value)
    else:
        raw = re.sub(r"[^\d,.\-+]", "", str(value).strip())
        if not raw or raw in {"-", "+", ".", ","}:
            raise ValueError("Escribe un monto válido.")
        negative = raw.startswith("-") or (str(value).strip().startswith("(") and str(value).strip().endswith(")"))
        raw = raw.replace("-", "").replace("+", "")
        if "," in raw and "." in raw:
            decimal_separator = "," if raw.rfind(",") > raw.rfind(".") else "."
            thousands_separator = "." if decimal_separator == "," else ","
            raw = raw.replace(thousands_separator, "").replace(decimal_separator, ".")
        elif "," in raw:
            pieces = raw.rsplit(",", 1)
            raw = pieces[0].replace(",", "") + ("." + pieces[1] if len(pieces[1]) <= 2 else pieces[1])
        elif "." in raw:
            whole, fractional = raw.rsplit(".", 1)
            if len(fractional) == 3 and whole.isdigit() and int(whole) > 0:
                raw = raw.replace(".", "")
        try:
            parsed = float(raw)
        except ValueError as error:
            raise ValueError("Escribe un monto válido.") from error
        if negative:
            parsed = -parsed
    if not math.isfinite(parsed) or parsed == 0 or abs(parsed) > 999_999_999_999:
        raise ValueError("El monto debe ser distinto de cero y tener hasta 12 cifras.")
    amount_cents = round(abs(parsed) * 100)
    if amount_cents == 0:
        raise ValueError("El monto debe ser de al menos un centavo.")
    return amount_cents, parsed < 0


def transaction_to_dict(transaction):
    return {
        "id": transaction["id"],
        "type": transaction["transaction_type"],
        "amount_cents": transaction["amount_cents"],
        "amount": transaction["amount_cents"] / 100,
        "currency": "COP",
        "date": transaction["transaction_date"],
        "category": transaction["category"],
        "nature": transaction["nature"],
        "cost_type": transaction["cost_type"],
        "vendor": transaction["vendor"],
        "description": transaction["description"],
        "source": transaction["source"],
        "file_id": transaction["file_id"],
        "file_name": transaction["file_name"],
        "recurring_id": transaction["recurring_id"],
    }


def recurrence_date(start_date, frequency, interval_count, occurrence_index):
    start = date.fromisoformat(start_date)
    interval = interval_count * occurrence_index
    if frequency == "semanal":
        return start + timedelta(weeks=interval)
    if frequency == "anual":
        year = start.year + interval
        return start.replace(year=year, day=min(start.day, calendar.monthrange(year, start.month)[1]))
    month_index = start.year * 12 + start.month - 1 + interval
    year, month_index = divmod(month_index, 12)
    month = month_index + 1
    return start.replace(year=year, month=month, day=min(start.day, calendar.monthrange(year, month)[1]))


def process_due_recurring_transactions():
    today = date.today()
    with get_db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        schedules = connection.execute(
            "SELECT * FROM recurring_transactions WHERE active = 1 AND next_run_date <= ?",
            (today.isoformat(),),
        ).fetchall()
        for schedule in schedules:
            occurrence_count = schedule["occurrence_count"]
            next_run = date.fromisoformat(schedule["next_run_date"])
            catchup_count = 0
            while next_run <= today:
                if catchup_count >= RECURRENCE_CATCHUP_LIMIT:
                    raise RuntimeError(
                        f"La recurrencia {schedule['id']} excedió el límite de ejecuciones pendientes."
                    )
                external_id = f"recurrence:{schedule['id']}:{occurrence_count}"
                transaction_id = uuid.uuid5(uuid.NAMESPACE_URL, external_id).hex
                connection.execute(
                    "INSERT OR IGNORE INTO transactions "
                    "(id, owner_id, transaction_type, amount_cents, transaction_date, category, "
                    "nature, cost_type, vendor, description, source, external_id, recurring_id, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'recurring', ?, ?, ?)",
                    (
                        transaction_id,
                        schedule["owner_id"],
                        schedule["transaction_type"],
                        schedule["amount_cents"],
                        next_run.isoformat(),
                        schedule["category"],
                        schedule["nature"],
                        schedule["cost_type"],
                        schedule["vendor"],
                        schedule["description"],
                        external_id,
                        schedule["id"],
                        now_iso(),
                    ),
                )
                occurrence_count += 1
                catchup_count += 1
                next_run = recurrence_date(
                    schedule["start_date"],
                    schedule["frequency"],
                    schedule["interval_count"],
                    occurrence_count,
                )
            connection.execute(
                "UPDATE recurring_transactions SET occurrence_count = ?, next_run_date = ? WHERE id = ?",
                (occurrence_count, next_run.isoformat(), schedule["id"]),
            )


def recurring_scheduler_loop():
    while not recurring_scheduler_stop.wait(30):
        try:
            process_due_recurring_transactions()
        except Exception:
            app.logger.exception("No se pudieron generar las transacciones recurrentes vencidas.")


def start_recurring_scheduler():
    global recurring_scheduler_started
    with recurring_scheduler_lock:
        if recurring_scheduler_started:
            return
        recurring_scheduler_started = True
        scheduler_thread = threading.Thread(
            target=recurring_scheduler_loop,
            name="financia-recurring-transactions",
            daemon=True,
        )
        scheduler_thread.start()


atexit.register(recurring_scheduler_stop.set)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def csrf_token():
    token = session.get("csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def secure_cookie():
    return (
        request.is_secure
        or os.environ.get("FINANCIA_COOKIE_SECURE") == "1"
        or os.environ.get("FLASK_ENV") == "production"
    )


def token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@app.before_request
def load_authenticated_user():
    start_recurring_scheduler()
    g.user_id = None
    raw_token = request.cookies.get("financia_session")
    if raw_token:
        with get_db() as connection:
            auth_session = connection.execute(
                "SELECT user_id FROM user_sessions WHERE token_hash = ? AND expires_at > ?",
                (token_hash(raw_token), now_iso()),
            ).fetchone()
        if auth_session:
            g.user_id = auth_session["user_id"]

    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        submitted = request.headers.get("X-CSRF-Token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(submitted, expected):
            return jsonify({"error": "La sesión de seguridad expiró. Recarga la página e inténtalo de nuevo."}), 403


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    if secure_cookie():
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


def require_auth(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user_id is None:
            return jsonify({"error": "Inicia sesión para acceder a tus documentos."}), 401
        return view(*args, **kwargs)

    return wrapped


def user_to_dict(user):
    return {"id": user["id"], "email": user["email"]}


def encrypt_existing_files():
    with get_db() as connection:
        records = connection.execute("SELECT id, stored_name FROM files").fetchall()
    for record in records:
        path = UPLOAD_DIR / record["stored_name"]
        contents = path.read_bytes()
        if not contents.startswith(STORAGE_MARKER):
            write_encrypted_file(path, contents)


def write_encrypted_file(path, contents):
    encrypted = STORAGE_MARKER + fernet.encrypt(contents)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(dir=UPLOAD_DIR, delete=False) as temporary_file:
            temporary_path = Path(temporary_file.name)
            temporary_file.write(encrypted)
        temporary_path.replace(path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def read_encrypted_file(path):
    contents = path.read_bytes()
    if not contents.startswith(STORAGE_MARKER):
        raise OSError("El archivo almacenado no tiene el formato cifrado esperado.")
    encrypted = contents[len(STORAGE_MARKER):]
    for key in [fernet, *fallback_fernets]:
        try:
            return key.decrypt(encrypted)
        except InvalidToken:
            continue
    raise InvalidToken


def create_user(email, password_hash=None, oauth_identity=None):
    user_id = uuid.uuid4().hex
    with get_db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        user_count = connection.execute("SELECT COUNT(*) AS total FROM users").fetchone()["total"]
        connection.execute(
            "INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (user_id, email, password_hash, now_iso()),
        )
        if oauth_identity:
            connection.execute(
                "INSERT INTO oauth_identities (provider, subject, user_id) VALUES (?, ?, ?)",
                (oauth_identity[0], oauth_identity[1], user_id),
            )
        if user_count == 0:
            encrypt_existing_files()
            connection.execute("UPDATE files SET owner_id = ? WHERE owner_id IS NULL", (user_id,))
    return user_id


def authenticated_response(user_id, status=200):
    raw_token, user, has_passkey = create_auth_session(user_id)
    response = jsonify(
        {
            "authenticated": True,
            "user": user_to_dict(user),
            "has_passkey": has_passkey,
            "csrf_token": csrf_token(),
        }
    )
    response.status_code = status
    response.set_cookie(
        "financia_session",
        raw_token,
        max_age=int(SESSION_LIFETIME.total_seconds()),
        httponly=True,
        secure=secure_cookie(),
        samesite="Lax",
        path="/",
    )
    return response


def create_auth_session(user_id):
    raw_token = secrets.token_urlsafe(48)
    expires_at = datetime.now(timezone.utc) + SESSION_LIFETIME
    with get_db() as connection:
        connection.execute(
            "INSERT INTO user_sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (token_hash(raw_token), user_id, expires_at.isoformat()),
        )
        user = connection.execute("SELECT id, email FROM users WHERE id = ?", (user_id,)).fetchone()
        passkey = connection.execute(
            "SELECT 1 FROM passkeys WHERE user_id = ? LIMIT 1", (user_id,)
        ).fetchone()

    session.clear()
    return raw_token, user, passkey is not None


def file_to_dict(file_record):
    return {
        "id": file_record["id"],
        "name": file_record["original_name"],
        "extension": file_record["extension"],
        "size": file_record["size"],
        "uploaded_at": file_record["uploaded_at"],
        "document_type": file_record["document_type"],
        "ocr_status": file_record["ocr_status"],
        "expense": (
            {
                "amount": file_record["expense_amount"],
                "date": file_record["expense_date"],
                "vendor": file_record["expense_vendor"],
                "category": file_record["expense_category"],
            }
            if file_record["expense_id"]
            else None
        ),
    }


def extract_receipt_data(text):
    lines = [line.strip(" \t:|") for line in text.splitlines() if line.strip(" \t:|")]
    normalized_lines = [re.sub(r"\s+", " ", line) for line in lines]
    vendor = next(
        (
            line[:120]
            for line in normalized_lines
            if not re.search(
                r"\b(?:receipt|recibo|factura|invoice|ticket|fecha|date|total|subtotal|"
                r"iva|tax|nit|rfc|cuit|cash|cambio|change|gracias|thank)\b",
                line,
                re.IGNORECASE,
            )
        ),
        None,
    )

    expense_date = None
    for line in normalized_lines:
        match = DATE_PATTERN.search(line)
        if not match:
            continue
        if match.group("iso_year"):
            year, month, day = int(match.group("iso_year")), int(match.group("iso_month")), int(match.group("iso_day"))
        else:
            day, month, year = int(match.group("day")), int(match.group("month")), int(match.group("year"))
            if year < 100:
                year += 2000
        try:
            expense_date = date(year, month, day).isoformat()
        except ValueError:
            continue
        break

    amount = None
    candidate_lines = [
        line
        for line in normalized_lines
        if re.search(r"\b(?:total|importe|monto|amount|grand total|a pagar|total a pagar)\b|[$€£]", line, re.IGNORECASE)
    ]
    for line in reversed(candidate_lines or normalized_lines):
        candidates = list(AMOUNT_PATTERN.finditer(line))
        if not candidates:
            continue
        raw_amount = candidates[-1].group("amount").replace(" ", "")
        if "," in raw_amount and "." in raw_amount:
            decimal_separator = "," if raw_amount.rfind(",") > raw_amount.rfind(".") else "."
            thousands_separator = "." if decimal_separator == "," else ","
            normalized_amount = raw_amount.replace(thousands_separator, "").replace(decimal_separator, ".")
        elif "," in raw_amount:
            normalized_amount = raw_amount.replace(",", ".") if len(raw_amount.rsplit(",", 1)[-1]) == 2 else raw_amount.replace(",", "")
        elif "." in raw_amount and len(raw_amount.rsplit(".", 1)[-1]) == 3:
            normalized_amount = raw_amount.replace(".", "")
        else:
            normalized_amount = raw_amount
        try:
            parsed_amount = float(normalized_amount)
        except ValueError:
            continue
        if parsed_amount > 0:
            amount = round(parsed_amount, 2)
            break

    lowered = text.casefold()
    category_keywords = {
        "alimentacion": ("restaurant", "restaurante", "cafe", "cafeteria", "supermercado", "market", "comida", "food"),
        "transporte": ("uber", "taxi", "gasolina", "combustible", "parking", "estacionamiento", "transporte", "bus"),
        "servicios": ("electricidad", "agua potable", "internet", "telefono", "electric", "utility"),
        "salud": ("farmacia", "pharmacy", "hospital", "clinica", "medico", "salud", "health"),
        "vivienda": ("alquiler", "renta", "hipoteca", "rent", "mortgage"),
        "educacion": ("universidad", "colegio", "escuela", "education", "tuition"),
        "compras": ("tienda", "store", "shopping", "ropa", "clothing"),
    }
    category = next(
        (
            name
            for name, keywords in category_keywords.items()
            if any(keyword in lowered for keyword in keywords)
        ),
        "otros",
    )
    is_invoice = bool(re.search(r"\b(?:factura|invoice)\b", lowered))
    is_receipt = bool(
        re.search(r"\b(?:recibo|receipt|ticket|subtotal|total a pagar)\b", lowered)
        or (
            not is_invoice
            and amount is not None
            and expense_date is not None
            and re.search(r"\b(?:total|importe|monto|amount|a pagar)\b", lowered)
        )
    )
    return {
        "vendor": vendor,
        "amount": amount,
        "date": expense_date,
        "category": category,
        "is_receipt": is_receipt,
        "is_invoice": is_invoice,
    }


def process_receipt_image(contents):
    configured_executable = os.environ.get("TESSERACT_CMD")
    if configured_executable:
        executable = (
            configured_executable
            if Path(configured_executable).is_file()
            else shutil.which(configured_executable)
        )
    else:
        executable = shutil.which("tesseract")
        if executable is None:
            candidates = [
                Path(os.environ.get("LOCALAPPDATA", "")) / "Tesseract-OCR" / "tesseract.exe",
                Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Tesseract-OCR" / "tesseract.exe",
                Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
                / "Tesseract-OCR"
                / "tesseract.exe",
            ]
            executable = next((str(candidate) for candidate in candidates if candidate.is_file()), None)
    if executable is None:
        return None, "unavailable"
    pytesseract.pytesseract.tesseract_cmd = executable
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(contents)) as image:
                image.verify()
            with Image.open(BytesIO(contents)) as image:
                if image.width * image.height > 30_000_000:
                    return None, "too_large"
                text = pytesseract.image_to_string(
                    image,
                    lang=os.environ.get("FINANCIA_OCR_LANG", "spa+eng"),
                    timeout=15,
                )
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        return None, "too_large"
    except (OSError, UnidentifiedImageError, pytesseract.TesseractNotFoundError, pytesseract.TesseractError):
        app.logger.exception("No se pudo procesar la imagen con OCR.")
        return None, "error"
    return extract_receipt_data(text), "processed"


def webauthn_rp_id():
    return os.environ.get("FINANCIA_RP_ID") or request.host.split(":", 1)[0]


def webauthn_origin():
    return os.environ.get("FINANCIA_ORIGIN") or request.host_url.rstrip("/")


def valid_email(email):
    return isinstance(email, str) and len(email) <= 254 and EMAIL_PATTERN.fullmatch(email) is not None


@app.get("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/styles.css")
def styles():
    return send_from_directory(BASE_DIR, "styles.css")


@app.get("/app.js")
def javascript():
    return send_from_directory(BASE_DIR, "app.js")


@app.get("/api/auth/status")
def auth_status():
    user = None
    has_passkey = False
    if g.user_id is not None:
        with get_db() as connection:
            user = connection.execute(
                "SELECT id, email FROM users WHERE id = ?", (g.user_id,)
            ).fetchone()
            has_passkey = connection.execute(
                "SELECT 1 FROM passkeys WHERE user_id = ? LIMIT 1", (g.user_id,)
            ).fetchone() is not None
    return jsonify(
        {
            "authenticated": user is not None,
            "user": user_to_dict(user) if user else None,
            "has_passkey": has_passkey,
            "providers": sorted(oauth_providers),
            "csrf_token": csrf_token(),
        }
    )


@app.post("/api/auth/register")
def register():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Los datos de registro no son válidos."}), 400
    raw_email = payload.get("email")
    email = raw_email.strip().casefold() if isinstance(raw_email, str) else ""
    password = payload.get("password", "")
    if not valid_email(email):
        return jsonify({"error": "Escribe una dirección de correo válida."}), 400
    if not isinstance(password, str) or len(password) < 12 or len(password) > 1024:
        return jsonify({"error": "La contraseña debe tener entre 12 y 1024 caracteres."}), 400
    try:
        user_id = create_user(email, generate_password_hash(password))
    except sqlite3.IntegrityError:
        return jsonify({"error": "Ya existe una cuenta con ese correo."}), 409
    except OSError:
        app.logger.exception("No se pudieron cifrar los documentos existentes durante el registro.")
        return jsonify({"error": "No se pudieron proteger los documentos existentes. Inténtalo de nuevo."}), 500
    return authenticated_response(user_id, 201)


@app.post("/api/auth/login")
def login():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "El correo o la contraseña no son correctos."}), 401
    raw_email = payload.get("email")
    email = raw_email.strip().casefold() if isinstance(raw_email, str) else ""
    password = payload.get("password", "")
    if not valid_email(email) or not isinstance(password, str):
        return jsonify({"error": "El correo o la contraseña no son correctos."}), 401
    with get_db() as connection:
        user = connection.execute(
            "SELECT id, email, password_hash FROM users WHERE email = ? COLLATE NOCASE",
            (email,),
        ).fetchone()
    if user is None or user["password_hash"] is None or not check_password_hash(
        user["password_hash"], password
    ):
        return jsonify({"error": "El correo o la contraseña no son correctos."}), 401
    return authenticated_response(user["id"])


@app.post("/api/auth/logout")
def logout():
    raw_token = request.cookies.get("financia_session")
    if raw_token:
        with get_db() as connection:
            connection.execute("DELETE FROM user_sessions WHERE token_hash = ?", (token_hash(raw_token),))
    response = jsonify({"authenticated": False})
    response.delete_cookie(
        "financia_session",
        path="/",
        httponly=True,
        secure=secure_cookie(),
        samesite="Lax",
    )
    session.clear()
    return response


@app.get("/api/auth/oauth/<provider>")
def oauth_login(provider):
    client = oauth_providers.get(provider)
    if client is None:
        return jsonify({"error": f"El inicio de sesión con {provider} no está configurado."}), 503
    redirect_uri = os.environ.get("FINANCIA_ORIGIN", "").rstrip("/")
    if redirect_uri:
        redirect_uri += f"/api/auth/oauth/{provider}/callback"
    else:
        redirect_uri = request.url_root.rstrip("/") + f"/api/auth/oauth/{provider}/callback"
    return client.authorize_redirect(redirect_uri)


@app.get("/api/auth/oauth/<provider>/callback")
def oauth_callback(provider):
    client = oauth_providers.get(provider)
    if client is None:
        return jsonify({"error": f"El inicio de sesión con {provider} no está configurado."}), 503
    try:
        token = client.authorize_access_token()
    except Exception:
        app.logger.exception("Falló la autenticación OAuth con %s.", provider)
        return jsonify({"error": "No se pudo completar el inicio de sesión del proveedor."}), 401

    identity = token.get("userinfo")
    if identity is None:
        try:
            identity = client.userinfo(token=token)
        except Exception:
            app.logger.exception("No se pudo obtener el perfil OAuth de %s.", provider)
            return jsonify({"error": "El proveedor no devolvió un perfil válido."}), 401
    if not isinstance(identity, dict):
        return jsonify({"error": "El proveedor no devolvió un perfil válido."}), 401
    subject = identity.get("sub")
    raw_email = identity.get("email")
    email = raw_email.strip().casefold() if isinstance(raw_email, str) else ""
    email_verified = identity.get("email_verified", False)
    if isinstance(email_verified, str):
        email_verified = email_verified.casefold() == "true"
    if not isinstance(subject, str) or not subject or not valid_email(email) or not email_verified:
        return jsonify({"error": "El proveedor no verificó la dirección de correo de la cuenta."}), 403

    with get_db() as connection:
        linked = connection.execute(
            "SELECT user_id FROM oauth_identities WHERE provider = ? AND subject = ?",
            (provider, subject),
        ).fetchone()
        existing = connection.execute(
            "SELECT id FROM users WHERE email = ? COLLATE NOCASE", (email,)
        ).fetchone()
    if linked:
        user_id = linked["user_id"]
    elif existing:
        user_id = existing["id"]
        with get_db() as connection:
            connection.execute(
                "INSERT INTO oauth_identities (provider, subject, user_id) VALUES (?, ?, ?)",
                (provider, subject, user_id),
            )
    else:
        try:
            user_id = create_user(email, oauth_identity=(provider, subject))
        except sqlite3.IntegrityError:
            with get_db() as connection:
                user = connection.execute(
                    "SELECT id FROM users WHERE email = ? COLLATE NOCASE", (email,)
                ).fetchone()
            if user is None:
                raise
            user_id = user["id"]
            with get_db() as connection:
                connection.execute(
                    "INSERT OR IGNORE INTO oauth_identities (provider, subject, user_id) VALUES (?, ?, ?)",
                    (provider, subject, user_id),
                )
        except OSError:
            app.logger.exception("No se pudieron cifrar los documentos existentes durante el registro OAuth.")
            return jsonify({"error": "No se pudieron proteger los documentos existentes."}), 500
    raw_token, _user, _has_passkey = create_auth_session(user_id)
    csrf_token()
    response = redirect("/")
    response.set_cookie(
        "financia_session",
        raw_token,
        max_age=int(SESSION_LIFETIME.total_seconds()),
        httponly=True,
        secure=secure_cookie(),
        samesite="Lax",
        path="/",
    )
    return response


@app.post("/api/auth/passkeys/register/options")
@require_auth
def passkey_registration_options():
    with get_db() as connection:
        user = connection.execute("SELECT id, email FROM users WHERE id = ?", (g.user_id,)).fetchone()
        credentials = connection.execute(
            "SELECT credential_id FROM passkeys WHERE user_id = ?", (g.user_id,)
        ).fetchall()
    options = generate_registration_options(
        rp_id=webauthn_rp_id(),
        rp_name="Financia",
        user_id=user["id"].encode("utf-8"),
        user_name=user["email"],
        user_display_name=user["email"],
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(row["credential_id"]))
            for row in credentials
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    session["passkey_registration_challenge"] = bytes_to_base64url(options.challenge)
    return jsonify(json.loads(options_to_json(options)))


@app.post("/api/auth/passkeys/register/verify")
@require_auth
def verify_passkey_registration():
    payload = request.get_json(silent=True)
    challenge = session.pop("passkey_registration_challenge", None)
    if not challenge or not payload:
        return jsonify({"error": "La solicitud de biometría expiró. Inténtalo de nuevo."}), 400
    try:
        verification = verify_registration_response(
            credential=RegistrationCredential.parse_raw(json.dumps(payload)),
            expected_challenge=base64url_to_bytes(challenge),
            expected_rp_id=webauthn_rp_id(),
            expected_origin=webauthn_origin(),
            require_user_verification=True,
        )
    except Exception:
        app.logger.exception("No se pudo verificar el registro de una passkey.")
        return jsonify({"error": "No se pudo verificar la huella o Face ID. Inténtalo de nuevo."}), 400
    try:
        with get_db() as connection:
            connection.execute(
                "INSERT INTO passkeys (credential_id, user_id, public_key, sign_count, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    bytes_to_base64url(verification.credential_id),
                    g.user_id,
                    bytes_to_base64url(verification.credential_public_key),
                    verification.sign_count,
                    now_iso(),
                ),
            )
    except sqlite3.IntegrityError:
        return jsonify({"error": "Esta passkey ya está registrada."}), 409
    return jsonify({"registered": True})


@app.post("/api/auth/passkeys/login/options")
def passkey_login_options():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Escribe tu correo para buscar una passkey."}), 400
    raw_email = payload.get("email")
    email = raw_email.strip().casefold() if isinstance(raw_email, str) else ""
    if not valid_email(email):
        return jsonify({"error": "Escribe tu correo para buscar una passkey."}), 400
    with get_db() as connection:
        user = connection.execute(
            "SELECT id FROM users WHERE email = ? COLLATE NOCASE", (email,)
        ).fetchone()
        credentials = connection.execute(
            "SELECT credential_id FROM passkeys WHERE user_id = ?",
            (user["id"],),
        ).fetchall() if user else []
    if not credentials:
        return jsonify({"error": "No hay una passkey registrada para ese correo."}), 404
    options = generate_authentication_options(
        rp_id=webauthn_rp_id(),
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(row["credential_id"]))
            for row in credentials
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    session["passkey_login_challenge"] = bytes_to_base64url(options.challenge)
    session["passkey_login_user_id"] = user["id"]
    return jsonify(json.loads(options_to_json(options)))


@app.post("/api/auth/passkeys/login/verify")
def verify_passkey_login():
    payload = request.get_json(silent=True)
    challenge = session.pop("passkey_login_challenge", None)
    user_id = session.pop("passkey_login_user_id", None)
    if not challenge or not user_id or not isinstance(payload, dict):
        return jsonify({"error": "La solicitud de biometría expiró. Inténtalo de nuevo."}), 400
    credential_id = payload.get("id")
    with get_db() as connection:
        credential = connection.execute(
            "SELECT credential_id, public_key, sign_count FROM passkeys "
            "WHERE credential_id = ? AND user_id = ?",
            (credential_id, user_id),
        ).fetchone()
    if credential is None:
        return jsonify({"error": "No se reconoció esta passkey."}), 401
    try:
        verification = verify_authentication_response(
            credential=AuthenticationCredential.parse_raw(json.dumps(payload)),
            expected_challenge=base64url_to_bytes(challenge),
            expected_rp_id=webauthn_rp_id(),
            expected_origin=webauthn_origin(),
            credential_public_key=base64url_to_bytes(credential["public_key"]),
            credential_current_sign_count=credential["sign_count"],
            require_user_verification=True,
        )
    except Exception:
        app.logger.exception("Falló la verificación de una passkey.")
        return jsonify({"error": "No se pudo verificar la huella o Face ID."}), 401
    with get_db() as connection:
        connection.execute(
            "UPDATE passkeys SET sign_count = ? WHERE credential_id = ?",
            (verification.new_sign_count, credential["credential_id"]),
        )
    return authenticated_response(user_id)


@app.get("/api/files")
@require_auth
def list_files():
    with get_db() as connection:
        files = connection.execute(
            "SELECT f.id, f.original_name, f.extension, f.size, f.uploaded_at, "
            "f.document_type, f.ocr_status, e.id AS expense_id, e.amount AS expense_amount, "
            "e.expense_date, e.vendor AS expense_vendor, e.category AS expense_category "
            "FROM files AS f LEFT JOIN expenses AS e ON e.file_id = f.id "
            "WHERE f.owner_id = ? ORDER BY f.uploaded_at DESC",
            (g.user_id,),
        ).fetchall()
    return jsonify([file_to_dict(file_record) for file_record in files])


@app.post("/api/files")
@require_auth
def upload_files():
    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "Selecciona al menos un archivo."}), 400

    total_size = 0
    for uploaded_file in files:
        uploaded_file.stream.seek(0, os.SEEK_END)
        total_size += uploaded_file.stream.tell()
        uploaded_file.stream.seek(0)
    if total_size > MAX_UPLOAD_SIZE:
        return jsonify({"error": "El tamaño total de los archivos supera el límite de 25 MB."}), 413
    document_type = request.form.get("document_type", "otro")
    if document_type not in DOCUMENT_TYPES:
        return jsonify({"error": "Selecciona un tipo de documento válido."}), 400

    uploaded = []
    errors = []
    for uploaded_file in files:
        original_name = secure_filename(uploaded_file.filename or "")
        if not original_name:
            errors.append({"name": "Archivo sin nombre", "error": "El nombre del archivo no es válido."})
            continue

        extension = Path(original_name).suffix.lower().lstrip(".")
        if extension not in ALLOWED_EXTENSIONS:
            errors.append(
                {
                    "name": original_name,
                    "error": "Formato no permitido. Revisa los formatos admitidos.",
                }
            )
            continue

        file_id = uuid.uuid4().hex
        stored_name = f"{file_id}.{extension}"
        destination = UPLOAD_DIR / stored_name
        contents = uploaded_file.read()
        effective_document_type = document_type
        ocr_status = "not_applicable"
        receipt_data = None
        if extension in IMAGE_EXTENSIONS:
            receipt_data, ocr_status = process_receipt_image(contents)
            if receipt_data and receipt_data.get("is_receipt"):
                effective_document_type = "recibo"
            elif receipt_data and receipt_data.get("is_invoice"):
                effective_document_type = "factura"
        is_receipt = effective_document_type == "recibo" or (
            receipt_data is not None and receipt_data.get("is_receipt")
        )
        try:
            write_encrypted_file(destination, contents)
            uploaded_at = now_iso()
            with get_db() as connection:
                connection.execute(
                    "INSERT INTO files "
                    "(id, original_name, stored_name, extension, size, uploaded_at, owner_id, document_type, ocr_status) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        file_id,
                        original_name,
                        stored_name,
                        extension,
                        len(contents),
                        uploaded_at,
                        g.user_id,
                        effective_document_type,
                        ocr_status,
                    ),
                )
                if is_receipt:
                    transaction_id = uuid.uuid4().hex
                    receipt_amount = receipt_data["amount"] if receipt_data else None
                    receipt_date = receipt_data["date"] if receipt_data else None
                    receipt_vendor = receipt_data["vendor"] if receipt_data else None
                    receipt_category = receipt_data["category"] if receipt_data else "otros"
                    connection.execute(
                        "INSERT INTO expenses "
                        "(id, owner_id, file_id, amount, expense_date, vendor, category, created_at, transaction_id) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            transaction_id,
                            g.user_id,
                            file_id,
                            receipt_amount,
                            receipt_date,
                            receipt_vendor,
                            receipt_category,
                            now_iso(),
                            transaction_id,
                        ),
                    )
                    if receipt_amount and receipt_amount > 0:
                        connection.execute(
                            "INSERT INTO transactions "
                            "(id, owner_id, transaction_type, amount_cents, transaction_date, category, "
                            "nature, vendor, description, source, external_id, file_id, created_at) "
                            "VALUES (?, ?, 'gasto', ?, ?, ?, 'variable', ?, ?, 'recibo', ?, ?, ?)",
                            (
                                transaction_id,
                                g.user_id,
                                round(receipt_amount * 100),
                                receipt_date or uploaded_at[:10],
                                receipt_category if receipt_category in EXPENSE_CATEGORIES else "otros",
                                receipt_vendor,
                                f"Gasto asociado al recibo {original_name}",
                                f"receipt:{file_id}",
                                file_id,
                                uploaded_at,
                            ),
                        )
        except OSError:
            destination.unlink(missing_ok=True)
            app.logger.exception("No se pudo cifrar el archivo subido.")
            return jsonify({"error": "No se pudo proteger el archivo. Inténtalo de nuevo."}), 500
        except sqlite3.Error:
            destination.unlink(missing_ok=True)
            app.logger.exception("No se pudo registrar el archivo subido.")
            return jsonify({"error": "No se pudo registrar el archivo. Inténtalo de nuevo."}), 500

        uploaded.append(
            {
                "id": file_id,
                "name": original_name,
                "extension": extension,
                "size": len(contents),
                "uploaded_at": uploaded_at,
                "document_type": effective_document_type,
                "ocr_status": ocr_status,
                "expense": (
                    {
                        "amount": receipt_data["amount"] if receipt_data else None,
                        "date": receipt_data["date"] if receipt_data else None,
                        "vendor": receipt_data["vendor"] if receipt_data else None,
                        "category": receipt_data["category"] if receipt_data else "otros",
                    }
                    if is_receipt
                    else None
                ),
            }
        )

    status_code = 207 if errors else 201
    return jsonify({"uploaded": uploaded, "errors": errors}), status_code


@app.get("/api/expenses")
@require_auth
def list_expenses():
    with get_db() as connection:
        expenses = connection.execute(
            "SELECT e.id, e.file_id, e.amount, e.expense_date, e.vendor, e.category, "
            "f.original_name, f.ocr_status "
            "FROM expenses AS e JOIN files AS f ON f.id = e.file_id "
            "WHERE e.owner_id = ? ORDER BY COALESCE(e.expense_date, f.uploaded_at) DESC",
            (g.user_id,),
        ).fetchall()
    return jsonify(
        [
            {
                "id": expense["id"],
                "file_id": expense["file_id"],
                "file_name": expense["original_name"],
                "amount": expense["amount"],
                "date": expense["expense_date"],
                "vendor": expense["vendor"],
                "category": expense["category"],
                "ocr_status": expense["ocr_status"],
            }
            for expense in expenses
        ]
    )


def validate_transaction_payload(payload):
    transaction_type = payload.get("type", "gasto")
    if not isinstance(transaction_type, str) or transaction_type not in TRANSACTION_TYPES:
        raise ValueError("Selecciona si la transacción es un gasto o un costo.")
    amount_cents, is_negative = parse_amount_cents(payload.get("amount"))
    if is_negative:
        raise ValueError("El monto debe ser positivo; selecciona gasto o costo por separado.")

    transaction_date = parse_transaction_date(payload.get("date", date.today().isoformat()))
    description = payload.get("description", "")
    if not isinstance(description, str) or not description.strip() or len(description.strip()) > 240:
        raise ValueError("La descripción es obligatoria y debe tener hasta 240 caracteres.")
    vendor = payload.get("vendor", "")
    if vendor not in (None, "") and (not isinstance(vendor, str) or len(vendor.strip()) > 160):
        raise ValueError("El proveedor debe tener hasta 160 caracteres.")
    vendor = vendor.strip() if isinstance(vendor, str) else None

    nature = None
    cost_type = None
    if transaction_type == "gasto":
        category = payload.get("category")
        nature = payload.get("nature")
        if not isinstance(category, str) or category not in TRANSACTION_EXPENSE_CATEGORIES:
            raise ValueError("Selecciona una categoría de gasto válida.")
        if not isinstance(nature, str) or nature not in EXPENSE_NATURES:
            raise ValueError("Indica si el gasto es fijo o variable.")
    else:
        cost_type = payload.get("cost_type")
        if not isinstance(cost_type, str) or cost_type not in COST_TYPES:
            raise ValueError("Selecciona materia prima, mano de obra, adquisición u otros costos.")
        category = cost_type

    file_id = payload.get("file_id")
    if file_id not in (None, "") and not isinstance(file_id, str):
        raise ValueError("El comprobante seleccionado no es válido.")
    return {
        "transaction_type": transaction_type,
        "amount_cents": amount_cents,
        "transaction_date": transaction_date,
        "category": category,
        "nature": nature,
        "cost_type": cost_type,
        "vendor": vendor or None,
        "description": description.strip(),
        "file_id": file_id or None,
    }


def validate_transaction_file(connection, file_id, owner_id):
    if not file_id:
        return
    if connection.execute(
        "SELECT 1 FROM files WHERE id = ? AND owner_id = ?", (file_id, owner_id)
    ).fetchone() is None:
        raise ValueError("El comprobante no existe o no pertenece a tu cuenta.")


def build_budget_response(connection, owner_id):
    month_start = date.today().replace(day=1).isoformat()
    today = date.today().isoformat()
    budget_rows = connection.execute(
        "SELECT id, transaction_type, category, limit_cents FROM budgets "
        "WHERE owner_id = ? ORDER BY transaction_type, category",
        (owner_id,),
    ).fetchall()
    category_rows = connection.execute(
        "SELECT transaction_type, category, SUM(amount_cents) AS spent_cents "
        "FROM transactions WHERE owner_id = ? AND transaction_date >= ? AND transaction_date <= ? "
        "GROUP BY transaction_type, category",
        (owner_id, month_start, today),
    ).fetchall()
    spending = {
        (row["transaction_type"], row["category"]): row["spent_cents"] or 0
        for row in category_rows
    }
    budgets = []
    alerts = []
    for row in budget_rows:
        spent_cents = spending.get((row["transaction_type"], row["category"]), 0)
        limit_cents = row["limit_cents"]
        if spent_cents >= limit_cents:
            status = "exceeded"
        elif spent_cents * 100 >= limit_cents * 80:
            status = "warning"
        else:
            status = "normal"
        budget = {
            "id": row["id"],
            "type": row["transaction_type"],
            "category": row["category"],
            "limit_cents": limit_cents,
            "spent_cents": spent_cents,
            "remaining_cents": max(0, limit_cents - spent_cents),
            "progress_percent": round(spent_cents * 100 / limit_cents, 1),
            "status": status,
        }
        budgets.append(budget)
        if status != "normal":
            alerts.append(budget)
    return {
        "month": month_start[:7],
        "budgets": budgets,
        "alerts": alerts,
        "category_spending": [
            {
                "type": row["transaction_type"],
                "category": row["category"],
                "spent_cents": row["spent_cents"] or 0,
            }
            for row in category_rows
        ],
    }


@app.get("/api/transactions")
@require_auth
def list_transactions():
    process_due_recurring_transactions()
    start_of_month = date.today().replace(day=1).isoformat()
    with get_db() as connection:
        transactions = connection.execute(
            "SELECT t.*, f.original_name AS file_name FROM transactions AS t "
            "LEFT JOIN files AS f ON f.id = t.file_id "
            "WHERE t.owner_id = ? ORDER BY t.transaction_date DESC, t.created_at DESC LIMIT 500",
            (g.user_id,),
        ).fetchall()
        totals = connection.execute(
            "SELECT transaction_type, nature, cost_type, SUM(amount_cents) AS total, COUNT(*) AS count "
            "FROM transactions WHERE owner_id = ? AND transaction_date >= ? "
            "GROUP BY transaction_type, nature, cost_type",
            (g.user_id, start_of_month),
        ).fetchall()
        category_spending = connection.execute(
            "SELECT transaction_type, category, SUM(amount_cents) AS spent_cents "
            "FROM transactions WHERE owner_id = ? AND transaction_date >= ? AND transaction_date <= ? "
            "GROUP BY transaction_type, category",
            (g.user_id, start_of_month, date.today().isoformat()),
        ).fetchall()
    summary = {
        "month": start_of_month[:7],
        "expenses_cents": 0,
        "costs_cents": 0,
        "fixed_expenses_cents": 0,
        "variable_expenses_cents": 0,
        "raw_material_cents": 0,
        "direct_labor_cents": 0,
        "acquisition_costs_cents": 0,
        "count": 0,
    }
    total_by_cost_type = {
        "materia_prima": "raw_material_cents",
        "mano_obra_directa": "direct_labor_cents",
        "adquisicion": "acquisition_costs_cents",
    }
    for total in totals:
        amount_cents = total["total"] or 0
        summary["count"] += total["count"]
        if total["transaction_type"] == "gasto":
            summary["expenses_cents"] += amount_cents
            key = "fixed_expenses_cents" if total["nature"] == "fijo" else "variable_expenses_cents"
            summary[key] += amount_cents
        else:
            summary["costs_cents"] += amount_cents
            key = total_by_cost_type.get(total["cost_type"])
            if key:
                summary[key] += amount_cents
    return jsonify(
        {
            "transactions": [transaction_to_dict(item) for item in transactions],
            "summary": summary,
            "category_spending": [
                {
                    "type": item["transaction_type"],
                    "category": item["category"],
                    "spent_cents": item["spent_cents"] or 0,
                }
                for item in category_spending
            ],
            "currency": "COP",
            "bank_sync": {
                "configured": False,
                "country": "CO",
                "message": "La conexión bancaria automática aún no está configurada. Importa un extracto CSV.",
            },
        }
    )


@app.get("/api/budgets")
@require_auth
def list_budgets():
    with get_db() as connection:
        response = build_budget_response(connection, g.user_id)
    return jsonify(response)


@app.post("/api/budgets")
@require_auth
def save_budget():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Los datos del presupuesto no son válidos."}), 400
    transaction_type = payload.get("type")
    category = payload.get("category")
    if transaction_type == "gasto":
        valid_categories = TRANSACTION_EXPENSE_CATEGORIES
    elif transaction_type == "costo":
        valid_categories = COST_TYPES
    else:
        return jsonify({"error": "Selecciona si el presupuesto corresponde a gastos o costos."}), 400
    if not isinstance(category, str) or category not in valid_categories:
        return jsonify({"error": "Selecciona una categoría válida para el presupuesto."}), 400
    try:
        limit_cents, is_negative = parse_amount_cents(payload.get("amount"))
        if is_negative:
            raise ValueError("El límite del presupuesto debe ser positivo.")
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    budget_id = uuid.uuid4().hex
    timestamp = now_iso()
    with get_db() as connection:
        connection.execute(
            "INSERT INTO budgets (id, owner_id, transaction_type, category, limit_cents, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(owner_id, transaction_type, category) DO UPDATE SET "
            "limit_cents = excluded.limit_cents, updated_at = excluded.updated_at",
            (budget_id, g.user_id, transaction_type, category, limit_cents, timestamp, timestamp),
        )
        response = build_budget_response(connection, g.user_id)
    return jsonify(response), 200


@app.delete("/api/budgets/<budget_id>")
@require_auth
def delete_budget(budget_id):
    with get_db() as connection:
        changed = connection.execute(
            "DELETE FROM budgets WHERE id = ? AND owner_id = ?",
            (budget_id, g.user_id),
        ).rowcount
        if not changed:
            return jsonify({"error": "No se encontró el presupuesto."}), 404
        response = build_budget_response(connection, g.user_id)
    return jsonify(response)


@app.post("/api/transactions")
@require_auth
def create_transaction():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Los datos de la transacción no son válidos."}), 400
    try:
        transaction = validate_transaction_payload(payload)
        transaction_id = uuid.uuid4().hex
        with get_db() as connection:
            validate_transaction_file(connection, transaction["file_id"], g.user_id)
            connection.execute(
                "INSERT INTO transactions "
                "(id, owner_id, transaction_type, amount_cents, transaction_date, category, nature, "
                "cost_type, vendor, description, source, file_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'manual', ?, ?)",
                (
                    transaction_id,
                    g.user_id,
                    transaction["transaction_type"],
                    transaction["amount_cents"],
                    transaction["transaction_date"],
                    transaction["category"],
                    transaction["nature"],
                    transaction["cost_type"],
                    transaction["vendor"],
                    transaction["description"],
                    transaction["file_id"],
                    now_iso(),
                ),
            )
            record = connection.execute(
                "SELECT t.*, f.original_name AS file_name FROM transactions AS t "
                "LEFT JOIN files AS f ON f.id = t.file_id WHERE t.id = ?",
                (transaction_id,),
            ).fetchone()
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except sqlite3.IntegrityError:
        app.logger.exception("No se pudo registrar la transacción.")
        return jsonify({"error": "No se pudo registrar la transacción."}), 500
    return jsonify({"transaction": transaction_to_dict(record)}), 201


@app.delete("/api/transactions/<transaction_id>")
@require_auth
def delete_transaction(transaction_id):
    with get_db() as connection:
        transaction = connection.execute(
            "SELECT id, source FROM transactions WHERE id = ? AND owner_id = ?",
            (transaction_id, g.user_id),
        ).fetchone()
        if transaction is None:
            return jsonify({"error": "No se encontró la transacción."}), 404
        if transaction["source"] == "recibo":
            connection.execute(
                "DELETE FROM expenses WHERE transaction_id = ? AND owner_id = ?",
                (transaction_id, g.user_id),
            )
        connection.execute(
            "DELETE FROM transactions WHERE id = ? AND owner_id = ?",
            (transaction_id, g.user_id),
        )
    return jsonify({"deleted": True})


def normalize_csv_header(value):
    normalized = unicodedata.normalize("NFKD", value.strip().casefold())
    return re.sub(r"[^a-z0-9]+", "_", normalized).strip("_")


@app.post("/api/transactions/import")
@require_auth
def import_bank_csv():
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return jsonify({"error": "Selecciona un extracto bancario en formato CSV."}), 400
    contents = upload.stream.read(BANK_IMPORT_MAX_BYTES + 1)
    if len(contents) > BANK_IMPORT_MAX_BYTES:
        return jsonify({"error": "El extracto supera el límite de 5 MB."}), 413
    try:
        csv_text = contents.decode("utf-8-sig")
    except UnicodeDecodeError:
        return jsonify({"error": "El CSV debe estar codificado en UTF-8."}), 400
    try:
        dialect = csv.Sniffer().sniff(csv_text[:8192], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(csv_text.splitlines(), dialect=dialect)
    if not reader.fieldnames:
        return jsonify({"error": "El CSV debe tener una fila de encabezados."}), 400
    aliases = {
        "date": {"fecha", "date", "transaction_date", "fecha_transaccion"},
        "description": {"descripcion", "description", "concepto", "detalle", "memo", "reference"},
        "amount": {"monto", "amount", "valor", "importe", "transaction_amount"},
        "type": {"tipo", "type", "naturaleza_transaccion", "transaction_type"},
        "category": {"categoria", "category", "rubro"},
        "nature": {"naturaleza", "fixed_variable", "fijo_variable", "expense_nature"},
        "cost_type": {"tipo_costo", "cost_type", "costo"},
        "vendor": {"proveedor", "comercio", "merchant", "vendor", "beneficiario"},
    }
    headers = {normalize_csv_header(header): header for header in reader.fieldnames}
    columns = {
        key: next((headers[alias] for alias in choices if alias in headers), None)
        for key, choices in aliases.items()
    }
    if not all(columns[key] for key in ("date", "description", "amount", "type")):
        return jsonify(
            {"error": "El CSV necesita encabezados para fecha, descripción, monto y tipo (gasto o costo)."}
        ), 400
    rows = []
    errors = []
    file_digest = hashlib.sha256(contents).hexdigest()
    for line_number, row in enumerate(reader, start=2):
        if not row or not any(value and value.strip() for value in row.values() if isinstance(value, str)):
            continue
        try:
            raw_amount = row.get(columns["amount"], "")
            amount_cents, is_negative = parse_amount_cents(raw_amount)
            raw_type = normalize_csv_header(row.get(columns["type"]) or "")
            if raw_type in {"ingreso", "income", "deposit", "credito", "credit", "abono"}:
                raise ValueError("este módulo registra egresos, no ingresos")
            if raw_type in {"costo", "cost", "production_cost", "direct_cost"}:
                transaction_type = "costo"
            elif raw_type in {"gasto", "expense", "egreso", "debit", "debito", "cargo", "retiro"}:
                transaction_type = "gasto"
            else:
                raise ValueError("el tipo debe ser gasto o costo")
            cost_type = None
            nature = None
            raw_category = normalize_csv_header(row.get(columns["category"]) or "") if columns["category"] else ""
            if transaction_type == "costo":
                raw_cost_type = normalize_csv_header(row.get(columns["cost_type"]) or "") if columns["cost_type"] else ""
                cost_type = raw_cost_type if raw_cost_type in COST_TYPES else (
                    raw_category if raw_category in COST_TYPES else "otros"
                )
                category = cost_type
            else:
                category = raw_category if raw_category in TRANSACTION_EXPENSE_CATEGORIES else "otros"
                raw_nature = normalize_csv_header(row.get(columns["nature"]) or "") if columns["nature"] else ""
                nature = raw_nature if raw_nature in EXPENSE_NATURES else "variable"
            if is_negative and transaction_type == "gasto":
                amount_cents = abs(amount_cents)
            description = (row.get(columns["description"]) or "").strip()
            if not description:
                raise ValueError("falta la descripción")
            vendor = (row.get(columns["vendor"]) or "").strip() if columns["vendor"] else ""
            if len(description) > 240 or len(vendor) > 160:
                raise ValueError("la descripción o el proveedor supera el límite de caracteres")
            transaction_date = parse_transaction_date(row.get(columns["date"], ""))
            rows.append(
                {
                    "transaction_type": transaction_type,
                    "amount_cents": amount_cents,
                    "transaction_date": transaction_date,
                    "category": category,
                    "nature": nature,
                    "cost_type": cost_type,
                    "vendor": vendor or None,
                    "description": description,
                    "external_id": f"csv:{file_digest}:{line_number}",
                    "line_number": line_number,
                }
            )
        except ValueError as error:
            errors.append({"line": line_number, "error": str(error)})
    if not rows and errors:
        return jsonify({"error": "No se importaron filas válidas.", "errors": errors}), 400
    imported = 0
    skipped = 0
    with get_db() as connection:
        for row in rows:
            exists = connection.execute(
                "SELECT 1 FROM transactions WHERE owner_id = ? AND external_id = ?",
                (g.user_id, row["external_id"]),
            ).fetchone()
            if exists:
                skipped += 1
                continue
            connection.execute(
                "INSERT INTO transactions "
                "(id, owner_id, transaction_type, amount_cents, transaction_date, category, nature, "
                "cost_type, vendor, description, source, external_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'bank_csv', ?, ?)",
                (
                    uuid.uuid4().hex,
                    g.user_id,
                    row["transaction_type"],
                    row["amount_cents"],
                    row["transaction_date"],
                    row["category"],
                    row["nature"],
                    row["cost_type"],
                    row["vendor"],
                    row["description"],
                    row["external_id"],
                    now_iso(),
                ),
            )
            imported += 1
    return jsonify({"imported": imported, "skipped": skipped, "errors": errors}), (207 if errors else 201)


@app.get("/api/recurring-transactions")
@require_auth
def list_recurring_transactions():
    process_due_recurring_transactions()
    with get_db() as connection:
        schedules = connection.execute(
            "SELECT * FROM recurring_transactions WHERE owner_id = ? ORDER BY active DESC, next_run_date",
            (g.user_id,),
        ).fetchall()
    return jsonify(
        [
            {
                "id": item["id"],
                "type": item["transaction_type"],
                "amount_cents": item["amount_cents"],
                "currency": "COP",
                "category": item["category"],
                "nature": item["nature"],
                "cost_type": item["cost_type"],
                "vendor": item["vendor"],
                "description": item["description"],
                "frequency": item["frequency"],
                "interval": item["interval_count"],
                "next_run_date": item["next_run_date"],
                "active": bool(item["active"]),
            }
            for item in schedules
        ]
    )


@app.post("/api/recurring-transactions")
@require_auth
def create_recurring_transaction():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Los datos de la recurrencia no son válidos."}), 400
    try:
        transaction = validate_transaction_payload(payload)
        if transaction["file_id"]:
            return jsonify({"error": "Los pagos recurrentes no pueden usar un comprobante futuro."}), 400
        frequency = payload.get("frequency")
        if not isinstance(frequency, str) or frequency not in RECURRENCE_FREQUENCIES:
            return jsonify({"error": "Selecciona una frecuencia semanal, mensual o anual."}), 400
        interval = payload.get("interval", 1)
        if isinstance(interval, bool) or not isinstance(interval, int) or not 1 <= interval <= RECURRENCE_INTERVAL_LIMIT:
            return jsonify({"error": "El intervalo debe ser un número entero entre 1 y 24."}), 400
        schedule_id = uuid.uuid4().hex
        start_date = transaction["transaction_date"]
        with get_db() as connection:
            connection.execute(
                "INSERT INTO recurring_transactions "
                "(id, owner_id, transaction_type, amount_cents, category, nature, cost_type, vendor, description, "
                "frequency, interval_count, start_date, next_run_date, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    schedule_id,
                    g.user_id,
                    transaction["transaction_type"],
                    transaction["amount_cents"],
                    transaction["category"],
                    transaction["nature"],
                    transaction["cost_type"],
                    transaction["vendor"],
                    transaction["description"],
                    frequency,
                    interval,
                    start_date,
                    start_date,
                    now_iso(),
                ),
            )
        process_due_recurring_transactions()
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    return jsonify({"id": schedule_id, "created": True}), 201


@app.delete("/api/recurring-transactions/<schedule_id>")
@require_auth
def cancel_recurring_transaction(schedule_id):
    with get_db() as connection:
        changed = connection.execute(
            "UPDATE recurring_transactions SET active = 0 WHERE id = ? AND owner_id = ? AND active = 1",
            (schedule_id, g.user_id),
        ).rowcount
        if not changed:
            return jsonify({"error": "No se encontró una recurrencia activa."}), 404
    return jsonify({"cancelled": True})


@app.patch("/api/files/<file_id>/metadata")
@require_auth
def update_file_metadata(file_id):
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Los datos del documento no son válidos."}), 400

    document_type = payload.get("document_type")
    if not isinstance(document_type, str) or document_type not in DOCUMENT_TYPES:
        return jsonify({"error": "Selecciona un tipo de documento válido."}), 400

    expense_data = payload.get("expense")
    if expense_data is not None and not isinstance(expense_data, dict):
        return jsonify({"error": "Los datos del gasto no son válidos."}), 400

    amount = None
    expense_date = None
    vendor = None
    category = "otros"
    if expense_data is not None:
        raw_amount = expense_data.get("amount")
        if raw_amount not in (None, ""):
            if isinstance(raw_amount, bool):
                return jsonify({"error": "Escribe un monto válido."}), 400
            try:
                amount = round(float(raw_amount), 2)
            except (TypeError, ValueError):
                return jsonify({"error": "Escribe un monto válido."}), 400
            if not math.isfinite(amount) or amount < 0 or amount > 999_999_999_999:
                return jsonify({"error": "El monto debe ser mayor o igual a cero y tener hasta 12 cifras."}), 400

        raw_date = expense_data.get("date")
        if raw_date not in (None, ""):
            if not isinstance(raw_date, str):
                return jsonify({"error": "Escribe una fecha válida."}), 400
            try:
                expense_date = date.fromisoformat(raw_date).isoformat()
            except ValueError:
                return jsonify({"error": "Escribe una fecha válida."}), 400

        raw_vendor = expense_data.get("vendor")
        if raw_vendor not in (None, ""):
            if not isinstance(raw_vendor, str) or len(raw_vendor.strip()) > 160:
                return jsonify({"error": "El proveedor debe tener hasta 160 caracteres."}), 400
            vendor = raw_vendor.strip() or None

        category = expense_data.get("category", "otros")
        if not isinstance(category, str) or category not in EXPENSE_CATEGORIES:
            return jsonify({"error": "Selecciona una categoría de gasto válida."}), 400
        document_type = "recibo"

    with get_db() as connection:
        file_record = connection.execute(
            "SELECT id FROM files WHERE id = ? AND owner_id = ?",
            (file_id, g.user_id),
        ).fetchone()
        if file_record is None:
            return jsonify({"error": "No se encontró el archivo."}), 404
        connection.execute(
            "UPDATE files SET document_type = ? WHERE id = ? AND owner_id = ?",
            (document_type, file_id, g.user_id),
        )
        existing_expense = connection.execute(
            "SELECT id, transaction_id FROM expenses WHERE file_id = ? AND owner_id = ?",
            (file_id, g.user_id),
        ).fetchone()
        if expense_data is None:
            if existing_expense:
                if existing_expense["transaction_id"]:
                    connection.execute(
                        "DELETE FROM transactions WHERE id = ? AND owner_id = ? AND source = 'recibo'",
                        (existing_expense["transaction_id"], g.user_id),
                    )
                connection.execute(
                    "DELETE FROM expenses WHERE id = ? AND owner_id = ?",
                    (existing_expense["id"], g.user_id),
                )
        elif existing_expense:
            transaction_id = existing_expense["transaction_id"] or uuid.uuid4().hex
            connection.execute(
                "UPDATE expenses SET amount = ?, expense_date = ?, vendor = ?, category = ?, transaction_id = ? "
                "WHERE id = ? AND owner_id = ?",
                (amount, expense_date, vendor, category, transaction_id, existing_expense["id"], g.user_id),
            )
            if amount is not None and amount > 0:
                transaction_date = expense_date or date.today().isoformat()
                connection.execute(
                    "INSERT INTO transactions "
                    "(id, owner_id, transaction_type, amount_cents, transaction_date, category, nature, "
                    "vendor, description, source, external_id, file_id, created_at) "
                    "VALUES (?, ?, 'gasto', ?, ?, ?, 'variable', ?, ?, 'recibo', ?, ?, ?) "
                    "ON CONFLICT(id) DO UPDATE SET amount_cents = excluded.amount_cents, "
                    "transaction_date = excluded.transaction_date, category = excluded.category, "
                    "vendor = excluded.vendor, description = excluded.description",
                    (
                        transaction_id,
                        g.user_id,
                        round(amount * 100),
                        transaction_date,
                        category,
                        vendor,
                        f"Gasto asociado al recibo {file_id}",
                        f"receipt:{file_id}",
                        file_id,
                        now_iso(),
                    ),
                )
            elif existing_expense["transaction_id"]:
                connection.execute(
                    "DELETE FROM transactions WHERE id = ? AND owner_id = ? AND source = 'recibo'",
                    (existing_expense["transaction_id"], g.user_id),
                )
                connection.execute(
                    "UPDATE expenses SET transaction_id = NULL WHERE id = ? AND owner_id = ?",
                    (existing_expense["id"], g.user_id),
                )
        else:
            transaction_id = uuid.uuid4().hex
            connection.execute(
                "INSERT INTO expenses "
                "(id, owner_id, file_id, amount, expense_date, vendor, category, created_at, transaction_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (transaction_id, g.user_id, file_id, amount, expense_date, vendor, category, now_iso(), transaction_id),
            )
            if amount is not None and amount > 0:
                connection.execute(
                    "INSERT INTO transactions "
                    "(id, owner_id, transaction_type, amount_cents, transaction_date, category, nature, "
                    "vendor, description, source, external_id, file_id, created_at) "
                    "VALUES (?, ?, 'gasto', ?, ?, ?, 'variable', ?, ?, 'recibo', ?, ?, ?)",
                    (
                        transaction_id,
                        g.user_id,
                        round(amount * 100),
                        expense_date or date.today().isoformat(),
                        category,
                        vendor,
                        f"Gasto asociado al recibo {file_id}",
                        f"receipt:{file_id}",
                        file_id,
                        now_iso(),
                    ),
                )
    return jsonify({"updated": True, "document_type": document_type, "expense": expense_data})


@app.get("/api/files/<file_id>/download")
@require_auth
def download_file(file_id):
    with get_db() as connection:
        file_record = connection.execute(
            "SELECT stored_name, original_name FROM files WHERE id = ? AND owner_id = ?",
            (file_id, g.user_id),
        ).fetchone()
    if file_record is None:
        return jsonify({"error": "No se encontró el archivo."}), 404

    try:
        decrypted = read_encrypted_file(UPLOAD_DIR / file_record["stored_name"])
    except OSError:
        app.logger.exception("No se pudo leer el archivo cifrado.")
        return jsonify({"error": "No se pudo leer el archivo protegido."}), 500
    except Exception:
        app.logger.exception("Falló el descifrado del archivo solicitado.")
        return jsonify({"error": "No se pudo descifrar el archivo. Comprueba la clave de cifrado."}), 500
    from io import BytesIO

    return send_file(
        BytesIO(decrypted),
        as_attachment=True,
        download_name=file_record["original_name"],
    )


@app.delete("/api/files/<file_id>")
@require_auth
def delete_file(file_id):
    with get_db() as connection:
        file_record = connection.execute(
            "SELECT stored_name FROM files WHERE id = ? AND owner_id = ?",
            (file_id, g.user_id),
        ).fetchone()
        if file_record is None:
            return jsonify({"error": "No se encontró el archivo."}), 404
        connection.execute(
            "DELETE FROM transactions WHERE file_id = ? AND owner_id = ? AND source = 'recibo'",
            (file_id, g.user_id),
        )
        connection.execute("DELETE FROM files WHERE id = ? AND owner_id = ?", (file_id, g.user_id))

    file_path = UPLOAD_DIR / file_record["stored_name"]
    try:
        file_path.unlink(missing_ok=True)
    except OSError:
        app.logger.exception("No se pudo eliminar el archivo almacenado.")
        return jsonify({"error": "No se pudo eliminar el archivo almacenado."}), 500
    return jsonify({"deleted": True})


@app.errorhandler(413)
def file_too_large(_error):
    return jsonify({"error": "La carga supera el límite de 25 MB, incluyendo los datos de envío."}), 413


@app.errorhandler(404)
def route_not_found(error):
    if request.path.startswith("/api/"):
        return jsonify(
            {"error": "No se encontró esta ruta de la API. Si acabas de actualizar Financia, reinicia Flask."}
        ), 404
    return error


@app.errorhandler(405)
def method_not_allowed(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "El método de esta solicitud no está permitido para la ruta de la API."}), 405
    return error


@app.errorhandler(500)
def internal_server_error(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Ocurrió un error interno al procesar la solicitud de la API."}), 500
    return error


if not os.environ.get("FINANCIA_SECRET_KEY"):
    app.logger.warning("FINANCIA_SECRET_KEY no está configurada; las sesiones locales caducarán al reiniciar.")

initialize_database()
process_due_recurring_transactions()


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
