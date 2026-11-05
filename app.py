import base64
import hashlib
import io
import json
import os
import secrets
import sqlite3
import string
from functools import wraps
from pathlib import Path

import pyotp
import qrcode
from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from zxcvbn import zxcvbn

ROOT = Path(__file__).resolve().parent
INSTANCE = ROOT / "instance"
INSTANCE.mkdir(exist_ok=True)
DB_PATH = INSTANCE / "password_suite.db"
KEY_PATH = INSTANCE / "app.key"

if not KEY_PATH.exists():
    KEY_PATH.write_bytes(secrets.token_bytes(32))
try:
    os.chmod(KEY_PATH, 0o600)
except OSError:
    pass

app = Flask(__name__)
app.config.update(
    SECRET_KEY=KEY_PATH.read_bytes(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=False,  # localhost HTTP only; use HTTPS if exposing beyond localhost
    PERMANENT_SESSION_LIFETIME=900,
)

AMBIGUOUS = "O0Il1|\x60'\\""
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS account (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT,
            mfa_enabled INTEGER NOT NULL DEFAULT 0,
            recovery_hashes TEXT NOT NULL DEFAULT '[]'
        )""")

init_db()

def account():
    with db() as con:
        return con.execute("SELECT * FROM account WHERE id=1").fetchone()

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

def generate_password(length, use_lower, use_upper, use_digits, use_symbols, avoid_ambiguous):
    pools = []
    if use_lower: pools.append(string.ascii_lowercase)
    if use_upper: pools.append(string.ascii_uppercase)
    if use_digits: pools.append(string.digits)
    if use_symbols: pools.append(SYMBOLS)
    if avoid_ambiguous:
        pools = ["".join(c for c in pool if c not in AMBIGUOUS) for pool in pools]
    pools = [p for p in pools if p]
    if not pools:
        raise ValueError("Select at least one character set.")
    if length < len(pools):
        raise ValueError(f"Length must be at least {len(pools)} for the selected character sets.")
    alphabet = "".join(pools)
    chars = [secrets.choice(pool) for pool in pools]
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; img-src 'self' data:"
    )
    return response

@app.route("/")
def index():
    if not account():
        return redirect(url_for("setup"))
    if not session.get("authenticated"):
        return redirect(url_for("login"))
    return render_template("index.html", username=account()["username"])

@app.route("/setup", methods=["GET", "POST"])
def setup():
    if account():
        return redirect(url_for("login"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        if len(username) < 3:
            flash("Username must contain at least 3 characters.", "error")
        elif len(password) < 12:
            flash("Use at least 12 characters for the master password.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        else:
            secret = pyotp.random_base32()
            with db() as con:
                con.execute(
                    "INSERT INTO account (id, username, password_hash, totp_secret, mfa_enabled) VALUES (1, ?, ?, ?, 0)",
                    (username, generate_password_hash(password, method="scrypt"), secret),
                )
            session["setup_pending"] = True
            return redirect(url_for("enroll_mfa"))
    return render_template("setup.html")

@app.route("/mfa-enroll", methods=["GET", "POST"])
def enroll_mfa():
    row = account()
    if not row:
        return redirect(url_for("setup"))
    if not session.get("setup_pending") and not session.get("authenticated"):
        return redirect(url_for("login"))
    secret = row["totp_secret"]
    if not secret:
        return redirect(url_for("login"))
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=row["username"], issuer_name="Local Password Security Suite")
    qr = qrcode.make(uri)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    qr_data = base64.b64encode(buffer.getvalue()).decode()
    if request.method == "POST":
        token = request.form.get("token", "").replace(" ", "")
        if pyotp.TOTP(secret).verify(token, valid_window=1):
            recovery = [secrets.token_urlsafe(9) for _ in range(8)]
            hashes = [generate_password_hash(code) for code in recovery]
            with db() as con:
                con.execute("UPDATE account SET mfa_enabled=1, recovery_hashes=? WHERE id=1",
                            (json.dumps(hashes),))
            session.clear()
            return render_template("recovery.html", recovery=recovery)
        flash("That authenticator code was not accepted. Try again.", "error")
    return render_template("mfa_enroll.html", qr_data=qr_data, secret=secret)

@app.route("/login", methods=["GET", "POST"])
def login():
    row = account()
    if not row:
        return redirect(url_for("setup"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        token = request.form.get("token", "").strip()
        recovery_code = request.form.get("recovery_code", "").strip()
        if username != row["username"] or not check_password_hash(row["password_hash"], password):
            flash("Invalid username or master password.", "error")
        elif not row["mfa_enabled"]:
            session["setup_pending"] = True
            return redirect(url_for("enroll_mfa"))
        else:
            verified = pyotp.TOTP(row["totp_secret"]).verify(token, valid_window=1) if token else False
            hashes = json.loads(row["recovery_hashes"] or "[]")
            used_index = next((i for i, h in enumerate(hashes) if recovery_code and check_password_hash(h, recovery_code)), None)
            if verified:
                session.clear()
                session["authenticated"] = True
                session.permanent = True
                return redirect(url_for("index"))
            if used_index is not None:
                hashes.pop(used_index)
                with db() as con:
                    con.execute("UPDATE account SET recovery_hashes=? WHERE id=1", (json.dumps(hashes),))
                session.clear()
                session["authenticated"] = True
                session.permanent = True
                flash("A recovery code was used. Generate new recovery codes after signing in.", "warning")
                return redirect(url_for("index"))
            flash("MFA verification failed. Enter your 6-digit code or a recovery code.", "error")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/generate", methods=["POST"])
@login_required
def generate():
    try:
        length = int(request.form.get("length", "20"))
        if not 8 <= length <= 128:
            raise ValueError("Choose a password length between 8 and 128.")
        password = generate_password(
            length,
            request.form.get("lower") == "on",
            request.form.get("upper") == "on",
            request.form.get("digits") == "on",
            request.form.get("symbols") == "on",
            request.form.get("avoid_ambiguous") == "on",
        )
        return render_template("index.html", username=account()["username"], generated=password)
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("index"))

@app.route("/check", methods=["POST"])
@login_required
def check():
    password = request.form.get("password", "")
    if not password:
        flash("Enter a password to analyse.", "error")
        return redirect(url_for("index"))
    result = zxcvbn(password)
    score = result["score"]
    labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]
    feedback = result.get("feedback", {})
    suggestions = feedback.get("suggestions", [])
    warning = feedback.get("warning", "")
    # Do not log or persist the submitted password.
    return render_template(
        "index.html", username=account()["username"],
        analysis={"score": score, "label": labels[score],
                  "guesses": result.get("guesses", 0),
                  "crack": result.get("crack_times_display", {}).get("offline_slow_hashing_1e4_per_second", "Unknown"),
                  "warning": warning, "suggestions": suggestions}
    )

@app.route("/recovery-regenerate", methods=["POST"])
@login_required
def recovery_regenerate():
    recovery = [secrets.token_urlsafe(9) for _ in range(8)]
    hashes = [generate_password_hash(code) for code in recovery]
    with db() as con:
        con.execute("UPDATE account SET recovery_hashes=? WHERE id=1", (json.dumps(hashes),))
    return render_template("recovery.html", recovery=recovery)

if __name__ == "__main__":
    # Bind only to loopback: this app is intended for this computer only.
    app.run(host="127.0.0.1", port=5000, debug=False)
