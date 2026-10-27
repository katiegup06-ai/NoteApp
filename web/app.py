"""NotesApp - a small grades application.

Deliberately insecure teaching app for the EPITA Computer Security course.
Do not deploy this anywhere real.
"""
import os
import csv
import io
import json
import hmac
import time
import base64
import hashlib
import subprocess

from werkzeug.exceptions import RequestEntityTooLarge
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
import psycopg2
import psycopg2.extras
from cryptography.exceptions import InvalidTag
from comment_crypto import load_key, encrypt_comment, decrypt_comment
from export_integrity import (
    hmac_sha256_hex, make_export_bundle, load_hmac_key, verify_bytes,
)
from flask import (
    Flask, request, session, redirect, url_for,
    render_template, Response, jsonify, abort,
)

# --- Configuration ------------------------------------------------------------
# All configuration comes from the environment (set in docker-compose.yml).
DB_HOST = os.environ.get("DB_HOST", "db")
DB_NAME = os.environ.get("DB_NAME", "notesapp")
DB_USER = os.environ.get("DB_USER", "notesapp")
DB_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "notesapp_pg_pw_2024")
JWT_SECRET = os.environ.get("JWT_SECRET", "s3cr3t")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-session-key")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
app.secret_key = SECRET_KEY
COMMENT_KEY = load_key()
load_hmac_key()
ph = PasswordHasher()


def is_argon2_hash(value: str) -> bool:
    return value.startswith("$argon2")

LOG_FILE = os.environ.get("NOTESAPP_LOG", "/var/log/notesapp/app.log")


def log(msg):
    """Very small access log. No rotation, no policy (see flaw #14)."""
    try:
        with open(LOG_FILE, "a") as fh:
            fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except OSError:
        pass


# --- Database -----------------------------------------------------------------
def get_db():
    conn = psycopg2.connect(
        host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD,
        cursor_factory=psycopg2.extras.RealDictCursor,
    )
    conn.autocommit = True
    return conn


# --- Encrypted comments -------------------------------------------------------
def _comment_for_display(note):
    try:
        return decrypt_comment(note["comment"], note["id"], COMMENT_KEY)
    except (InvalidTag, ValueError):
        app.logger.error("Comment verification failed for note %s", note["id"])
        abort(500, description="Stored comment could not be verified.")


def _decrypt_note_rows(notes):
    for note in notes:
        note["comment"] = _comment_for_display(note)
    return notes


# --- Minimal JWT (deliberately weak) ------------------------------------------
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def make_jwt(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url(json.dumps(header).encode())
    p = _b64url(json.dumps(payload).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


def verify_jwt(token: str):
    """Decode a JWT. Accepts alg:none (no signature) and HS256 with a short key.

    This is intentionally broken (flaw #4): an attacker can forge any identity
    by setting "alg":"none", and the HS256 key is trivially guessable.
    """
    try:
        h_b64, p_b64, sig_b64 = token.split(".")
    except ValueError:
        return None
    try:
        header = json.loads(_b64url_decode(h_b64))
        payload = json.loads(_b64url_decode(p_b64))
    except Exception:
        return None

    alg = header.get("alg", "").lower()
    if alg == "none":
        # No signature verification at all.
        return payload
    if alg == "hs256":
        signing_input = f"{h_b64}.{p_b64}".encode()
        expected = _b64url(hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest())
        if hmac.compare_digest(expected, sig_b64):
            return payload
        return None
    return None


def current_identity():
    """Return the acting identity from a Bearer JWT if present, else the session."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        payload = verify_jwt(auth[7:].strip())
        if payload:
            return payload
    if "user_id" in session:
        return {"user_id": session["user_id"], "username": session.get("username"),
                "role": session.get("role")}
    return None


# --- Auth helpers -------------------------------------------------------------
def login_required(role=None):
    if "user_id" not in session:
        return False
    if role and session.get("role") != role:
        return False
    return True


# --- Routes -------------------------------------------------------------------
@app.route("/")
def index():
    if "user_id" in session:
        role = session.get("role")
        if role == "student":
            return redirect(url_for("dashboard"))
        if role == "teacher":
            return redirect(url_for("teacher"))
        if role == "admin":
            return redirect(url_for("admin"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # Username concatenation stays for the later SQL injection lab.
        query = (
            "SELECT id, username, role, password FROM users "
            "WHERE username = '" + username + "'"
        )
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(query)
            row = cur.fetchone()
        except Exception as e:
            error = f"Query error: {e}"
            row = None

        authenticated = False
        if row:
            stored = row["password"]
            if is_argon2_hash(stored):
                try:
                    ph.verify(stored, password)
                    authenticated = True
                except (VerifyMismatchError, InvalidHash):
                    authenticated = False
            else:
                if stored == password:
                    authenticated = True
                    new_hash = ph.hash(password)
                    cur.execute(
                        "UPDATE users SET password = %s WHERE id = %s",
                        (new_hash, row["id"]),
                    )
                    log(f"upgraded {row['username']} to argon2")

        conn.close()

        if authenticated:
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["role"] = row["role"]
            session["token"] = make_jwt({
                "user_id": row["id"],
                "username": row["username"],
                "role": row["role"],
            })
            log(f"login success user={row['username']} role={row['role']}")
            return redirect(url_for("index"))

        if not error:
            error = "Invalid credentials."
        log(f"login failure username={username!r}")

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if not login_required():
        return redirect(url_for("login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT n.id, n.grade, n.comment, c.name AS class_name "
        "FROM notes n JOIN classes c ON c.id = n.class_id "
        "WHERE n.student_id = %s ORDER BY c.name",
        (session["user_id"],),
    )
    notes = cur.fetchall()
    conn.close()
    notes = _decrypt_note_rows(notes)
    return render_template("dashboard.html", notes=notes, token=session.get("token"))


@app.route("/api/notes/<int:note_id>")
def api_notes(note_id):
    ident = current_identity()
    if not ident:
        return jsonify({"error": "unauthorized"}), 401
    conn = get_db()
    cur = conn.cursor()
    # Flaw #7 (IDOR): the owner of the note is never checked. Any authenticated
    # caller can read any note id. Flaw #4: `ident` may come from a forged token.
    cur.execute(
        "SELECT n.id, n.student_id, n.class_id, n.grade, n.comment, "
        "u.username AS student, c.name AS class_name "
        "FROM notes n JOIN users u ON u.id = n.student_id "
        "JOIN classes c ON c.id = n.class_id WHERE n.id = %s",
        (note_id,),
    )
    note = cur.fetchone()
    conn.close()
    if not note:
        return jsonify({"error": "not found"}), 404
    note["comment"] = _comment_for_display(note)
    note["grade"] = float(note["grade"]) if note["grade"] is not None else None
    return jsonify(note)


@app.route("/teacher")
def teacher():
    if not login_required("teacher"):
        return redirect(url_for("login"))
    conn = get_db()
    cur = conn.cursor()
    # A teacher sees every class (no owner scoping - broken access control).
    cur.execute("SELECT id, name, teacher_id FROM classes ORDER BY name")
    classes = cur.fetchall()
    cur.execute(
        "SELECT n.id, n.grade, n.comment, n.student_id, n.class_id, "
        "u.username AS student, c.name AS class_name "
        "FROM notes n JOIN users u ON u.id = n.student_id "
        "JOIN classes c ON c.id = n.class_id ORDER BY c.name, u.username"
    )
    notes = cur.fetchall()
    cur.execute("SELECT id, username FROM users WHERE role = 'student' ORDER BY username")
    students = cur.fetchall()
    conn.close()
    notes = _decrypt_note_rows(notes)
    return render_template("teacher.html", classes=classes, notes=notes, students=students)


@app.route("/grades", methods=["POST"])
def grades():
    # Flaw #11: no CSRF token checked on this state-changing POST.
    if not login_required("teacher"):
        return redirect(url_for("login"))
    note_id = request.form.get("note_id", "").strip()
    student_id = request.form.get("student_id")
    class_id = request.form.get("class_id")
    grade = request.form.get("grade")
    comment = request.form.get("comment", "")
    conn = get_db()
    try:
        # One transaction keeps the new ID and its encrypted comment together.
        conn.autocommit = False
        with conn.cursor() as cur:
            if note_id:
                note_id = int(note_id)
                encrypted = encrypt_comment(comment, note_id, COMMENT_KEY)
                cur.execute(
                    "UPDATE notes SET grade = %s, comment = %s WHERE id = %s",
                    (grade, encrypted, note_id),
                )
            else:
                # Obtain the generated ID without ever writing the plaintext.
                cur.execute(
                    "INSERT INTO notes (student_id, class_id, grade, comment) "
                    "VALUES (%s, %s, %s, NULL) RETURNING id",
                    (student_id, class_id, grade),
                )
                note_id = cur.fetchone()["id"]
                encrypted = encrypt_comment(comment, note_id, COMMENT_KEY)
                cur.execute(
                    "UPDATE notes SET comment = %s WHERE id = %s",
                    (encrypted, note_id),
                )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    log(f"grade write by {session.get('username')} note_id={note_id}")
    return redirect(url_for("teacher"))


@app.route("/export.csv")
def export_csv():
    if not login_required("teacher"):
        return redirect(url_for("login"))
    class_id = request.args.get("class_id")
    conn = get_db()
    cur = conn.cursor()
    if class_id:
        cur.execute(
            "SELECT n.id, u.username AS student, c.name AS class, n.grade, n.comment "
            "FROM notes n JOIN users u ON u.id = n.student_id "
            "JOIN classes c ON c.id = n.class_id WHERE n.class_id = %s "
            "ORDER BY u.username",
            (class_id,),
        )
    else:
        cur.execute(
            "SELECT n.id, u.username AS student, c.name AS class, n.grade, n.comment "
            "FROM notes n JOIN users u ON u.id = n.student_id "
            "JOIN classes c ON c.id = n.class_id ORDER BY c.name, u.username"
        )
    rows = cur.fetchall()
    conn.close()
    rows = _decrypt_note_rows(rows)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["student", "class", "grade", "comment"])
    for r in rows:
        writer.writerow([r["student"], r["class"], r["grade"], r["comment"]])
       # Authenticate the exact UTF-8 bytes of the CSV.
    csv_bytes = buf.getvalue().encode("utf-8")
    digest = hmac_sha256_hex(csv_bytes)
    headers = {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    }

    if request.args.get("bundle") == "1":
        headers["Content-Disposition"] = (
            "attachment; filename=grades-with-hmac-sha256.zip"
        )
        headers["X-CSV-HMAC-SHA256"] = digest
        return Response(
            make_export_bundle(csv_bytes),
            mimetype="application/zip",
            headers=headers,
        )

    headers["Content-Disposition"] = "attachment; filename=grades.csv"
    headers["X-Content-HMAC-SHA256"] = digest
    return Response(csv_bytes, mimetype="text/csv", headers=headers)


@app.route("/verify-export", methods=["GET", "POST"])
def verify_export():
    if not login_required("teacher"):
        return redirect(url_for("login"))

    matches = None
    error = None
    status = 200

    if request.method == "POST":
        try:
            csv_file = request.files.get("csv_file")
            checksum_file = request.files.get("checksum_file")

            if (
                csv_file is None
                or not csv_file.filename
                or checksum_file is None
                or not checksum_file.filename
            ):
                raise ValueError("Choose both the CSV and HMAC files.")

            csv_limit = 5 * 1024 * 1024
            csv_bytes = csv_file.stream.read(csv_limit + 1)
            checksum_bytes = checksum_file.stream.read(4097)

            if len(csv_bytes) > csv_limit or len(checksum_bytes) > 4096:
                raise RequestEntityTooLarge()

            checksum_text = checksum_bytes.decode("utf-8")
            matches = verify_bytes(
                csv_bytes,
                checksum_text,
                filename=csv_file.filename,
            )

        except RequestEntityTooLarge:
            error = "Upload too large. The CSV limit is 5 MiB."
            status = 413

        except UnicodeError:
            error = "The HMAC file must contain valid UTF-8 text."
            status = 400

        except ValueError as exc:
            error = str(exc)
            status = 400

    return (
        render_template(
            "verify_export.html",
            matches=matches,
            error=error,
        ),
        status,
        {"Cache-Control": "no-store"},
    )

@app.route("/admin")
def admin():
    if not login_required("admin"):
        return redirect(url_for("login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role, teacher_id FROM users ORDER BY id")
    users = cur.fetchall()
    cur.execute("SELECT id, name, teacher_id FROM classes ORDER BY id")
    classes = cur.fetchall()
    conn.close()
    return render_template("admin.html", users=users, classes=classes,
                           ping_result=request.args.get("ping_result"))


@app.route("/admin/ping", methods=["POST"])
def admin_ping():
    # Flaw #11: no CSRF token. Flaw #9: command injection via os/system shell.
    if not login_required("admin"):
        return redirect(url_for("login"))
    host = request.form.get("host", "")
    # Host is concatenated straight into a shell command.
    cmd = "ping -c 1 " + host
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10,
        )
        output = result.stdout + result.stderr
    except Exception as e:
        output = str(e)
    log(f"admin ping host={host!r}")
    return render_template("admin.html", users=_all_users(), classes=_all_classes(),
                           ping_result=output)


def _all_users():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role, teacher_id FROM users ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    return rows


def _all_classes():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, name, teacher_id FROM classes ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    return rows


@app.route("/admin/users", methods=["POST"])
def admin_users():
    if not login_required("admin"):
        return redirect(url_for("login"))
    action = request.form.get("action")
    conn = get_db()
    cur = conn.cursor()
    if action == "create":
        cur.execute(
            "INSERT INTO users (username, password, role, teacher_id) "
            "VALUES (%s, %s, %s, %s)",
            (request.form.get("username"), request.form.get("password"),
             request.form.get("role", "student"), None),
        )
    elif action == "delete":
        cur.execute("DELETE FROM users WHERE id = %s", (request.form.get("user_id"),))
    conn.close()
    return redirect(url_for("admin"))


@app.route("/healthz")
def healthz():
    try:
        conn = get_db()
        conn.close()
        return "ok", 200
    except Exception as e:
        return f"db error: {e}", 500


if __name__ == "__main__":
    # Plain HTTP on purpose (flaw #3). Nginx + TLS is added in a later lab.
    app.run(host="0.0.0.0", port=5000, debug=True)
