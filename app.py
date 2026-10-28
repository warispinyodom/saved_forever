import json
import logging
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation
from functools import wraps
from io import BytesIO
from pathlib import Path

import firebase_admin
from dotenv import load_dotenv
from firebase_admin import auth as firebase_auth
from firebase_admin import credentials
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect

from PIL import Image, UnidentifiedImageError
from supabase import Client, create_client

from config import Config

load_dotenv()
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

csrf = CSRFProtect(app)

csp = {
    "default-src": ["'self'"],
    "script-src": [
        "'self'",
        "'unsafe-inline'",
        "https://cdn.jsdelivr.net",
        "https://www.gstatic.com",
    ],
    "style-src": [
        "'self'",
        "'unsafe-inline'",
        "https://cdn.jsdelivr.net",
        "https://fonts.googleapis.com",
    ],
    "font-src": [
        "'self'",
        "https://cdn.jsdelivr.net",
        "https://fonts.gstatic.com",
        "data:",
    ],
    "img-src": ["'self'", "data:", "https://*.supabase.co"],
    "connect-src": [
        "'self'",
        "https://identitytoolkit.googleapis.com",
        "https://securetoken.googleapis.com",
    ],
}

Talisman(app, content_security_policy=csp, force_https=app.config["FORCE_HTTPS"])


def load_firebase_credentials():
    credentials_json = os.getenv("FIREBASE_CREDENTIALS")
    if not credentials_json:
        raise RuntimeError("FIREBASE_CREDENTIALS is required.")

    try:
        service_account = json.loads(credentials_json)
    except json.JSONDecodeError as error:
        raise RuntimeError("FIREBASE_CREDENTIALS must contain valid JSON.") from error

    if service_account.get("type") != "service_account":
        raise RuntimeError("FIREBASE_CREDENTIALS must be a service account.")

    database_url = os.getenv("FIREBASE_DATABASE_URL")
    options = {"databaseURL": database_url} if database_url else None
    try:
        return firebase_admin.get_app()
    except ValueError:
        return firebase_admin.initialize_app(
            credentials.Certificate(service_account),
            options=options,
        )


firebase_app = load_firebase_credentials()
firebase_project_id = firebase_app.project_id
firebase_api_key = os.getenv("FIREBASE_API_KEY")
firebase_auth_domain = os.getenv("FIREBASE_AUTH_DOMAIN") or (
    f"{firebase_project_id}.firebaseapp.com" if firebase_project_id else None
)
firebase_web_configured = bool(firebase_api_key and firebase_auth_domain)

# --- Supabase Safe Initialization (เพื่อไม่ให้ Vercel Deploy Crash) ---
supabase_url = os.getenv("SUPABASE_URL")
supabase_key = (
    os.getenv("SUPABASE_SECRET_KEY")
    or os.getenv("SUPABASE_KEY")
    or os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    or os.getenv("SUPABASE_ANON_KEY")
)
SUPABASE_BUCKET = os.getenv("SUPABASE_BUCKET", "portfolio-images")


def get_supabase_client() -> Client:
    """สร้างหรือดึง Supabase Client แบบปลอดภัย"""
    if not supabase_url or not supabase_key:
        logger.warning("Supabase URL หรือ Key ยังไม่ได้ตั้งค่าใน Environment Variables")
        return None
    try:
        return create_client(supabase_url, supabase_key)
    except Exception as err:
        logger.error(f"ไม่สามารถสร้าง Supabase Client ได้: {err}")
        return None


# ลองสร้าง Client ในระดับเริ่มต้น แต่ป้องกันการ Throw Exception ปิดกั้น Vercel
supabase: Client = get_supabase_client()

# --- SQLite Database Config (ปรับให้อยู่ใน /tmp/ เมื่อรันบน Vercel) ---
default_db_path = (
    Path("/tmp/savings.sqlite3") if os.getenv("VERCEL") else Path(app.instance_path) / "savings.sqlite3"
)
DATABASE_PATH = Path(os.getenv("SAVINGS_DATABASE", default_db_path))
DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

ALLOWED_IMAGE_TYPES = {
    "png": ("PNG", "image/png"),
    "jpg": ("JPEG", "image/jpeg"),
    "jpeg": ("JPEG", "image/jpeg"),
    "webp": ("WEBP", "image/webp"),
}


@contextmanager
def get_database():
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
    with get_database() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS games (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                price_cents INTEGER NOT NULL CHECK (price_cents > 0),
                active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS savings_goals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                game_id INTEGER NOT NULL REFERENCES games(id),
                target_cents INTEGER NOT NULL CHECK (target_cents > 0),
                saved_cents INTEGER NOT NULL DEFAULT 0 CHECK (saved_cents >= 0),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS savings_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                goal_id INTEGER NOT NULL REFERENCES savings_goals(id) ON DELETE CASCADE,
                amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )


initialize_database()


def parse_amount_cents(raw_value):
    try:
        amount = Decimal(raw_value)
        if not amount.is_finite() or amount <= 0 or amount.as_tuple().exponent < -2:
            return None
        cents = int(amount * 100)
    except (InvalidOperation, TypeError, ValueError):
        return None
    return cents if cents <= 100_000_000_000 else None


def valid_image(file_bytes, extension):
    expected_format, _ = ALLOWED_IMAGE_TYPES[extension]
    try:
        with Image.open(BytesIO(file_bytes)) as image:
            if image.format != expected_format:
                return False
            image.verify()
    except (UnidentifiedImageError, OSError, SyntaxError, ValueError):
        return False
    return True


def login_required(view):
    @wraps(view)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("กรุณาเข้าสู่ระบบก่อนใช้งาน", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return decorated_function


def admin_required(view):
    @wraps(view)
    @login_required
    def decorated_function(*args, **kwargs):
        if session.get("role") != "admin":
            flash("หน้านี้สำหรับผู้ดูแลระบบเท่านั้น", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)

    return decorated_function


def user_required(view):
    @wraps(view)
    @login_required
    def decorated_function(*args, **kwargs):
        if session.get("role", "user") != "user":
            flash("หน้านี้สำหรับผู้ใช้งานทั่วไปเท่านั้น", "warning")
            return redirect(url_for("admin_dashboard"))
        return view(*args, **kwargs)

    return decorated_function


def render_auth_page(template):
    return render_template(
        template,
        firebase_config={
            "apiKey": firebase_api_key,
            "authDomain": firebase_auth_domain,
        },
        firebase_web_configured=firebase_web_configured,
    )


@app.route("/")
def home():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))


@app.route("/login")
def login():
    return render_auth_page("login.html")


@app.route("/register")
def register():
    return render_auth_page("register.html")


@app.route("/api/auth/session", methods=["POST"])
def session_login():
    data = request.get_json(silent=True)
    id_token = data.get("idToken") if isinstance(data, dict) else None
    if not isinstance(id_token, str) or not id_token:
        return jsonify({"status": "error", "message": "A Firebase ID token is required."}), 400

    try:
        decoded_token = firebase_auth.verify_id_token(id_token, app=firebase_app, check_revoked=True)
    except (
        firebase_auth.InvalidIdTokenError,
        firebase_auth.ExpiredIdTokenError,
        firebase_auth.RevokedIdTokenError,
        firebase_auth.UserDisabledError,
    ):
        return jsonify({"status": "error", "message": "Invalid or expired token."}), 401
    except firebase_admin.exceptions.FirebaseError:
        logger.exception("Firebase token verification failed.")
        return jsonify({"status": "error", "message": "Authentication service is unavailable."}), 503

    session.clear()
    session["user_id"] = decoded_token["uid"]
    session["email"] = decoded_token.get("email")
    session["role"] = (
        "admin"
        if decoded_token.get("role") == "admin" or decoded_token.get("admin") is True
        else "user"
    )
    return jsonify({"status": "success"}), 200


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("ออกจากระบบเรียบร้อยแล้ว", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    destination = "admin_dashboard" if session.get("role") == "admin" else "user_dashboard"
    return redirect(url_for(destination))


@app.route("/user")
@app.route("/user/")
@user_required
def user_dashboard():
    global supabase
    user_id = session["user_id"]
    files = []

    client = supabase or get_supabase_client()
    if client:
        try:
            files = client.storage.from_(SUPABASE_BUCKET).list(f"users/{user_id}")
        except Exception:
            logger.exception("Failed to list files from Supabase Storage.")
            flash("ไม่สามารถโหลดรายการไฟล์จาก Supabase ได้ในขณะนี้", "danger")

    with get_database() as connection:
        games = connection.execute(
            "SELECT id, name, description, price_cents FROM games WHERE active = 1 ORDER BY name"
        ).fetchall()
        goals = connection.execute(
            """
            SELECT goals.id, goals.target_cents, goals.saved_cents, goals.created_at,
                   games.name AS game_name, games.price_cents
            FROM savings_goals AS goals
            JOIN games ON games.id = goals.game_id
            WHERE goals.user_id = ?
            ORDER BY goals.created_at DESC, goals.id DESC
            """,
            (user_id,),
        ).fetchall()

    return render_template(
        "user/dashboard.html",
        email=session.get("email"),
        files=files,
        supabase_url=supabase_url,
        bucket=SUPABASE_BUCKET,
        user_id=user_id,
        role=session.get("role", "user"),
        games=games,
        goals=goals,
    )


@app.route("/user/savings", methods=["POST"])
@user_required
def create_savings_goal():
    try:
        game_id = int(request.form.get("game_id", ""))
    except ValueError:
        flash("กรุณาเลือกเกมที่ถูกต้อง", "danger")
        return redirect(url_for("user_dashboard"))

    with get_database() as connection:
        game = connection.execute(
            "SELECT id, price_cents FROM games WHERE id = ? AND active = 1",
            (game_id,),
        ).fetchone()
        if game is None:
            flash("ไม่พบเกมที่เลือก หรือเกมนี้ยังไม่เปิดให้ใช้งาน", "danger")
            return redirect(url_for("user_dashboard"))

        raw_target = request.form.get("target_amount", "").strip()
        target_cents = parse_amount_cents(raw_target) if raw_target else game["price_cents"]
        if target_cents is None:
            flash("จำนวนเงินเป้าหมายต้องมากกว่า 0 และใส่ทศนิยมได้ไม่เกิน 2 ตำแหน่ง", "danger")
            return redirect(url_for("user_dashboard"))

        connection.execute(
            "INSERT INTO savings_goals (user_id, game_id, target_cents) VALUES (?, ?, ?)",
            (session["user_id"], game_id, target_cents),
        )

    flash("เพิ่มเป้าหมายการออมแล้ว", "success")
    return redirect(url_for("user_dashboard"))


@app.route("/user/savings/<int:goal_id>/deposit", methods=["POST"])
@user_required
def deposit_savings(goal_id):
    amount_cents = parse_amount_cents(request.form.get("amount", "").strip())
    if amount_cents is None:
        flash("จำนวนเงินออมต้องมากกว่า 0 และใส่ทศนิยมได้ไม่เกิน 2 ตำแหน่ง", "danger")
        return redirect(url_for("user_dashboard"))

    with get_database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        goal = connection.execute(
            """
            SELECT target_cents, saved_cents
            FROM savings_goals
            WHERE id = ? AND user_id = ?
            """,
            (goal_id, session["user_id"]),
        ).fetchone()
        if goal is None:
            flash("ไม่พบเป้าหมายการออมนี้", "danger")
            return redirect(url_for("user_dashboard"))

        remaining_cents = goal["target_cents"] - goal["saved_cents"]
        if amount_cents > remaining_cents:
            flash("จำนวนเงินออมเกินยอดที่ยังขาดอยู่", "warning")
            return redirect(url_for("user_dashboard"))

        connection.execute(
            "UPDATE savings_goals SET saved_cents = saved_cents + ? WHERE id = ? AND user_id = ?",
            (amount_cents, goal_id, session["user_id"]),
        )
        connection.execute(
            "INSERT INTO savings_transactions (goal_id, amount_cents) VALUES (?, ?)",
            (goal_id, amount_cents),
        )

    flash("บันทึกเงินออมแล้ว", "success")
    return redirect(url_for("user_dashboard"))


@app.route("/user/savings/<int:goal_id>/delete", methods=["POST"])
@user_required
def delete_savings_goal(goal_id):
    with get_database() as connection:
        result = connection.execute(
            "DELETE FROM savings_goals WHERE id = ? AND user_id = ?",
            (goal_id, session["user_id"]),
        )
        if result.rowcount == 0:
            flash("ไม่พบเป้าหมายการออมนี้", "danger")
            return redirect(url_for("user_dashboard"))

    flash("ลบเป้าหมายการออมแล้ว", "success")
    return redirect(url_for("user_dashboard"))


@app.route("/admin")
@admin_required
def admin_dashboard():
    with get_database() as connection:
        games = connection.execute(
            """
            SELECT games.id, games.name, games.description, games.price_cents,
                   games.active, games.created_at,
                   COUNT(savings_goals.id) AS goal_count,
                   COALESCE(SUM(savings_goals.saved_cents), 0) AS total_saved_cents
            FROM games
            LEFT JOIN savings_goals ON savings_goals.game_id = games.id
            GROUP BY games.id
            ORDER BY games.created_at DESC, games.id DESC
            """
        ).fetchall()

        stats = {
            "total_games": len(games),
            "active_games": sum(1 for g in games if g["active"]),
            "total_goals": sum(g["goal_count"] for g in games),
            "total_saved_cents": sum(g["total_saved_cents"] for g in games),
        }

    return render_template("admin/dashboard.html", email=session.get("email"), games=games, stats=stats)


@app.route("/admin/games", methods=["POST"])
@admin_required
def create_game():
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    price_cents = parse_amount_cents(request.form.get("price", "").strip())
    if not name or len(name) > 120:
        flash("ชื่อเกมต้องมีความยาว 1 ถึง 120 ตัวอักษร", "danger")
        return redirect(url_for("admin_dashboard"))
    if len(description) > 1000:
        flash("รายละเอียดเกมต้องไม่เกิน 1000 ตัวอักษร", "danger")
        return redirect(url_for("admin_dashboard"))
    if price_cents is None:
        flash("ราคาเกมต้องมากกว่า 0 และใส่ทศนิยมได้ไม่เกิน 2 ตำแหน่ง", "danger")
        return redirect(url_for("admin_dashboard"))

    with get_database() as connection:
        connection.execute(
            "INSERT INTO games (name, description, price_cents) VALUES (?, ?, ?)",
            (name, description, price_cents),
        )
    flash("เพิ่มรายการเกมเป้าหมายออมเงินสำเร็จแล้ว", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/games/<int:game_id>/update", methods=["POST"])
@admin_required
def update_game(game_id):
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    price_cents = parse_amount_cents(request.form.get("price", "").strip())
    if not name or len(name) > 120 or len(description) > 1000 or price_cents is None:
        flash("ข้อมูลเกมไม่ถูกต้อง กรุณาตรวจสอบชื่อ รายละเอียด และราคา", "danger")
        return redirect(url_for("admin_dashboard"))

    active = 1 if request.form.get("active") in ("on", "1") else 0
    with get_database() as connection:
        result = connection.execute(
            """
            UPDATE games SET name = ?, description = ?, price_cents = ?, active = ?
            WHERE id = ?
            """,
            (name, description, price_cents, active, game_id),
        )
        if result.rowcount == 0:
            flash("ไม่พบรายการเกมที่ต้องการแก้ไข", "danger")
            return redirect(url_for("admin_dashboard"))
    flash("บันทึกการแก้ไขรายการเกมเรียบร้อยแล้ว", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/games/<int:game_id>/delete", methods=["POST"])
@admin_required
def delete_game(game_id):
    with get_database() as connection:
        game = connection.execute("SELECT id FROM games WHERE id = ?", (game_id,)).fetchone()
        if game is None:
            flash("ไม่พบรายการเกมที่ต้องการลบ", "danger")
            return redirect(url_for("admin_dashboard"))

        goal_count = connection.execute(
            "SELECT COUNT(*) FROM savings_goals WHERE game_id = ?", (game_id,)
        ).fetchone()[0]
        if goal_count:
            flash("ลบรายการนี้ไม่ได้ เนื่องจากมีเป้าหมายการออมของผู้ใช้งานอยู่ ให้ใช้วิธีปิดการใช้งานแทน", "warning")
            return redirect(url_for("admin_dashboard"))

        connection.execute("DELETE FROM games WHERE id = ?", (game_id,))
    flash("ลบรายการเกมเรียบร้อยแล้ว", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/games/batch", methods=["POST"])
@admin_required
def batch_game_actions():
    action = request.form.get("action", "").strip()
    game_ids_raw = request.form.getlist("game_ids")

    if not game_ids_raw:
        flash("กรุณาเลือกรายการอย่างน้อย 1 รายการเพื่อดำเนินการ", "warning")
        return redirect(url_for("admin_dashboard"))

    try:
        game_ids = [int(gid) for gid in game_ids_raw]
    except ValueError:
        flash("รหัสรายการเกมไม่ถูกต้อง", "danger")
        return redirect(url_for("admin_dashboard"))

    with get_database() as connection:
        if action == "delete":
            placeholders = ",".join("?" * len(game_ids))
            goals_check = connection.execute(
                f"""
                SELECT game_id, COUNT(*) as cnt
                FROM savings_goals
                WHERE game_id IN ({placeholders})
                GROUP BY game_id
                """,
                game_ids,
            ).fetchall()

            blocked_ids = {row["game_id"] for row in goals_check if row["cnt"] > 0}
            deletable_ids = [gid for gid in game_ids if gid not in blocked_ids]

            if deletable_ids:
                del_placeholders = ",".join("?" * len(deletable_ids))
                connection.execute(f"DELETE FROM games WHERE id IN ({del_placeholders})", deletable_ids)

            if blocked_ids and deletable_ids:
                flash(
                    f"ลบรายการสำเร็จ {len(deletable_ids)} รายการ (มี {len(blocked_ids)} รายการที่ลบไม่ได้เพราะมีผู้ใช้ออมเงินอยู่)",
                    "warning",
                )
            elif blocked_ids and not deletable_ids:
                flash("ไม่สามารถลบรายการที่เลือกได้ เนื่องจากทุกรายการมีผู้ใช้ออมเงินอยู่ ให้ใช้วิธีปิดการใช้งานแทน", "danger")
            else:
                flash(f"ลบรายการเกมที่เลือกเรียบร้อยแล้ว {len(deletable_ids)} รายการ", "success")

        elif action == "update":
            updated_count = 0
            for gid in game_ids:
                name = request.form.get(f"name_{gid}", "").strip()
                description = request.form.get(f"description_{gid}", "").strip()
                price_raw = request.form.get(f"price_{gid}", "").strip()
                price_cents = parse_amount_cents(price_raw)
                active = 1 if request.form.get(f"active_{gid}") in ("on", "1") else 0

                if name and len(name) <= 120 and len(description) <= 1000 and price_cents is not None:
                    res = connection.execute(
                        """
                        UPDATE games
                        SET name = ?, description = ?, price_cents = ?, active = ?
                        WHERE id = ?
                        """,
                        (name, description, price_cents, active, gid),
                    )
                    if res.rowcount > 0:
                        updated_count += 1

            flash(f"บันทึกการแก้ไขสำเร็จทั้งหมด {updated_count} รายการ", "success")

        elif action == "toggle_active":
            target_status = 1 if request.form.get("active_status") == "1" else 0
            placeholders = ",".join("?" * len(game_ids))
            params = [target_status] + game_ids
            connection.execute(f"UPDATE games SET active = ? WHERE id IN ({placeholders})", params)
            status_text = "เปิดการใช้งาน" if target_status == 1 else "ปิดการใช้งาน"
            flash(f"ปรับสถานะเป็น{status_text}เรียบร้อยแล้ว {len(game_ids)} รายการ", "success")

        else:
            flash("รูปแบบคำสั่งไม่ถูกต้อง", "danger")

    return redirect(url_for("admin_dashboard"))


@app.route("/upload", methods=["POST"])
@user_required
def upload_file():
    global supabase
    uploaded_file = request.files.get("file")
    if uploaded_file is None or not uploaded_file.filename:
        flash("กรุณาเลือกไฟล์รูปภาพ", "danger")
        return redirect(url_for("dashboard"))

    extension = uploaded_file.filename.rsplit(".", 1)[-1].lower()
    if "." not in uploaded_file.filename or extension not in ALLOWED_IMAGE_TYPES:
        flash("รองรับเฉพาะไฟล์ PNG, JPG, JPEG และ WEBP", "danger")
        return redirect(url_for("dashboard"))

    file_bytes = uploaded_file.read()
    if not valid_image(file_bytes, extension):
        flash("ไฟล์ที่เลือกไม่ใช่รูปภาพชนิดที่ถูกต้อง", "danger")
        return redirect(url_for("dashboard"))

    client = supabase or get_supabase_client()
    if not client:
        flash("ไม่สามารถเชื่อมต่อ Supabase Storage ได้ กรุณาตรวจสอบการตั้งค่าคีย์", "danger")
        return redirect(url_for("dashboard"))

    safe_name = f"{uuid.uuid4().hex}.{extension}"
    file_path = f"users/{session['user_id']}/{safe_name}"
    _, content_type = ALLOWED_IMAGE_TYPES[extension]

    try:
        client.storage.from_(SUPABASE_BUCKET).upload(
            path=file_path,
            file=file_bytes,
            file_options={"content-type": content_type},
        )
    except Exception:
        logger.exception("Failed to upload image to Supabase Storage.")
        flash("อัปโหลดไฟล์ไม่สำเร็จ กรุณาลองใหม่", "danger")
    else:
        flash("อัปโหลดรูปภาพสำเร็จ", "success")

    return redirect(url_for("dashboard"))


@app.route("/delete-image/<filename>", methods=["POST"])
@user_required
def delete_image(filename):
    global supabase
    if not re.fullmatch(r"[0-9a-f]{32}\.(?:png|jpg|jpeg|webp)", filename):
        flash("ชื่อไฟล์รูปภาพไม่ถูกต้อง", "danger")
        return redirect(url_for("dashboard"))

    client = supabase or get_supabase_client()
    if not client:
        flash("ไม่สามารถเชื่อมต่อ Supabase Storage ได้", "danger")
        return redirect(url_for("dashboard"))

    file_path = f"users/{session['user_id']}/{filename}"
    try:
        client.storage.from_(SUPABASE_BUCKET).remove([file_path])
    except Exception:
        logger.exception("Failed to delete image from Supabase Storage.")
        flash("ลบรูปภาพไม่สำเร็จ กรุณาลองใหม่", "danger")
    else:
        flash("ลบรูปภาพสำเร็จ", "success")

    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("FLASK_PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true",
    )