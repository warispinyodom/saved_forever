import json
import logging
import os
import re
import uuid
from datetime import datetime
from decimal import Decimal, InvalidOperation
from functools import wraps
from io import BytesIO

import firebase_admin
from dotenv import load_dotenv
from firebase_admin import auth as firebase_auth
from firebase_admin import credentials, db
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

supabase_url = os.getenv("SUPABASE_URL")
supabase_key = (
    os.getenv("SUPABASE_SECRET_KEY")
    or os.getenv("SUPABASE_KEY")
    or os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    or os.getenv("SUPABASE_ANON_KEY")
)
SUPABASE_BUCKET = os.getenv("SUPABASE_BUCKET", "portfolio-images")


def get_supabase_client() -> Client:
    if not supabase_url or not supabase_key:
        logger.warning("Supabase URL หรือ Key ยังไม่ได้ตั้งค่าใน Environment Variables")
        return None
    try:
        return create_client(supabase_url, supabase_key)
    except Exception as err:
        logger.error(f"ไม่สามารถสร้าง Supabase Client ได้: {err}")
        return None


supabase: Client = get_supabase_client()

ALLOWED_IMAGE_TYPES = {
    "png": ("PNG", "image/png"),
    "jpg": ("JPEG", "image/jpeg"),
    "jpeg": ("JPEG", "image/jpeg"),
    "webp": ("WEBP", "image/webp"),
}


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


def fetch_user_dashboard_data(user_id):
    raw_games = db.reference("games").order_by_key().limit_to_first(100).get() or {}
    raw_goals = db.reference("savings_goals").order_by_key().limit_to_first(200).get() or {}

    games_dict = {}
    active_games = []
    if isinstance(raw_games, dict):
        for g_id, val in raw_games.items():
            if isinstance(val, dict):
                g_item = dict(val)
                g_item["id"] = str(g_id)
                g_item["active"] = 1 if g_item.get("active", 1) in (1, True, "1", "on") else 0
                g_item["price_cents"] = int(g_item.get("price_cents", 0))
                games_dict[str(g_id)] = g_item
                if g_item["active"] == 1:
                    active_games.append(g_item)

    active_games.sort(key=lambda x: str(x.get("name", "")).lower())

    user_goals = []
    if isinstance(raw_goals, dict):
        for goal_id, val in raw_goals.items():
            if isinstance(val, dict) and str(val.get("user_id")) == str(user_id):
                goal = dict(val)
                goal["id"] = str(goal_id)
                gid = str(goal.get("game_id"))
                game_info = games_dict.get(gid, {})
                goal["game_name"] = game_info.get("name", "เกมที่ถูกลบ")
                goal["price_cents"] = game_info.get("price_cents", goal.get("target_cents", 0))
                goal["target_cents"] = int(goal.get("target_cents", 0))
                goal["saved_cents"] = int(goal.get("saved_cents", 0))
                user_goals.append(goal)

    user_goals.sort(key=lambda x: str(x.get("created_at", "")), reverse=True)
    return active_games, user_goals


def fetch_admin_dashboard_data():
    raw_games = db.reference("games").order_by_key().limit_to_first(200).get() or {}
    raw_goals = db.reference("savings_goals").order_by_key().limit_to_first(500).get() or {}

    goals_list = []
    if isinstance(raw_goals, dict):
        for g_id, g_val in raw_goals.items():
            if isinstance(g_val, dict):
                goal = dict(g_val)
                goal["id"] = str(g_id)
                goals_list.append(goal)

    game_goals_map = {}
    total_goals_count = len(goals_list)
    total_saved_all = 0

    for g in goals_list:
        gid = str(g.get("game_id"))
        saved = int(g.get("saved_cents", 0))
        total_saved_all += saved
        if gid not in game_goals_map:
            game_goals_map[gid] = {"count": 0, "saved": 0}
        game_goals_map[gid]["count"] += 1
        game_goals_map[gid]["saved"] += saved

    games = []
    if isinstance(raw_games, dict):
        for key, val in raw_games.items():
            if isinstance(val, dict):
                game = dict(val)
                game_id_str = str(key)
                game["id"] = game_id_str
                game["active"] = 1 if game.get("active", 1) in (1, True, "1", "on") else 0
                game["price_cents"] = int(game.get("price_cents", 0))
                game_stats = game_goals_map.get(game_id_str, {"count": 0, "saved": 0})
                game["goal_count"] = game_stats["count"]
                game["total_saved_cents"] = game_stats["saved"]
                games.append(game)

    games.sort(key=lambda x: str(x.get("created_at", "")), reverse=True)

    stats = {
        "total_games": len(games),
        "active_games": sum(1 for g in games if g["active"] == 1),
        "total_goals": total_goals_count,
        "total_saved_cents": total_saved_all,
    }

    return games, stats


# --- Routes & Controllers ---
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
            files = client.storage.from_(SUPABASE_BUCKET).list(
                f"users/{user_id}",
                options={"limit": 50, "sortBy": {"column": "created_at", "order": "desc"}}
            )
        except Exception:
            logger.exception("Failed to list files from Supabase Storage.")
            flash("ไม่สามารถโหลดรายการไฟล์จาก Supabase ได้ในขณะนี้", "danger")

    games, goals = fetch_user_dashboard_data(user_id)

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
    game_id = request.form.get("game_id", "").strip()
    if not game_id:
        flash("กรุณาเลือกเกมที่ถูกต้อง", "danger")
        return redirect(url_for("user_dashboard"))

    # 1. ตรวจสอบป้องกันการสร้างเป้าหมายซ้ำสำหรับเกมเดิม
    raw_goals = db.reference("savings_goals").order_by_key().limit_to_first(200).get() or {}
    if isinstance(raw_goals, dict):
        for g_id, g_val in raw_goals.items():
            if isinstance(g_val, dict) and str(g_val.get("user_id")) == str(session["user_id"]) and str(g_val.get("game_id")) == str(game_id):
                flash("คุณตั้งเป้าหมายออมเงินสำหรับเกมนี้อยู่แล้ว สามารถแก้ไขยอดออมหรือลบรายการเดิมได้", "warning")
                return redirect(url_for("user_dashboard"))

    game_ref = db.reference(f"games/{game_id}")
    game_data = game_ref.get()
    if not game_data or not (game_data.get("active") in (1, True, "1", "on")):
        flash("ไม่พบเกมที่เลือก หรือเกมนี้ยังไม่เปิดให้ใช้งาน", "danger")
        return redirect(url_for("user_dashboard"))

    raw_target = request.form.get("target_amount", "").strip()
    target_cents = parse_amount_cents(raw_target) if raw_target else int(game_data.get("price_cents", 0))
    if target_cents is None or target_cents <= 0:
        flash("จำนวนเงินเป้าหมายต้องมากกว่า 0 และใส่ทศนิยมได้ไม่เกิน 2 ตำแหน่ง", "danger")
        return redirect(url_for("user_dashboard"))

    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    db.reference("savings_goals").push({
        "user_id": session["user_id"],
        "game_id": game_id,
        "target_cents": target_cents,
        "saved_cents": 0,
        "created_at": now_str,
    })

    flash("เพิ่มเป้าหมายการออมแล้ว", "success")
    return redirect(url_for("user_dashboard"))


@app.route("/user/savings/<goal_id>/deposit", methods=["POST"])
@user_required
def deposit_savings(goal_id):
    amount_cents = parse_amount_cents(request.form.get("amount", "").strip())
    if amount_cents is None:
        flash("จำนวนเงินออมต้องมากกว่า 0 และใส่ทศนิยมได้ไม่เกิน 2 ตำแหน่ง", "danger")
        return redirect(url_for("user_dashboard"))

    goal_ref = db.reference(f"savings_goals/{goal_id}")
    goal = goal_ref.get()
    if not goal or str(goal.get("user_id")) != str(session["user_id"]):
        flash("ไม่พบเป้าหมายการออมนี้", "danger")
        return redirect(url_for("user_dashboard"))

    target_cents = int(goal.get("target_cents", 0))
    saved_cents = int(goal.get("saved_cents", 0))
    remaining_cents = target_cents - saved_cents

    if amount_cents > remaining_cents:
        flash("จำนวนเงินออมเกินยอดที่ยังขาดอยู่", "warning")
        return redirect(url_for("user_dashboard"))

    new_saved = saved_cents + amount_cents
    goal_ref.update({"saved_cents": new_saved})

    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    db.reference("savings_transactions").push({
        "goal_id": goal_id,
        "amount_cents": amount_cents,
        "created_at": now_str,
    })

    flash("บันทึกเงินออมแล้ว", "success")
    return redirect(url_for("user_dashboard"))


@app.route("/user/savings/<goal_id>/update", methods=["POST"])
@user_required
def update_savings_goal(goal_id):
    goal_ref = db.reference(f"savings_goals/{goal_id}")
    goal = goal_ref.get()
    if not goal or str(goal.get("user_id")) != str(session["user_id"]):
        flash("ไม่พบเป้าหมายการออมนี้", "danger")
        return redirect(url_for("user_dashboard"))

    raw_target = request.form.get("target_amount", "").strip()
    raw_saved = request.form.get("saved_amount", "").strip()

    updates = {}
    if raw_target:
        target_cents = parse_amount_cents(raw_target)
        if target_cents is None or target_cents <= 0:
            flash("จำนวนเงินเป้าหมายต้องมากกว่า 0 บาท", "danger")
            return redirect(url_for("user_dashboard"))
        updates["target_cents"] = target_cents

    if raw_saved:
        try:
            saved_cents = int(Decimal(raw_saved) * 100) if Decimal(raw_saved) >= 0 else None
        except Exception:
            saved_cents = None

        if saved_cents is None:
            flash("จำนวนเงินออมสะสมต้องไม่ติดลบ", "danger")
            return redirect(url_for("user_dashboard"))

        current_target = updates.get("target_cents", int(goal.get("target_cents", 0)))
        if saved_cents > current_target:
            flash("จำนวนเงินออมสะสมต้องไม่เกินเป้าหมาย", "warning")
            return redirect(url_for("user_dashboard"))

        updates["saved_cents"] = saved_cents

    if updates:
        goal_ref.update(updates)
        flash("อัปเดตข้อมูลเป้าหมายการออมเรียบร้อยแล้ว", "success")
    else:
        flash("ไม่มีการเปลี่ยนแปลงข้อมูล", "info")

    return redirect(url_for("user_dashboard"))


@app.route("/user/savings/<goal_id>/delete", methods=["POST"])
@user_required
def delete_savings_goal(goal_id):
    goal_ref = db.reference(f"savings_goals/{goal_id}")
    goal = goal_ref.get()
    if not goal or str(goal.get("user_id")) != str(session["user_id"]):
        flash("ไม่พบเป้าหมายการออมนี้", "danger")
        return redirect(url_for("user_dashboard"))

    goal_ref.delete()
    flash("ลบเป้าหมายการออมแล้ว", "success")
    return redirect(url_for("user_dashboard"))


@app.route("/admin")
@admin_required
def admin_dashboard():
    games, stats = fetch_admin_dashboard_data()
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

    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    db.reference("games").push({
        "name": name,
        "description": description,
        "price_cents": price_cents,
        "active": 1,
        "created_at": now_str,
    })
    flash("เพิ่มรายการเกมเป้าหมายออมเงินสำเร็จแล้ว", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/games/<game_id>/update", methods=["POST"])
@admin_required
def update_game(game_id):
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    price_cents = parse_amount_cents(request.form.get("price", "").strip())
    if not name or len(name) > 120 or len(description) > 1000 or price_cents is None:
        flash("ข้อมูลเกมไม่ถูกต้อง กรุณาตรวจสอบชื่อ รายละเอียด และราคา", "danger")
        return redirect(url_for("admin_dashboard"))

    active = 1 if request.form.get("active") in ("on", "1") else 0
    game_ref = db.reference(f"games/{game_id}")
    if not game_ref.get():
        flash("ไม่พบรายการเกมที่ต้องการแก้ไข", "danger")
        return redirect(url_for("admin_dashboard"))

    game_ref.update({
        "name": name,
        "description": description,
        "price_cents": price_cents,
        "active": active,
    })
    flash("บันทึกการแก้ไขรายการเกมเรียบร้อยแล้ว", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/games/<game_id>/delete", methods=["POST"])
@admin_required
def delete_game(game_id):
    game_ref = db.reference(f"games/{game_id}")
    if not game_ref.get():
        flash("ไม่พบรายการเกมที่ต้องการลบ", "danger")
        return redirect(url_for("admin_dashboard"))

    raw_goals = db.reference("savings_goals").order_by_key().limit_to_first(500).get() or {}
    has_goals = any(isinstance(v, dict) and str(v.get("game_id")) == str(game_id) for v in raw_goals.values())

    if has_goals:
        flash("ลบรายการนี้ไม่ได้ เนื่องจากมีเป้าหมายการออมของผู้ใช้งานอยู่ ให้ใช้วิธีปิดการใช้งานแทน", "warning")
        return redirect(url_for("admin_dashboard"))

    game_ref.delete()
    flash("ลบรายการเกมเรียบร้อยแล้ว", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/games/batch", methods=["POST"])
@admin_required
def batch_game_actions():
    action = request.form.get("action", "").strip()
    game_ids = request.form.getlist("game_ids")

    if not game_ids:
        flash("กรุณาเลือกรายการอย่างน้อย 1 รายการเพื่อดำเนินการ", "warning")
        return redirect(url_for("admin_dashboard"))

    raw_goals = db.reference("savings_goals").order_by_key().limit_to_first(500).get() or {}
    goals_list = [v for v in raw_goals.values() if isinstance(v, dict)]

    if action == "delete":
        blocked_ids = set()
        for g in goals_list:
            blocked_ids.add(str(g.get("game_id")))

        deletable_ids = [gid for gid in game_ids if str(gid) not in blocked_ids]

        for gid in deletable_ids:
            db.reference(f"games/{gid}").delete()

        if blocked_ids and deletable_ids:
            flash(
                f"ลบรายการสำเร็จ {len(deletable_ids)} รายการ (มีบางรายการที่ลบไม่ได้เพราะมีผู้ใช้ออมเงินอยู่)",
                "warning",
            )
        elif not deletable_ids:
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
                game_ref = db.reference(f"games/{gid}")
                if game_ref.get():
                    game_ref.update({
                        "name": name,
                        "description": description,
                        "price_cents": price_cents,
                        "active": active,
                    })
                    updated_count += 1

        flash(f"บันทึกการแก้ไขสำเร็จทั้งหมด {updated_count} รายการ", "success")

    elif action == "toggle_active":
        target_status = 1 if request.form.get("active_status") == "1" else 0
        for gid in game_ids:
            game_ref = db.reference(f"games/{gid}")
            if game_ref.get():
                game_ref.update({"active": target_status})

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