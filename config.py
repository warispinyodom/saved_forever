import os
import secrets

from dotenv import load_dotenv

load_dotenv()

force_https = os.getenv("FLASK_FORCE_HTTPS", "false").lower() == "true"


class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)
    WTF_CSRF_ENABLED = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = force_https
    FORCE_HTTPS = force_https
