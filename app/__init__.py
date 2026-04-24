from flask import Flask
from flask_jwt_extended import JWTManager
from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()

jwt = JWTManager()
mongo_client = None
db = None


def create_app():
    app = Flask(__name__)

    # ── Config ──────────────────────────────────────────────────────────────
    app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "dev-secret")
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", 3600))

    # ── Extensions ──────────────────────────────────────────────────────────
    jwt.init_app(app)

    # ── Database ────────────────────────────────────────────────────────────
    global mongo_client, db
    mongo_client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017/auth_api"))
    db = mongo_client.get_default_database()
    app.db = db  # attach to app so routes can access it

    # ── Blueprints ──────────────────────────────────────────────────────────
    from app.routes.auth import auth_bp
    from app.routes.users import users_bp
    from app.routes.admin import admin_bp

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(users_bp, url_prefix="/api/users")
    app.register_blueprint(admin_bp, url_prefix="/api/admin")

    return app
