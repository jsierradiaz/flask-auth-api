from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import create_access_token, get_jwt_identity, verify_jwt_in_request
from app.models.user import UserModel, PERMISSIONS, ROLE_PERMISSIONS

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["POST"])
def register():
    """
    POST /api/auth/register
    Body: { "email": "...", "password": "...", "role": "viewer|editor|manager|admin" }

    Creates a new user and assigns a preset permission bundle based on role.
    Defaults to "viewer" if no role is provided.
    """
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    role = data.get("role", "viewer")

    # ── Validation ───────────────────────────────────────────────────────────
    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    if len(password) < 6:
        return jsonify({"error": "password must be at least 6 characters"}), 400

    if role not in ROLE_PERMISSIONS:
        return jsonify({
            "error": f"Invalid role. Choose from: {list(ROLE_PERMISSIONS.keys())}"
        }), 400

    user_model = UserModel(current_app.db)

    if user_model.find_by_email(email):
        return jsonify({"error": "A user with that email already exists"}), 409

    # ── Create user with the role's permission bundle ────────────────────────
    permissions = list(ROLE_PERMISSIONS[role])
    user = user_model.create(email=email, password=password, permissions=permissions)

    return jsonify({
        "message": "User registered successfully",
        "user": user,
    }), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    POST /api/auth/login
    Body: { "email": "...", "password": "..." }

    Returns a JWT access token on success.
    """
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    user_model = UserModel(current_app.db)

    # Verify credentials
    raw_hash = user_model.get_raw_password(email)
    if not raw_hash or not user_model.verify_password(password, raw_hash):
        return jsonify({"error": "Invalid email or password"}), 401

    user = user_model.find_by_email(email)

    if not user.get("is_active"):
        return jsonify({"error": "This account has been deactivated"}), 403

    # Issue JWT — store user_id as the identity
    access_token = create_access_token(identity=user["id"])

    return jsonify({
        "message": "Login successful",
        "access_token": access_token,
        "token_type": "Bearer",
        "user": user,
    }), 200


@auth_bp.route("/me", methods=["GET"])
def me():
    """
    GET /api/auth/me
    Header: Authorization: Bearer <token>

    Returns the profile of the currently authenticated user.
    """
    try:
        verify_jwt_in_request()
    except Exception as e:
        return jsonify({"error": "Missing or invalid token", "detail": str(e)}), 401

    user_id = get_jwt_identity()
    user_model = UserModel(current_app.db)
    user = user_model.find_by_id(user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"user": user}), 200


@auth_bp.route("/permissions", methods=["GET"])
def list_permissions():
    """
    GET /api/auth/permissions

    Public endpoint — returns all available permissions and role bundles.
    Useful for frontends building permission UIs.
    """
    return jsonify({
        "all_permissions": sorted(PERMISSIONS),
        "role_bundles": {role: sorted(perms) for role, perms in ROLE_PERMISSIONS.items()},
    }), 200
