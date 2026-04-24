from functools import wraps
from flask import jsonify, current_app
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from app.models.user import UserModel


def require_permissions(*required_permissions):
    """
    Decorator that protects a route behind JWT auth AND permission checks.

    Usage:
        @require_permissions("posts:write")
        @require_permissions("users:read", "users:write")   # must have ALL
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # 1. Verify JWT is present and valid
            try:
                verify_jwt_in_request()
            except Exception as e:
                return jsonify({"error": "Missing or invalid token", "detail": str(e)}), 401

            # 2. Load the current user from DB
            user_id = get_jwt_identity()
            user_model = UserModel(current_app.db)
            user = user_model.find_by_id(user_id)

            if not user:
                return jsonify({"error": "User not found"}), 401

            if not user.get("is_active"):
                return jsonify({"error": "Account is deactivated"}), 403

            # 3. Check every required permission
            user_permissions = set(user.get("permissions", []))
            missing = set(required_permissions) - user_permissions

            if missing:
                return jsonify({
                    "error": "Forbidden",
                    "message": "You lack the required permissions for this action.",
                    "required": list(required_permissions),
                    "missing": list(missing),
                }), 403

            # 4. Attach user to kwargs so the route can use it
            kwargs["current_user"] = user
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def require_any_permission(*required_permissions):
    """
    Like require_permissions but passes if the user has AT LEAST ONE
    of the listed permissions.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                verify_jwt_in_request()
            except Exception as e:
                return jsonify({"error": "Missing or invalid token", "detail": str(e)}), 401

            user_id = get_jwt_identity()
            user_model = UserModel(current_app.db)
            user = user_model.find_by_id(user_id)

            if not user:
                return jsonify({"error": "User not found"}), 401

            if not user.get("is_active"):
                return jsonify({"error": "Account is deactivated"}), 403

            user_permissions = set(user.get("permissions", []))
            if not user_permissions.intersection(required_permissions):
                return jsonify({
                    "error": "Forbidden",
                    "message": "You need at least one of the required permissions.",
                    "required_any": list(required_permissions),
                }), 403

            kwargs["current_user"] = user
            return fn(*args, **kwargs)
        return wrapper
    return decorator
