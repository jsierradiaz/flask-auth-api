from flask import Blueprint, jsonify, current_app
from app.middleware.permissions import require_permissions
from app.models.user import UserModel

users_bp = Blueprint("users", __name__)


@users_bp.route("/", methods=["GET"])
@require_permissions("users:read")
def list_users(current_user):
    """
    GET /api/users/
    Required permission: users:read

    Returns a list of all users.
    """
    user_model = UserModel(current_app.db)
    users = user_model.find_all()
    return jsonify({"users": users, "count": len(users)}), 200


@users_bp.route("/<user_id>", methods=["GET"])
@require_permissions("users:read")
def get_user(user_id, current_user):
    """
    GET /api/users/<user_id>
    Required permission: users:read

    Returns a single user by ID.
    """
    user_model = UserModel(current_app.db)
    user = user_model.find_by_id(user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"user": user}), 200


@users_bp.route("/<user_id>/deactivate", methods=["PATCH"])
@require_permissions("users:delete")
def deactivate_user(user_id, current_user):
    """
    PATCH /api/users/<user_id>/deactivate
    Required permission: users:delete

    Deactivates a user account (soft delete).
    """
    # Prevent self-deactivation
    if user_id == current_user["id"]:
        return jsonify({"error": "You cannot deactivate your own account"}), 400

    user_model = UserModel(current_app.db)

    if not user_model.find_by_id(user_id):
        return jsonify({"error": "User not found"}), 404

    success = user_model.deactivate(user_id)
    if not success:
        return jsonify({"error": "Could not deactivate user"}), 500

    return jsonify({"message": f"User {user_id} has been deactivated"}), 200
