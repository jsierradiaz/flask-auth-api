from flask import Blueprint, request, jsonify, current_app
from app.middleware.permissions import require_permissions
from app.models.user import UserModel, PERMISSIONS

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/users/<user_id>/permissions", methods=["GET"])
@require_permissions("admin:access")
def get_user_permissions(user_id, current_user):
    """
    GET /api/admin/users/<user_id>/permissions
    Required permission: admin:access

    Returns a user's current permissions alongside ALL available permissions,
    so a frontend can build a diff/checkbox UI easily.
    """
    user_model = UserModel(current_app.db)
    user = user_model.find_by_id(user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    user_perms = set(user.get("permissions", []))

    return jsonify({
        "user_id": user_id,
        "email": user["email"],
        "permissions": {
            "granted": sorted(user_perms),
            "not_granted": sorted(PERMISSIONS - user_perms),
            "all_available": sorted(PERMISSIONS),
        },
    }), 200


@admin_bp.route("/users/<user_id>/permissions", methods=["PUT"])
@require_permissions("admin:manage_permissions")
def set_user_permissions(user_id, current_user):
    """
    PUT /api/admin/users/<user_id>/permissions
    Required permission: admin:manage_permissions
    Body: { "permissions": ["posts:read", "posts:write"] }

    Replaces the user's permission set entirely.
    """
    data = request.get_json(silent=True) or {}
    permissions = data.get("permissions")

    if not isinstance(permissions, list):
        return jsonify({"error": "'permissions' must be a list"}), 400

    user_model = UserModel(current_app.db)

    if not user_model.find_by_id(user_id):
        return jsonify({"error": "User not found"}), 404

    try:
        updated = user_model.set_permissions(user_id, permissions)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({
        "message": "Permissions updated successfully",
        "user": updated,
    }), 200


@admin_bp.route("/users/<user_id>/permissions/grant", methods=["PATCH"])
@require_permissions("admin:manage_permissions")
def grant_permissions(user_id, current_user):
    """
    PATCH /api/admin/users/<user_id>/permissions/grant
    Required permission: admin:manage_permissions
    Body: { "permissions": ["posts:write"] }

    Adds permissions without touching existing ones.
    """
    data = request.get_json(silent=True) or {}
    permissions = data.get("permissions")

    if not isinstance(permissions, list) or not permissions:
        return jsonify({"error": "'permissions' must be a non-empty list"}), 400

    user_model = UserModel(current_app.db)

    if not user_model.find_by_id(user_id):
        return jsonify({"error": "User not found"}), 404

    try:
        updated = user_model.grant_permissions(user_id, permissions)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({
        "message": "Permissions granted successfully",
        "user": updated,
    }), 200


@admin_bp.route("/users/<user_id>/permissions/revoke", methods=["PATCH"])
@require_permissions("admin:manage_permissions")
def revoke_permissions(user_id, current_user):
    """
    PATCH /api/admin/users/<user_id>/permissions/revoke
    Required permission: admin:manage_permissions
    Body: { "permissions": ["posts:delete"] }

    Removes specific permissions without touching the rest.
    """
    data = request.get_json(silent=True) or {}
    permissions = data.get("permissions")

    if not isinstance(permissions, list) or not permissions:
        return jsonify({"error": "'permissions' must be a non-empty list"}), 400

    user_model = UserModel(current_app.db)

    if not user_model.find_by_id(user_id):
        return jsonify({"error": "User not found"}), 404

    updated = user_model.revoke_permissions(user_id, permissions)

    return jsonify({
        "message": "Permissions revoked successfully",
        "user": updated,
    }), 200


@admin_bp.route("/users", methods=["GET"])
@require_permissions("admin:access")
def list_all_users(current_user):
    """
    GET /api/admin/users
    Required permission: admin:access

    Returns all users with their full permission sets.
    """
    user_model = UserModel(current_app.db)
    users = user_model.find_all()
    return jsonify({"users": users, "count": len(users)}), 200
