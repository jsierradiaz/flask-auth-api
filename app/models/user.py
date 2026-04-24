from datetime import datetime, timezone
from bson import ObjectId
import bcrypt


# ── All available permissions in the system ─────────────────────────────────
PERMISSIONS = {
    # User management
    "users:read",       # view user list
    "users:write",      # create / update users
    "users:delete",     # delete users
    # Content
    "posts:read",
    "posts:write",
    "posts:delete",
    # Admin panel
    "admin:access",
    "admin:manage_permissions",
}

# ── Preset permission bundles (convenience, not enforced server-side) ────────
ROLE_PERMISSIONS = {
    "viewer":  {"posts:read"},
    "editor":  {"posts:read", "posts:write"},
    "manager": {"posts:read", "posts:write", "posts:delete", "users:read"},
    "admin":   set(PERMISSIONS),  # all permissions
}


class UserModel:
    COLLECTION = "users"

    def __init__(self, db):
        self.collection = db[self.COLLECTION]
        # Ensure unique index on email
        self.collection.create_index("email", unique=True)

    # ── Create ───────────────────────────────────────────────────────────────
    def create(self, email: str, password: str, permissions: list = None) -> dict:
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        user = {
            "email": email,
            "password": hashed,
            "permissions": list(permissions or ROLE_PERMISSIONS["viewer"]),
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }
        result = self.collection.insert_one(user)
        user["_id"] = result.inserted_id
        return self._serialize(user)

    # ── Read ─────────────────────────────────────────────────────────────────
    def find_by_email(self, email: str) -> dict | None:
        user = self.collection.find_one({"email": email})
        return self._serialize(user) if user else None

    def find_by_id(self, user_id: str) -> dict | None:
        try:
            user = self.collection.find_one({"_id": ObjectId(user_id)})
            return self._serialize(user) if user else None
        except Exception:
            return None

    def find_all(self) -> list:
        return [self._serialize(u) for u in self.collection.find()]

    # ── Update permissions ───────────────────────────────────────────────────
    def set_permissions(self, user_id: str, permissions: list) -> dict | None:
        # Validate that all supplied permissions actually exist
        invalid = set(permissions) - PERMISSIONS
        if invalid:
            raise ValueError(f"Unknown permissions: {invalid}")

        self.collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"permissions": permissions, "updated_at": datetime.now(timezone.utc)}},
        )
        return self.find_by_id(user_id)

    def grant_permissions(self, user_id: str, permissions: list) -> dict | None:
        invalid = set(permissions) - PERMISSIONS
        if invalid:
            raise ValueError(f"Unknown permissions: {invalid}")

        self.collection.update_one(
            {"_id": ObjectId(user_id)},
            {
                "$addToSet": {"permissions": {"$each": permissions}},
                "$set": {"updated_at": datetime.now(timezone.utc)},
            },
        )
        return self.find_by_id(user_id)

    def revoke_permissions(self, user_id: str, permissions: list) -> dict | None:
        self.collection.update_one(
            {"_id": ObjectId(user_id)},
            {
                "$pullAll": {"permissions": permissions},
                "$set": {"updated_at": datetime.now(timezone.utc)},
            },
        )
        return self.find_by_id(user_id)

    # ── Password ─────────────────────────────────────────────────────────────
    def verify_password(self, plain: str, hashed: str) -> bool:
        return bcrypt.checkpw(plain.encode(), hashed.encode())

    def get_raw_password(self, email: str) -> str | None:
        """Return the stored hash (for login check only)."""
        user = self.collection.find_one({"email": email}, {"password": 1})
        return user["password"] if user else None

    # ── Deactivate ───────────────────────────────────────────────────────────
    def deactivate(self, user_id: str) -> bool:
        result = self.collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"is_active": False, "updated_at": datetime.now(timezone.utc)}},
        )
        return result.modified_count == 1

    # ── Helper ───────────────────────────────────────────────────────────────
    @staticmethod
    def _serialize(user: dict) -> dict:
        """Convert ObjectId → string and drop the password hash."""
        if not user:
            return user
        user = dict(user)
        user["id"] = str(user.pop("_id"))
        user.pop("password", None)
        return user
