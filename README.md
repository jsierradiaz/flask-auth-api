# 🔐 Flask Auth API

A production-style **JWT Authentication & Permission-Based Authorization** API built with Flask and MongoDB.

---

## Features

- ✅ JWT Authentication (register, login, /me)
- ✅ Permission-based access control (fine-grained, not just roles)
- ✅ Role presets (viewer, editor, manager, admin)
- ✅ Grant / Revoke / Replace permissions at runtime
- ✅ Soft user deactivation
- ✅ Reusable `@require_permissions` decorator
- ✅ Pytest test suite

---

## Project Structure

```
auth-api/
├── app/
│   ├── __init__.py              # App factory
│   ├── models/
│   │   └── user.py              # User model + permissions definitions
│   ├── routes/
│   │   ├── auth.py              # Register, Login, /me
│   │   ├── users.py             # User management (requires permissions)
│   │   └── admin.py             # Permission management (admin only)
│   └── middleware/
│       └── permissions.py       # @require_permissions decorator
├── tests/
│   └── test_auth.py
├── run.py
├── requirements.txt
└── .env.example
```

---

## Setup

```bash
# 1. Clone & enter the project
cd auth-api

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env with your MongoDB URI and a strong JWT secret

# 5. Run the server
python run.py
```

---

## API Reference

### Auth

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/register` | None | Register a new user |
| POST | `/api/auth/login` | None | Login and get JWT token |
| GET | `/api/auth/me` | JWT | Get current user profile |
| GET | `/api/auth/permissions` | None | List all permissions & role bundles |

### Users

| Method | Endpoint | Required Permission | Description |
|--------|----------|---------------------|-------------|
| GET | `/api/users/` | `users:read` | List all users |
| GET | `/api/users/<id>` | `users:read` | Get a user by ID |
| PATCH | `/api/users/<id>/deactivate` | `users:delete` | Deactivate a user |

### Admin

| Method | Endpoint | Required Permission | Description |
|--------|----------|---------------------|-------------|
| GET | `/api/admin/users` | `admin:access` | List all users with permissions |
| GET | `/api/admin/users/<id>/permissions` | `admin:access` | View a user's permissions |
| PUT | `/api/admin/users/<id>/permissions` | `admin:manage_permissions` | Replace all permissions |
| PATCH | `/api/admin/users/<id>/permissions/grant` | `admin:manage_permissions` | Add permissions |
| PATCH | `/api/admin/users/<id>/permissions/revoke` | `admin:manage_permissions` | Remove permissions |

---

## Permissions System

### All Available Permissions

| Permission | Description |
|------------|-------------|
| `users:read` | View user list and profiles |
| `users:write` | Create or update users |
| `users:delete` | Deactivate users |
| `posts:read` | Read posts |
| `posts:write` | Create or edit posts |
| `posts:delete` | Delete posts |
| `admin:access` | Access admin panel |
| `admin:manage_permissions` | Grant/revoke permissions |

### Role Presets

| Role | Permissions |
|------|-------------|
| `viewer` | `posts:read` |
| `editor` | `posts:read`, `posts:write` |
| `manager` | `posts:read`, `posts:write`, `posts:delete`, `users:read` |
| `admin` | All permissions |

---

## Usage Examples

### Register

```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "secret123", "role": "editor"}'
```

### Login

```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "secret123"}'
```

### Call a Protected Route

```bash
curl http://localhost:5000/api/users/ \
  -H "Authorization: Bearer <your_token>"
```

### Grant a Permission (as admin)

```bash
curl -X PATCH http://localhost:5000/api/admin/users/<user_id>/permissions/grant \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"permissions": ["posts:delete"]}'
```

---

## Running Tests

```bash
pytest tests/ -v
```

---

## Key Concepts Demonstrated

1. **JWT Authentication** — Stateless token-based auth; the server never stores sessions.
2. **Permission-based access control** — Each user has a flat list of granular permissions, not just a role string.
3. **Decorator middleware** — `@require_permissions("x")` cleanly separates auth logic from business logic.
4. **Least privilege** — New users default to the minimal `viewer` permission set.
5. **Soft deletes** — Users are deactivated, not permanently deleted, preserving audit history.
