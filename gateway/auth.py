from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Header, HTTPException

from contracts import UserContext

_DEMO_USERS = {
    "intern": ("intern-demo", UserContext(user_id="u-intern", role="intern", department="engineering", clearance=0)),
    "hr": ("hr-demo", UserContext(user_id="u-hr", role="hr_officer", department="hr", clearance=2)),
    "finance": ("finance-demo", UserContext(user_id="u-finance", role="finance_manager", department="finance", clearance=2)),
    "admin": ("admin-demo", UserContext(user_id="u-admin", role="admin", department="security", clearance=3)),
}


def _password_hash(password: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), b"hinderman-demo-salt-v1", 120_000)


_PASSWORDS = {username: _password_hash(value[0]) for username, value in _DEMO_USERS.items()}


def authenticate(username: str, password: str) -> UserContext | None:
    expected = _PASSWORDS.get(username)
    if expected is None or not hmac.compare_digest(_password_hash(password), expected):
        return None
    return _DEMO_USERS[username][1].model_copy(deep=True)


def create_token(user: UserContext) -> str:
    expires = datetime.now(timezone.utc) + timedelta(hours=8)
    return jwt.encode(
        {"sub": user.user_id, "role": user.role, "department": user.department,
         "clearance": user.clearance, "exp": expires},
        os.getenv("JWT_SECRET", "hinderman-local-demo-secret-change-before-network"),
        algorithm="HS256",
    )


def decode_token(token: str) -> UserContext:
    try:
        payload = jwt.decode(
            token, os.getenv("JWT_SECRET", "hinderman-local-demo-secret-change-before-network"),
            algorithms=["HS256"]
        )
        return UserContext(
            user_id=payload["sub"],
            role=payload["role"],
            department=payload["department"],
            clearance=payload["clearance"],
        )
    except (jwt.PyJWTError, KeyError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired bearer token") from exc


def get_current_user(authorization: str | None = Header(default=None)) -> UserContext:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    return decode_token(authorization[7:])


def require_admin(user: UserContext) -> None:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required")
