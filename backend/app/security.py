import base64
import hashlib
import hmac
import json
import time
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session
from .config import get_settings
from .database import get_db
from .models import AuditLog

VALID_ROLES = {"administrator", "red_team", "blue_team", "viewer"}
DEMO_USERS = {
    "admin@bayora.local": {"display_name": "Local Administrator", "role": "administrator"},
    "red@bayora.local": {"display_name": "Local Red Team", "role": "red_team"},
    "blue@bayora.local": {"display_name": "Local Blue Team", "role": "blue_team"},
    "viewer@bayora.local": {"display_name": "Local Viewer", "role": "viewer"},
}


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def create_session_token(email: str, role: str, ttl_seconds: int = 8 * 60 * 60) -> str:
    payload = {"sub": email, "role": role, "exp": int(time.time()) + ttl_seconds}
    encoded = _b64(json.dumps(payload, separators=(",", ":")).encode())
    signature = _b64(hmac.new(get_settings().auth_secret.encode(), encoded.encode(), hashlib.sha256).digest())
    return f"{encoded}.{signature}"


def authenticate_demo_user(email: str, password: str) -> dict[str, str] | None:
    user = DEMO_USERS.get(email.lower())
    if not user or not hmac.compare_digest(password, get_settings().demo_password):
        return None
    return {"email": email.lower(), **user}


def decode_session_token(token: str) -> dict[str, str]:
    try:
        encoded, signature = token.split(".", 1)
        expected = _b64(hmac.new(get_settings().auth_secret.encode(), encoded.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise ValueError("invalid signature")
        payload = json.loads(_unb64(encoded))
        if payload.get("role") not in VALID_ROLES or int(payload.get("exp", 0)) < time.time():
            raise ValueError("expired or malformed")
        return payload
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired session") from exc


def current_role(authorization: str | None = Header(default=None), x_bayora_role: str | None = Header(default=None)) -> str:
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Use a Bearer session token")
        return decode_session_token(token)["role"]
    if not get_settings().allow_demo_role_header:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication is required")
    x_bayora_role = x_bayora_role or "administrator"
    if x_bayora_role not in VALID_ROLES:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown Bayora role")
    return x_bayora_role


def require_roles(*roles: str):
    def checker(role: str = Depends(current_role)) -> str:
        if role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This operation is not permitted for your role")
        return role
    return checker


def audit(db: Session, actor: str, action: str, resource_type: str, resource_id: str | None = None, detail: dict | None = None) -> None:
    db.add(AuditLog(actor=actor, action=action, resource_type=resource_type, resource_id=resource_id, detail=detail or {}))
