"""
Authentication and user management API routes.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.rbac import (
    APIKey,
    MFASetupResponse,
    PasswordChange,
    TokenPair,
    User,
    UserCreate,
    UserUpdate,
    auth_service,
    get_current_user,
    require_admin,
    require_analyst,
)
from app.database import get_db

router = APIRouter(prefix="/auth", tags=["authentication"])

security = HTTPBearer(auto_error=False)


class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: str | None = None
    remember_me: bool = False


@router.post("/login", response_model=TokenPair)
async def login(
    request: Request,
    login_data: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate user and return access + refresh tokens."""
    client_ip = request.client.host if request.client else ""
    user_agent = request.headers.get("user-agent", "")
    
    return await auth_service.authenticate(
        login_data.username,
        login_data.password,
        login_data.mfa_code,
        client_ip,
        user_agent,
    )


@router.post("/refresh", response_model=TokenPair)
async def refresh_token(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Refresh access token using refresh token."""
    body = await request.json()
    refresh_token = body.get("refresh_token")
    
    if not refresh_token:
        raise HTTPException(status_code=400, detail="refresh_token required")
    
    client_ip = request.client.host if request.client else ""
    user_agent = request.headers.get("user-agent", "")
    
    return await auth_service.refresh_tokens(refresh_token, client_ip, user_agent)


@router.post("/logout")
async def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke current session."""
    await auth_service.revoke_session(credentials.credentials, current_user.id)
    return {"message": "Logged out successfully"}


@router.post("/logout-all")
async def logout_all(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    current_user: User = Depends(get_current_user),
):
    """Revoke all sessions for current user except current."""
    count = await auth_service.revoke_all_sessions(current_user.id, credentials.credentials)
    return {"message": f"Revoked {count} other sessions"}


@router.get("/me", response_model=dict)
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current user profile."""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role.value,
        "is_active": current_user.is_active,
        "is_verified": current_user.is_verified,
        "mfa_enabled": current_user.mfa_enabled,
        "last_login": current_user.last_login,
        "created_at": current_user.created_at,
    }


@router.patch("/me", response_model=dict)
async def update_me(
    update_data: UserUpdate,
    current_user: User = Depends(get_current_user),
):
    """Update current user profile (limited fields)."""
    # Users can only update their own name/email
    allowed = UserUpdate(
        full_name=update_data.full_name,
        email=update_data.email,
    )
    updated = await auth_service.update_user(current_user.id, allowed, current_user.id)
    return {
        "id": updated.id,
        "username": updated.username,
        "email": updated.email,
        "full_name": updated.full_name,
        "role": updated.role.value,
        "is_active": updated.is_active,
    }


@router.post("/change-password")
async def change_password(
    password_data: PasswordChange,
    current_user: User = Depends(get_current_user),
):
    """Change current user password."""
    await auth_service.change_password(current_user.id, password_data)
    return {"message": "Password changed successfully. All other sessions revoked."}


# MFA endpoints
@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(current_user: User = Depends(get_current_user)):
    """Setup MFA - returns secret and QR code."""
    return await auth_service.setup_mfa(current_user.id)


@router.post("/mfa/verify")
async def verify_mfa(
    mfa_code: str,
    current_user: User = Depends(get_current_user),
):
    """Verify MFA code and enable MFA."""
    success = await auth_service.verify_mfa_setup(current_user.id, mfa_code)
    if success:
        return {"message": "MFA enabled successfully"}
    raise HTTPException(status_code=400, detail="Invalid MFA code")


@router.post("/mfa/disable")
async def disable_mfa(
    current_user: User = Depends(get_current_user),
):
    """Disable MFA for current user."""
    await auth_service.disable_mfa(current_user.id, current_user.id)
    return {"message": "MFA disabled"}


# Admin-only user management
@router.post("/users", response_model=dict, dependencies=[Depends(require_admin)])
async def create_user(
    user_data: UserCreate,
    current_user: User = Depends(get_current_user),
):
    """Create a new user (admin only)."""
    user = await auth_service.create_user(user_data, current_user.id)
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role.value,
        "is_active": user.is_active,
    }


@router.get("/users", dependencies=[Depends(require_admin)])
async def list_users(
    db: AsyncSession = Depends(get_db),
    limit: int = 100,
    offset: int = 0,
):
    """List all users (admin only)."""
    from sqlalchemy import select

    from app.auth.rbac import User
    
    result = await db.execute(select(User).offset(offset).limit(limit))
    users = result.scalars().all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "full_name": u.full_name,
            "role": u.role.value,
            "is_active": u.is_active,
            "mfa_enabled": u.mfa_enabled,
            "last_login": u.last_login,
            "created_at": u.created_at,
        }
        for u in users
    ]


@router.get("/users/{user_id}", dependencies=[Depends(require_admin)])
async def get_user(user_id: str, db: AsyncSession = Depends(get_db)):
    """Get user by ID (admin only)."""
    from sqlalchemy import select

    from app.auth.rbac import User
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role.value,
        "is_active": user.is_active,
        "mfa_enabled": user.mfa_enabled,
        "last_login": user.last_login,
        "created_at": user.created_at,
    }


@router.patch("/users/{user_id}", dependencies=[Depends(require_admin)])
async def update_user(
    user_id: str,
    update_data: UserUpdate,
    current_user: User = Depends(get_current_user),
):
    """Update user (admin only)."""
    updated = await auth_service.update_user(user_id, update_data, current_user.id)
    return {
        "id": updated.id,
        "username": updated.username,
        "email": updated.email,
        "full_name": updated.full_name,
        "role": updated.role.value,
        "is_active": updated.is_active,
    }


@router.delete("/users/{user_id}", dependencies=[Depends(require_admin)])
async def delete_user(user_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Delete user (admin only)."""
    from sqlalchemy import select

    from app.auth.rbac import User
    
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    await db.delete(user)
    await db.commit()
    return {"message": "User deleted"}


# API Key management
@router.post("/api-keys", response_model=dict, dependencies=[Depends(require_analyst)])
async def create_api_key(
    name: str,
    permissions: list[str] | None = None,
    expires_days: int | None = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create API key for programmatic access."""
    from datetime import timedelta

    from app.auth.rbac import generate_token, hash_token
    
    raw_key = f"mk_{generate_token(32)}"
    key_hash = hash_token(raw_key)
    key_prefix = raw_key[:12]
    
    api_key = APIKey(
        name=name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        user_id=current_user.id,
        permissions=permissions or [],
        expires_at=datetime.utcnow() + timedelta(days=expires_days) if expires_days else None,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)
    
    return {
        "id": api_key.id,
        "name": api_key.name,
        "key": raw_key,  # Only returned once!
        "prefix": key_prefix,
        "permissions": api_key.permissions,
        "expires_at": api_key.expires_at,
    }


@router.get("/api-keys", dependencies=[Depends(require_analyst)])
async def list_api_keys(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """List user's API keys."""
    from sqlalchemy import select
    
    result = await db.execute(select(APIKey).where(APIKey.user_id == current_user.id))
    keys = result.scalars().all()
    return [
        {
            "id": k.id,
            "name": k.name,
            "prefix": k.key_prefix,
            "permissions": k.permissions,
            "is_active": k.is_active,
            "expires_at": k.expires_at,
            "last_used": k.last_used,
            "created_at": k.created_at,
        }
        for k in keys
    ]


@router.delete("/api-keys/{key_id}", dependencies=[Depends(require_analyst)])
async def revoke_api_key(key_id: str, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Revoke API key."""
    from sqlalchemy import select
    
    result = await db.execute(select(APIKey).where(APIKey.id == key_id, APIKey.user_id == current_user.id))
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    key.is_active = False
    await db.commit()
    return {"message": "API key revoked"}


# Add missing import
from datetime import datetime