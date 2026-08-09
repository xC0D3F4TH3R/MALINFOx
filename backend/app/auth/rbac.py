"""
Authentication, Authorization, and RBAC for MALINFO.
Production-ready JWT-based auth with role-based access control,
audit logging, and session management for government deployment.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta
from enum import Enum

import bcrypt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    select,
)
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.auth.password_security import validate_password, validate_password_strength
from app.database import AsyncSessionLocal, get_db
from app.models import Base

logger = logging.getLogger("malinfo.auth")

# =============================================================================
# Models
# =============================================================================

class UserRole(str, Enum):
    """System roles with hierarchical permissions."""
    ADMIN = "admin"           # Full system access, user management, config
    ANALYST = "analyst"       # Submit samples, view all reports, trigger sandbox
    OPERATOR = "operator"     # Submit samples, view own reports, limited sandbox
    VIEWER = "viewer"         # Read-only access to reports
    CITIZEN = "citizen"       # Public reporting portal only


class Permission(str, Enum):
    """Granular permissions."""
    # Sample management
    SAMPLE_UPLOAD = "sample:upload"
    SAMPLE_VIEW_ALL = "sample:view_all"
    SAMPLE_VIEW_OWN = "sample:view_own"
    SAMPLE_DELETE = "sample:delete"
    SAMPLE_REANALYZE = "sample:reanalyze"

    # Sandbox
    SANDBOX_TRIGGER = "sandbox:trigger"
    SANDBOX_VIEW = "sandbox:view"
    SANDBOX_CONFIG = "sandbox:config"

    # Reports
    REPORT_VIEW_ALL = "report:view_all"
    REPORT_VIEW_OWN = "report:view_own"
    REPORT_EXPORT = "report:export"
    REPORT_DELETE = "report:delete"

    # Monitoring
    MONITOR_VIEW = "monitor:view"
    MONITOR_CONFIG = "monitor:config"

    # Threat Intel
    THREAT_INTEL_VIEW = "threat_intel:view"
    THREAT_INTEL_CONFIG = "threat_intel:config"

    # System
    USER_MANAGE = "user:manage"
    SYSTEM_CONFIG = "system:config"
    AUDIT_VIEW = "audit:view"

    # Public
    PUBLIC_REPORT = "public:report"


# Role -> Permissions mapping
ROLE_PERMISSIONS: dict[UserRole, set[Permission]] = {
    UserRole.ADMIN: set(Permission),  # All permissions
    UserRole.ANALYST: {
        Permission.SAMPLE_UPLOAD, Permission.SAMPLE_VIEW_ALL, Permission.SAMPLE_VIEW_OWN,
        Permission.SAMPLE_REANALYZE, Permission.SANDBOX_TRIGGER, Permission.SANDBOX_VIEW,
        Permission.REPORT_VIEW_ALL, Permission.REPORT_VIEW_OWN, Permission.REPORT_EXPORT,
        Permission.MONITOR_VIEW, Permission.THREAT_INTEL_VIEW, Permission.AUDIT_VIEW,
    },
    UserRole.OPERATOR: {
        Permission.SAMPLE_UPLOAD, Permission.SAMPLE_VIEW_OWN, Permission.SAMPLE_REANALYZE,
        Permission.SANDBOX_TRIGGER, Permission.SANDBOX_VIEW,
        Permission.REPORT_VIEW_OWN, Permission.REPORT_EXPORT,
    },
    UserRole.VIEWER: {
        Permission.SAMPLE_VIEW_OWN, Permission.REPORT_VIEW_OWN,
    },
    UserRole.CITIZEN: {
        Permission.PUBLIC_REPORT,
    },
}


def _uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    """User account model."""
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(256), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(256))
    hashed_password: Mapped[str] = mapped_column(String(256))
    role: Mapped[UserRole] = mapped_column(SQLEnum(UserRole), default=UserRole.VIEWER, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[str | None] = mapped_column(String(32), nullable=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_login: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    sessions: Mapped[list[UserSession]] = relationship(back_populates="user", cascade="all, delete-orphan")
    audit_logs: Mapped[list[AuditLog]] = relationship(back_populates="user", cascade="all, delete-orphan")


class UserSession(Base):
    """User session tracking for audit and revocation."""
    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), index=True)
    refresh_token_hash: Mapped[str] = mapped_column(String(64), index=True)
    ip_address: Mapped[str] = mapped_column(String(45))
    user_agent: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    last_activity: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)

    user: Mapped[User] = relationship(back_populates="sessions")


class AuditLog(Base):
    """Comprehensive audit trail for compliance."""
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(128), index=True)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    resource_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    ip_address: Mapped[str] = mapped_column(String(45))
    user_agent: Mapped[str] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[str] = mapped_column(String(32))  # success, failure, error
    severity: Mapped[str] = mapped_column(String(16), default="info")  # info, warning, critical
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    user: Mapped[User] = relationship(back_populates="audit_logs")


class APIKey(Base):
    """API keys for programmatic access."""
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    key_prefix: Mapped[str] = mapped_column(String(16))  # First 8 chars for identification
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), index=True)
    permissions: Mapped[list[str]] = mapped_column(JSON, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_used: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    rotation_count: Mapped[int] = mapped_column(Integer, default=0)
    # For key rotation - stores the previous key hash during transition
    previous_key_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    previous_key_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


# =============================================================================
# Schemas
# =============================================================================

class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: str | None = None
    remember_me: bool = False


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: EmailStr
    full_name: str = Field(..., min_length=1, max_length=256)
    password: str = Field(..., min_length=12, max_length=128)
    role: UserRole = UserRole.VIEWER


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    full_name: str | None = Field(None, min_length=1, max_length=256)
    role: UserRole | None = None
    is_active: bool | None = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=12, max_length=128)


class MFASetupResponse(BaseModel):
    secret: str
    qr_code_uri: str


# =============================================================================
# Password & Token Utilities
# =============================================================================

from typing import TYPE_CHECKING

from app.config import settings

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt).decode()


def verify_password(password: str, hashed: str) -> bool:
    """Verify password against bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def generate_token(length: int = 32) -> str:
    """Generate a secure random token."""
    return secrets.token_urlsafe(length)


def hash_token(token: str) -> str:
    """Hash token for storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def create_access_token(user_id: str, username: str, role: UserRole, expires_delta: timedelta | None = None) -> str:
    """Create JWT access token."""
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=30))  # Reduced to 30 minutes
    payload = {
        "sub": user_id,
        "username": username,
        "role": role.value,
        "type": "access",
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def create_refresh_token(user_id: str, expires_delta: timedelta | None = None) -> str:
    """Create JWT refresh token."""
    expire = datetime.utcnow() + (expires_delta or timedelta(days=7))  # Reduced to 7 days
    payload = {
        "sub": user_id,
        "type": "refresh",
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def decode_token(token: str) -> dict:
    """Decode and validate JWT token."""
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError as err:
        raise HTTPException(status_code=401, detail="Token expired") from err
    except jwt.InvalidTokenError as err:
        raise HTTPException(status_code=401, detail="Invalid token") from err


# =============================================================================
# Authentication Service
# =============================================================================

class AuthService:
    """Core authentication service."""

    def __init__(self):
        self.max_failed_attempts = 5
        self.lockout_duration = timedelta(minutes=15)

    async def authenticate(self, username: str, password: str, mfa_code: str | None = None, ip: str = "", user_agent: str = "") -> TokenPair:
        """Authenticate user and return token pair."""
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(User).where(User.username == username))
            user = result.scalar_one_or_none()

            if not user:
                await self._log_auth_failure(username, ip, user_agent, "user_not_found")
                raise HTTPException(status_code=401, detail="Invalid credentials")

            if not user.is_active:
                await self._log_auth_failure(username, ip, user_agent, "account_disabled")
                raise HTTPException(status_code=403, detail="Account disabled")

            if user.locked_until and user.locked_until > datetime.utcnow():
                await self._log_auth_failure(username, ip, user_agent, "account_locked")
                raise HTTPException(status_code=403, detail="Account temporarily locked")

            if not verify_password(password, user.hashed_password):
                await self._handle_failed_login(user, db, ip, user_agent)
                raise HTTPException(status_code=401, detail="Invalid credentials")

            # Check MFA if enabled
            if user.mfa_enabled:
                if not mfa_code:
                    raise HTTPException(status_code=400, detail="MFA code required")
                if not self._verify_mfa(user.mfa_secret, mfa_code):
                    await self._log_auth_failure(username, ip, user_agent, "mfa_failed")
                    raise HTTPException(status_code=401, detail="Invalid MFA code")

            # Reset failed attempts on successful login
            user.failed_login_attempts = 0
            user.locked_until = None
            user.last_login = datetime.utcnow()
            await db.commit()

            # Create session
            access_token = create_access_token(user.id, user.username, user.role)
            refresh_token = create_refresh_token(user.id)

            session = UserSession(
                user_id=user.id,
                token_hash=hash_token(access_token),
                refresh_token_hash=hash_token(refresh_token),
                ip_address=ip,
                user_agent=user_agent,
                expires_at=datetime.utcnow() + timedelta(days=7),  # Match refresh token expiry
            )
            db.add(session)
            await db.commit()

            await self._log_audit(user.id, "login", "session", session.id, ip, user_agent, {"role": user.role.value}, "success")

            return TokenPair(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in=30 * 60,  # 30 minutes
            )

    async def refresh_tokens(self, refresh_token: str, ip: str = "", user_agent: str = "") -> TokenPair:
        """Refresh access token using refresh token."""
        token_hash = hash_token(refresh_token)

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(UserSession).where(UserSession.refresh_token_hash == token_hash)
            )
            session = result.scalar_one_or_none()

            if not session or session.revoked or session.expires_at < datetime.utcnow():
                raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

            # Get user
            result = await db.execute(select(User).where(User.id == session.user_id))
            user = result.scalar_one_or_none()

            if not user or not user.is_active:
                raise HTTPException(status_code=401, detail="User not found or inactive")

            # Create new tokens
            new_access = create_access_token(user.id, user.username, user.role)
            new_refresh = create_refresh_token(user.id)

            # Revoke old session
            session.revoked = True
            new_session = UserSession(
                user_id=user.id,
                token_hash=hash_token(new_access),
                refresh_token_hash=hash_token(new_refresh),
                ip_address=ip,
                user_agent=user_agent,
                expires_at=datetime.utcnow() + timedelta(days=7),
            )
            db.add(new_session)
            await db.commit()

            return TokenPair(
                access_token=new_access,
                refresh_token=new_refresh,
                expires_in=30 * 60,  # 30 minutes
            )

    async def revoke_session(self, token: str, user_id: str) -> bool:
        """Revoke a specific session."""
        token_hash = hash_token(token)
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(UserSession).where(
                    UserSession.token_hash == token_hash,
                    UserSession.user_id == user_id
                )
            )
            session = result.scalar_one_or_none()
            if session:
                session.revoked = True
                await db.commit()
                return True
            return False

    async def revoke_all_sessions(self, user_id: str, except_token: str | None = None) -> int:
        """Revoke all sessions for a user."""
        except_hash = hash_token(except_token) if except_token else None
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(UserSession).where(
                    UserSession.user_id == user_id,
                    not UserSession.revoked
                )
            )
            sessions = result.scalars().all()
            count = 0
            for session in sessions:
                if except_hash and session.token_hash == except_hash:
                    continue
                session.revoked = True
                count += 1
            await db.commit()
            return count

    async def create_user(self, user_data: UserCreate, creator_id: str | None = None) -> User:
        """Create a new user."""
        # Validate password strength
        is_valid, errors = await validate_password(user_data.password)
        if not is_valid:
            raise HTTPException(status_code=400, detail="; ".join(errors))

        async with AsyncSessionLocal() as db:
            # Check uniqueness
            result = await db.execute(select(User).where(User.username == user_data.username))
            if result.scalar_one_or_none():
                raise HTTPException(status_code=400, detail="Username already exists")

            result = await db.execute(select(User).where(User.email == user_data.email))
            if result.scalar_one_or_none():
                raise HTTPException(status_code=400, detail="Email already exists")

            user = User(
                username=user_data.username,
                email=user_data.email,
                full_name=user_data.full_name,
                hashed_password=hash_password(user_data.password),
                role=user_data.role,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)

            if creator_id:
                await self._log_audit(creator_id, "user_create", "user", user.id, "", "", {"username": user.username}, "success")

            return user

    async def update_user(self, user_id: str, update_data: UserUpdate, actor_id: str) -> User:
        """Update user details."""
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(User).where(User.id == user_id))
            user = result.scalar_one_or_none()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            old_data = {"role": user.role.value, "is_active": user.is_active, "email": user.email}

            if update_data.email and update_data.email != user.email:
                result = await db.execute(select(User).where(User.email == update_data.email, User.id != user_id))
                if result.scalar_one_or_none():
                    raise HTTPException(status_code=400, detail="Email already in use")
                user.email = update_data.email

            if update_data.full_name:
                user.full_name = update_data.full_name

            if update_data.role:
                user.role = update_data.role

            if update_data.is_active is not None:
                user.is_active = update_data.is_active

            user.updated_at = datetime.utcnow()
            await db.commit()
            await db.refresh(user)

            await self._log_audit(actor_id, "user_update", "user", user.id, "", "", {"old": old_data, "new": {"role": user.role.value, "is_active": user.is_active}}, "success")
            return user

    async def change_password(self, user_id: str, password_data: PasswordChange) -> bool:
        """Change user password."""
        # Validate new password strength
        is_valid, errors = await validate_password(password_data.new_password)
        if not is_valid:
            raise HTTPException(status_code=400, detail="; ".join(errors))

        async with AsyncSessionLocal() as db:
            result = await db.execute(select(User).where(User.id == user_id))
            user = result.scalar_one_or_none()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            if not verify_password(password_data.current_password, user.hashed_password):
                raise HTTPException(status_code=400, detail="Current password incorrect")

            user.hashed_password = hash_password(password_data.new_password)
            user.updated_at = datetime.utcnow()
            await db.commit()

            # Revoke all sessions except current (will be handled by caller)
            await self.revoke_all_sessions(user_id)

            await self._log_audit(user_id, "password_change", "user", user_id, "", "", {}, "success")
            return True

    async def setup_mfa(self, user_id: str) -> MFASetupResponse:
        """Setup MFA for user."""
        import base64
        import io

        import pyotp
        import qrcode

        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        qr_uri = totp.provisioning_uri(name=f"MALINFO:{user_id}", issuer_name="MALINFO")

        # Generate QR code
        qr = qrcode.make(qr_uri)
        buf = io.BytesIO()
        qr.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()

        async with AsyncSessionLocal() as db:
            result = await db.execute(select(User).where(User.id == user_id))
            user = result.scalar_one_or_none()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            user.mfa_secret = secret
            user.mfa_enabled = False  # Enable after verification
            await db.commit()

        return MFASetupResponse(secret=secret, qr_code_uri=f"data:image/png;base64,{qr_b64}")

    async def verify_mfa_setup(self, user_id: str, mfa_code: str) -> bool:
        """Verify MFA setup code and enable MFA."""
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(User).where(User.id == user_id))
            user = result.scalar_one_or_none()
            if not user or not user.mfa_secret:
                raise HTTPException(status_code=400, detail="MFA not set up")

            if self._verify_mfa(user.mfa_secret, mfa_code):
                user.mfa_enabled = True
                await db.commit()
                await self._log_audit(user_id, "mfa_enable", "user", user_id, "", "", {}, "success")
                return True
            return False

    async def disable_mfa(self, user_id: str, actor_id: str) -> bool:
        """Disable MFA for user."""
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(User).where(User.id == user_id))
            user = result.scalar_one_or_none()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            user.mfa_enabled = False
            user.mfa_secret = None
            await db.commit()

            await self._log_audit(actor_id, "mfa_disable", "user", user_id, "", "", {}, "success")
            return True

    def _verify_mfa(self, secret: str, code: str) -> bool:
        """Verify TOTP code."""
        import pyotp
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)

    async def _handle_failed_login(self, user: User, db: AsyncSession, ip: str, user_agent: str):
        """Handle failed login attempt."""
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= self.max_failed_attempts:
            user.locked_until = datetime.utcnow() + self.lockout_duration
        await db.commit()
        await self._log_auth_failure(user.username, ip, user_agent, "invalid_password")

    async def _log_auth_failure(self, username: str, ip: str, user_agent: str, reason: str):
        """Log authentication failure."""
        async with AsyncSessionLocal() as db:
            log = AuditLog(
                user_id=None,
                action="login_failed",
                resource_type="auth",
                ip_address=ip,
                user_agent=user_agent,
                details={"username": username, "reason": reason},
                result="failure",
                severity="warning",
            )
            db.add(log)
            await db.commit()

    async def _log_audit(
        self,
        user_id: str,
        action: str,
        resource_type: str | None = None,
        resource_id: str | None = None,
        ip: str = "",
        user_agent: str = "",
        details: dict | None = None,
        result: str = "success",
        severity: str = "info",
    ):
        """Log audit event."""
        async with AsyncSessionLocal() as db:
            log = AuditLog(
                user_id=user_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                ip_address=ip,
                user_agent=user_agent,
                details=details or {},
                result=result,
                severity=severity,
            )
            db.add(log)
            await db.commit()


# Global auth service
auth_service = AuthService()


# =============================================================================
# API Key Rotation
# =============================================================================

async def rotate_api_key(api_key_id: str, user_id: str, db: AsyncSession) -> tuple[str, APIKey]:
    """
    Rotate an API key - generates a new key while keeping the old one valid for a transition period.
    Returns the new raw key and the updated APIKey object.
    """
    result = await db.execute(select(APIKey).where(APIKey.id == api_key_id, APIKey.user_id == user_id))
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    if not api_key.is_active:
        raise HTTPException(status_code=400, detail="Cannot rotate revoked API key")
    
    # Generate new key
    from app.auth.rbac import generate_token, hash_token
    new_raw_key = f"mk_{generate_token(32)}"
    new_key_hash = hash_token(new_raw_key)
    new_key_prefix = new_raw_key[:12]
    
    # Store current key as previous for transition period (24 hours)
    api_key.previous_key_hash = api_key.key_hash
    api_key.previous_key_expires_at = datetime.utcnow() + timedelta(hours=24)
    
    # Update to new key
    api_key.key_hash = new_key_hash
    api_key.key_prefix = new_key_prefix
    api_key.rotated_at = datetime.utcnow()
    api_key.rotation_count += 1
    api_key.last_used = None  # Reset last used for new key
    
    await db.commit()
    await db.refresh(api_key)
    
    # Log rotation
    await auth_service._log_audit(
        user_id, "api_key_rotate", "api_key", api_key_id, "", "",
        {"rotation_count": api_key.rotation_count}, "success"
    )
    
    return new_raw_key, api_key


async def cleanup_rotated_keys(db: AsyncSession) -> int:
    """
    Clean up expired previous keys (called periodically).
    Returns number of keys cleaned up.
    """
    result = await db.execute(
        select(APIKey).where(
            APIKey.previous_key_hash.isnot(None),
            APIKey.previous_key_expires_at < datetime.utcnow()
        )
    )
    keys = result.scalars().all()
    count = 0
    for key in keys:
        key.previous_key_hash = None
        key.previous_key_expires_at = None
        count += 1
    if count > 0:
        await db.commit()
    return count


# =============================================================================
# FastAPI Dependencies
# =============================================================================

security = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Get current authenticated user from JWT token."""
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")

    payload = decode_token(credentials.credentials)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")

    user_id = payload.get("sub")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")

    # Verify session exists and not revoked
    token_hash = hash_token(credentials.credentials)
    result = await db.execute(
        select(UserSession).where(
            UserSession.token_hash == token_hash,
            UserSession.user_id == user_id,
            not UserSession.revoked
        )
    )
    session = result.scalar_one_or_none()
    if not session or session.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Session expired or revoked")

    # Update last activity
    session.last_activity = datetime.utcnow()
    await db.commit()

    return user


async def get_current_user_optional(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User | None:
    """Get current user if authenticated, otherwise None."""
    try:
        return await get_current_user(credentials, db)
    except HTTPException:
        return None


def require_permission(permission: Permission):
    """Dependency factory for permission-based access control."""
    async def permission_checker(user: User = Depends(get_current_user)) -> User:
        user_permissions = ROLE_PERMISSIONS.get(user.role, set())
        if permission not in user_permissions:
            await auth_service._log_audit(
                user.id, "permission_denied", "authorization", None, "", "",
                {"required": permission.value, "role": user.role.value},
                "failure", "warning"
            )
            raise HTTPException(status_code=403, detail=f"Permission denied: {permission.value}")
        return user
    return permission_checker


def require_role(*roles: UserRole):
    """Dependency factory for role-based access control."""
    async def role_checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            await auth_service._log_audit(
                user.id, "role_denied", "authorization", None, "", "",
                {"required_roles": [r.value for r in roles], "user_role": user.role.value},
                "failure", "warning"
            )
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user
    return role_checker


# Common permission dependencies
require_admin = require_role(UserRole.ADMIN)
require_analyst = require_role(UserRole.ADMIN, UserRole.ANALYST)
require_operator = require_role(UserRole.ADMIN, UserRole.ANALYST, UserRole.OPERATOR)
require_authenticated = require_role(UserRole.ADMIN, UserRole.ANALYST, UserRole.OPERATOR, UserRole.VIEWER)


# =============================================================================
# API Key Authentication
# =============================================================================

async def get_api_key(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> APIKey:
    """Validate API key from Authorization header."""
    if not credentials or not credentials.credentials.startswith("mk_"):
        raise HTTPException(status_code=401, detail="Invalid API key format")

    key_hash = hash_token(credentials.credentials)
    
    # Check both current and previous (rotated) keys
    result = await db.execute(
        select(APIKey).where(
            (APIKey.key_hash == key_hash) | (APIKey.previous_key_hash == key_hash)
        )
    )
    api_key = result.scalar_one_or_none()

    if not api_key or not api_key.is_active:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")

    # Check if using previous (rotated) key
    if api_key.previous_key_hash == key_hash:
        # Verify transition period hasn't expired
        if api_key.previous_key_expires_at and api_key.previous_key_expires_at < datetime.utcnow():
            raise HTTPException(status_code=401, detail="API key expired (rotation transition period ended)")
        # Log warning about using old key
        logger.warning(
            "API key used during rotation transition period",
            extra={"api_key_id": api_key.id, "user_id": api_key.user_id}
        )
    elif api_key.expires_at and api_key.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="API key expired")

    # Update last used
    api_key.last_used = datetime.utcnow()
    await db.commit()

    return api_key


def require_api_permission(permission: Permission):
    """Check API key has required permission."""
    async def check_permission(api_key: APIKey = Depends(get_api_key)) -> APIKey:
        if permission.value not in api_key.permissions:
            raise HTTPException(status_code=403, detail=f"API key missing permission: {permission.value}")
        return api_key
    return check_permission