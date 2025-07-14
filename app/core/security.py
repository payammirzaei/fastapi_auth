# app/core/security.py

from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from app.core.config import settings

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_minutes: int = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(
        minutes=expires_minutes or settings.access_token_expire_minutes
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.jwt_secret, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[ALGORITHM])
    except JWTError:
        return None

async def validate_refresh_token(session: AsyncSession, refresh_token: str):
    from app.db.crud_user import get_refresh_token
    token_obj = await get_refresh_token(session, refresh_token)
    if not token_obj or token_obj.revoked:
        return None
    return token_obj

async def revoke_refresh_token_logic(session: AsyncSession, refresh_token: str):
    from app.db.crud_user import revoke_refresh_token
    await revoke_refresh_token(session, refresh_token)

async def issue_access_token_from_refresh(session: AsyncSession, refresh_token: str):
    token_obj = await validate_refresh_token(session, refresh_token)
    if not token_obj:
        return None
    user_id = token_obj.user_id
    from app.db.models import User
    from sqlalchemy import select
    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        return None
    return create_access_token(data={"sub": user.email})
