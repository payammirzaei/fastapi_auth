# app/db/crud_user.py

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models import User, RefreshToken
from app.core.security import hash_password
import secrets


async def get_user_by_email(session: AsyncSession, email: str) -> User | None:
    stmt = select(User).where(User.email == email)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def create_user(session: AsyncSession, email: str, password: str,fname:str,lname:str,phone:str) -> User:
    user = User(
        email=email,
        hashed_pw=hash_password(password),
        fname=fname,
        lname=lname,
        phone=phone
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def create_refresh_token(session: AsyncSession, user_id: int) -> RefreshToken:
    token_value = secrets.token_urlsafe(64)
    refresh_token = RefreshToken(user_id=user_id, token=token_value)
    session.add(refresh_token)
    await session.commit()
    await session.refresh(refresh_token)
    return refresh_token

async def get_refresh_token(session: AsyncSession, token: str) -> RefreshToken | None:
    stmt = select(RefreshToken).where(RefreshToken.token == token, RefreshToken.revoked == False)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()

async def revoke_refresh_token(session: AsyncSession, token: str) -> None:
    stmt = select(RefreshToken).where(RefreshToken.token == token)
    result = await session.execute(stmt)
    refresh_token = result.scalar_one_or_none()
    if refresh_token:
        refresh_token.revoked = True
        await session.commit()
