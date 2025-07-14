# app/db/crud_user.py

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models import User
from app.core.security import hash_password


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
