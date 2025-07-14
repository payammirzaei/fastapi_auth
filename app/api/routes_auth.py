# app/api/routes_auth.py

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import UserCreate, Token, TokenRefreshRequest
from app.db.crud_user import get_user_by_email, create_user, create_refresh_token, revoke_refresh_token
from app.db.session import get_session
from app.core.security import verify_password, create_access_token, validate_refresh_token, issue_access_token_from_refresh
from app.core.config import settings


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=Token, status_code=201)
async def register(user_in: UserCreate, session: AsyncSession = Depends(get_session)):
    existing = await get_user_by_email(session, user_in.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = await create_user(session, email=user_in.email, password=user_in.password, fname=user_in.fname, lname=user_in.lname, phone=user_in.phone)
    token = create_access_token(data={"sub": user.email})
    refresh_token_obj = await create_refresh_token(session, user_id=user.id)
    return {"access_token": token, "refresh_token": refresh_token_obj.token, "token_type": "bearer"}


@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_session),
):
    user = await get_user_by_email(session, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_pw):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token(data={"sub": user.email})
    refresh_token_obj = await create_refresh_token(session, user_id=user.id)
    return {"access_token": token, "refresh_token": refresh_token_obj.token, "token_type": "bearer"}


@router.post("/refresh", response_model=Token)
async def refresh_token(request: TokenRefreshRequest, session: AsyncSession = Depends(get_session)):
    new_access_token = await issue_access_token_from_refresh(session, request.refresh_token)
    if not new_access_token:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    # Revoke the old refresh token
    await revoke_refresh_token(session, request.refresh_token)
    # Get the user_id from the old refresh token
    from app.db.crud_user import get_refresh_token
    old_token_obj = await get_refresh_token(session, request.refresh_token)
    user_id = old_token_obj.user_id if old_token_obj else None
    # Issue a new refresh token
    new_refresh_token_obj = await create_refresh_token(session, user_id=user_id)
    return {"access_token": new_access_token, "refresh_token": new_refresh_token_obj.token, "token_type": "bearer"}
