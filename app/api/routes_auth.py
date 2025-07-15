# app/api/routes_auth.py

from fastapi import APIRouter, Depends, HTTPException, status, Body, Form
from fastapi.security import OAuth2PasswordRequestForm, OAuth2
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.api.schemas import UserCreate, Token, TokenRefreshRequest, ForgotPasswordRequest, ResetPasswordRequest
from app.db.crud_user import get_user_by_email, create_user, create_refresh_token, revoke_refresh_token
from app.db.session import get_session
from app.core.security import verify_password, create_access_token, validate_refresh_token, issue_access_token_from_refresh, generate_password_reset_token, verify_password_reset_token, send_email, hash_password, generate_email_verification_token, verify_email_verification_token
from app.core.config import settings
import pyotp
from pydantic import BaseModel


router = APIRouter(prefix="/auth", tags=["auth"])


class OAuth2PasswordRequestFormWith2FA(OAuth2PasswordRequestForm):
    def __init__(
        self,
        username: str = Form(...),
        password: str = Form(...),
        scope: str = Form(""),
        client_id: Optional[str] = Form(None),
        client_secret: Optional[str] = Form(None),
        two_fa_code: Optional[str] = Form(None, alias="two_fa_code"),
    ):
        super().__init__(
            username=username,
            password=password,
            scope=scope,
            client_id=client_id,
            client_secret=client_secret,
        )
        self.two_fa_code = two_fa_code


@router.post("/register", response_model=Token, status_code=201)
async def register(user_in: UserCreate, session: AsyncSession = Depends(get_session)):
    existing = await get_user_by_email(session, user_in.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Set is_verified to False on registration
    user = await create_user(session, email=user_in.email, password=user_in.password, fname=user_in.fname, lname=user_in.lname, phone=user_in.phone)
    user.is_verified = False
    session.add(user)
    await session.commit()
    await session.refresh(user)

    # Generate and send verification email
    token = generate_email_verification_token(user.email)
    verify_link = f"{settings.frontend_url}/auth/verify-email?token={token}"
    send_email(
        to_email=user.email,
        subject="Verify your email",
        body=f"<p>Click <a href='{verify_link}'>here</a> to verify your email address. This link will expire in 24 hours.</p>"
    )

    # Optionally, do not return tokens until verified, or return with a warning
    access_token = create_access_token(data={"sub": user.email})
    refresh_token_obj = await create_refresh_token(session, user_id=user.id)
    return {"access_token": access_token, "refresh_token": refresh_token_obj.token, "token_type": "bearer"}


@router.get("/verify-email")
async def verify_email(token: str, session: AsyncSession = Depends(get_session)):
    email = verify_email_verification_token(token)
    if not email:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")
    user = await get_user_by_email(session, email)
    if not user:
        raise HTTPException(status_code=400, detail="User not found")
    user.is_verified = True
    session.add(user)
    await session.commit()
    return {"detail": "Email verified successfully. You can now log in."}


@router.post(
    "/login",
    response_model=Token,
    description="""
Standard OAuth2 password login.\n\n**If 2FA is enabled for your account, enter your 2FA code in the `client_secret` field.**\nThis is required due to Swagger UI limitations.\n\nIf you use `/auth/login-json`, provide `two_fa_code` in the JSON body instead.
"""
)
async def login(
    form_data: OAuth2PasswordRequestFormWith2FA = Depends(),
    session: AsyncSession = Depends(get_session),
):
    user = await get_user_by_email(session, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_pw):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_verified:
        token = generate_email_verification_token(user.email)
        verify_link = f"{settings.frontend_url}/auth/verify-email?token={token}"
        send_email(
            to_email=user.email,
            subject="Verify your email",
            body=f"<p>Click <a href='{verify_link}'>here</a> to verify your email address. This link will expire in 24 hours.</p>"
        )
        raise HTTPException(
            status_code=403,
            detail="Please verify your email before logging in. A new verification email has been sent."
        )
    if user.is_2fa_enabled:
        # Use client_secret as the 2FA code for Swagger UI compatibility
        two_fa_code = form_data.client_secret
        if not two_fa_code:
            raise HTTPException(status_code=401, detail="2FA code required. Enter your 2FA code in the client_secret field.")
        if user.totp_secret is None:
            raise HTTPException(status_code=500, detail="2FA is enabled but no TOTP secret is set for this user.")
        import pyotp
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(two_fa_code):
            raise HTTPException(status_code=401, detail="Invalid 2FA code.")
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
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid refresh token: user not found")
    # Issue a new refresh token
    new_refresh_token_obj = await create_refresh_token(session, user_id=user_id)
    return {"access_token": new_access_token, "refresh_token": new_refresh_token_obj.token, "token_type": "bearer"}


@router.post("/forgot-password", status_code=204)
async def forgot_password(request: ForgotPasswordRequest, session: AsyncSession = Depends(get_session)):
    user = await get_user_by_email(session, request.email)
    if user:
        token = generate_password_reset_token(user.email)
        reset_link = f"{settings.frontend_url}/reset-password?token={token}"
        send_email(
            to_email=user.email,
            subject="Password Reset Request",
            body=f"<p>Click <a href='{reset_link}'>here</a> to reset your password. This link will expire in 1 hour.</p>"
        )
    # Always return 204 to prevent email enumeration
    return None

@router.post("/reset-password", status_code=204)
async def reset_password(request: ResetPasswordRequest, session: AsyncSession = Depends(get_session)):
    email = verify_password_reset_token(request.token)
    if not email:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    from app.db.crud_user import get_user_by_email
    user = await get_user_by_email(session, email)
    if not user:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="User not found")
    user.hashed_pw = hash_password(request.new_password)
    session.add(user)
    await session.commit()
    return None


class LoginJsonRequest(BaseModel):
    username: str
    password: str
    two_fa_code: str | None = None

@router.post(
    "/login-json",
    response_model=Token,
    description="""
Login with username, password, and optional two_fa_code for 2FA. 
If 2FA is enabled for the user, you must provide the current code from your authenticator app in the two_fa_code field. 
If 2FA is not enabled, omit two_fa_code or set it to null.
"""
)
async def login_json(
    req: LoginJsonRequest,
    session: AsyncSession = Depends(get_session),
):
    user = await get_user_by_email(session, req.username)
    if not user or not verify_password(req.password, user.hashed_pw):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_verified:
        token = generate_email_verification_token(user.email)
        verify_link = f"{settings.frontend_url}/auth/verify-email?token={token}"
        send_email(
            to_email=user.email,
            subject="Verify your email",
            body=f"<p>Click <a href='{verify_link}'>here</a> to verify your email address. This link will expire in 24 hours.</p>"
        )
        raise HTTPException(
            status_code=403,
            detail="Please verify your email before logging in. A new verification email has been sent."
        )
    if user.is_2fa_enabled:
        if not req.two_fa_code:
            raise HTTPException(status_code=401, detail="2FA code required.")
        if user.totp_secret is None:
            raise HTTPException(status_code=500, detail="2FA is enabled but no TOTP secret is set for this user.")
        import pyotp
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(req.two_fa_code):
            raise HTTPException(status_code=401, detail="Invalid 2FA code.")
    token = create_access_token(data={"sub": user.email})
    refresh_token_obj = await create_refresh_token(session, user_id=user.id)
    return {"access_token": token, "refresh_token": refresh_token_obj.token, "token_type": "bearer"}
