# app/api/routes_users.py

from fastapi import APIRouter, Depends
from app.api.schemas import UserOut
from app.api.deps import get_current_user
from app.db.models import User
from fastapi import Body
from app.core.security import revoke_refresh_token_logic
from app.db.session import get_session
from app.api.schemas import TokenRefreshRequest
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.schemas import UserUpdate, ChangePasswordRequest
from app.core.security import verify_password, hash_password
from pydantic_extra_types.phone_numbers import PhoneNumber
import phonenumbers

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserOut)
async def read_current_user(current_user: User = Depends(get_current_user)):
    from app.api.schemas import UserOut
    import phonenumbers
    from pydantic_extra_types.phone_numbers import PhoneNumber
    # Convert phone string to E.164 format for PhoneNumber
    try:
        parsed = phonenumbers.parse(current_user.phone, "IR")
        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        phone = PhoneNumber(e164)
    except Exception:
        phone = PhoneNumber("+989000000000")  # fallback to a default valid phone number
    return UserOut(
        id=current_user.id,
        email=current_user.email,
        fname=current_user.fname,
        lname=current_user.lname,
        phone=phone,
        is_active=current_user.is_active
    )


@router.post("/logout", status_code=204)
async def logout(request: TokenRefreshRequest = Body(...), session: AsyncSession = Depends(get_session)):
    await revoke_refresh_token_logic(session, request.refresh_token)
    return None

@router.patch("/me", response_model=UserOut)
async def update_current_user(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    updated = False
    if user_update.fname is not None:
        current_user.fname = user_update.fname
        updated = True
    if user_update.lname is not None:
        current_user.lname = user_update.lname
        updated = True
    if user_update.phone is not None:
        current_user.phone = str(user_update.phone)
        updated = True
    if user_update.email is not None:
        current_user.email = user_update.email
        updated = True
    if updated:
        session.add(current_user)
        await session.commit()
        await session.refresh(current_user)
    return current_user

@router.post("/change-password", status_code=204)
async def change_password(
    req: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    if not verify_password(req.current_password, current_user.hashed_pw):
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    current_user.hashed_pw = hash_password(req.new_password)
    session.add(current_user)
    await session.commit()
    return None