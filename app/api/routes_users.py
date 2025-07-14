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

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserOut)
async def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user


@router.post("/logout", status_code=204)
async def logout(request: TokenRefreshRequest = Body(...), session: AsyncSession = Depends(get_session)):
    await revoke_refresh_token_logic(session, request.refresh_token)
    return None