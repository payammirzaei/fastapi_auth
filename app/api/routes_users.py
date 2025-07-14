# app/api/routes_users.py

from fastapi import APIRouter, Depends
from app.api.schemas import UserOut
from app.api.deps import get_current_user
from app.db.models import User

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserOut)
async def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user
