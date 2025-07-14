
# app/api/schemas.py

from pydantic import BaseModel, EmailStr
from pydantic_extra_types.phone_numbers import PhoneNumber

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    fname:str
    lname:str
    phone:PhoneNumber


class UserOut(BaseModel):
    id: int
    email: EmailStr
    fname:str
    lname:str
    phone:PhoneNumber
    is_active: bool

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequest(BaseModel):
    refresh_token: str
