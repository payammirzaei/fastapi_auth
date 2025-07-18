
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
    is_2fa_enabled:bool

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class UserUpdate(BaseModel):
    fname: str | None = None
    lname: str | None = None
    phone: PhoneNumber | None = None
    email: EmailStr | None = None
    is_2fa_enabled:bool | None = None

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

class TwoFASetupResponse(BaseModel):
    qr_code: str  # data URI
    secret: str

class TwoFAEnableRequest(BaseModel):
    code: str

class TwoFADisableRequest(BaseModel):
    code: str
