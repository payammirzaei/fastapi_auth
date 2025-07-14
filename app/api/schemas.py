
# app/api/schemas.py

from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    fname:str
    lname:str
    phone:str


class UserOut(BaseModel):
    id: int
    email: EmailStr
    fname:str
    lname:str
    phone:str
    is_active: bool

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
