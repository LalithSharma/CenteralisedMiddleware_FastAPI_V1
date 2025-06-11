from typing import List
from pydantic import BaseModel, EmailStr

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    email: EmailStr
    status: str
    channels: List[str]

    class Config:
        orm_mode = True
        