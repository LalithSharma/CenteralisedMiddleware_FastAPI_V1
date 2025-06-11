from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class UserBase(BaseModel):
    email: EmailStr
    status: Optional[str] = "active"

class UserCreate(UserBase):
    password: str
    channels: str

class UserUpdate(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None
    status: Optional[str] = None

class UserOut(UserBase):
    id: int
    created_date: datetime
    update_date: Optional[datetime] = None

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    status: str
    
    class Config:
        orm_mode = True
