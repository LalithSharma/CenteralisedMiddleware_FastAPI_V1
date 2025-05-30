from datetime import datetime
import os
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from .dependencies import get_db, authenticate_user, create_access_token, get_user
from .models import Token
from .schemas import UserCreate, UserResponse
from users.models import User, UserAPI
from .utils import get_password_hash  # Import get_password_hash here

router = APIRouter()

@router.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token, expire_time = create_access_token(data={"sub": user.username })
    #db.add(user)
    login_record = UserAPI(
     user_id=user.id,
     unique_token = access_token,
     token_expiration = expire_time,
     login_time=datetime.utcnow(),
     token_type="Bearer",
    )
    db.add(login_record)
    db.commit()
    db.refresh(user)
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/signup", response_model= UserResponse)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user(db, username = user.username, email = user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        role=user.role,  
        status=user.status, 
        services=os.getenv("API_PREFIX"), 
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user