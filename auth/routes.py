from datetime import datetime
import os
from fastapi import APIRouter, Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from .dependencies import get_db, authenticate_user, create_access_token, get_user
from .models import Token
from .schemas import UserCreate, UserResponse
from users.models import Channel, User, UserAPI, UserChannel
from .utils import get_password_hash

router = APIRouter()
security = HTTPBearer()

SECRET_KEY = os.getenv("MIDDLEWARE_ADMIN_SECRET_KEY")
ALGORITHM = os.getenv("MIDDLEWARE_ADMIN_ALGORITHM")

def verify_admin_token(token: str) -> bool:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("role") == "admin":
            return True
    except JWTError:
        pass
    return False

@router.post("/login", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token, expire_time = create_access_token(data={"sub": user.email })
    #db.add(user)
    login_record = UserAPI(
     user_id=user.id,     
     token_type="Bearer",
     unique_token = access_token,
     token_expiration = expire_time,
     login_at=datetime.utcnow()
    )
    db.add(login_record)
    db.commit()
    db.refresh(user)
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/signup", response_model= UserResponse)
def signup(user: UserCreate, db: Session = Depends(get_db), 
           #credentials: HTTPAuthorizationCredentials = Security(security)
           ):
    
    # token = credentials.credentials
    # if not verify_admin_token(token):
    #     raise HTTPException(status_code=403, detail="Permission denied")
    
    db_user = get_user(db, email = user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    db_user = User(
        email=user.email,
        hashed_password=hashed_password,
        status=user.status,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    db_channel =db.query(Channel).filter(Channel.name == user.channels).first()
    if not db_channel:
        raise HTTPException(status_code=400, detail="Channel does not exist")
        
    user_channel_entry = UserChannel(
        user_id=db_user.id,
        channel_id=db_channel.id,
    )
    db.add(user_channel_entry)
    db.commit()
    
    return db_user