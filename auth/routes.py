from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from auth.middleware import admin_only
from .dependencies import get_db, authenticate_user, create_access_token, get_user, get_user_role
from .models import Token
from .schemas import UserCreate, UserResponse
from users.models import Channel, Role, User, UserAPI, UserChannel, UserRole
from .utils import get_password_hash

router = APIRouter()
security = HTTPBearer()

@router.post("/login", response_model=Token)
def signin(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    role = get_user_role(db, user.id)
    access_token, expire_time = create_access_token(data={"sub": user.email, "role": role })
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

@router.post("/signup", response_model= UserResponse, dependencies=[Depends(admin_only)])
def signup(user: UserCreate, db: Session = Depends(get_db)):
    
    db_user = get_user(db, email = user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    db_channel =db.query(Channel).filter(Channel.name == user.channels).first()
    if not db_channel:
        raise HTTPException(status_code=400, detail="Channel does not exist, Please entered given Channel name.!")
    
    db_role = db.query(Role).filter(Role.name == user.role).first()
    if not db_role:
        raise HTTPException(status_code=400, detail="Role does not exist, Please entered given Role name.!")
    
    hashed_password = get_password_hash(user.password)
    db_user = User(
        email=user.email,
        hashed_password=hashed_password,
        status=user.status,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
        
    user_channel_entry = UserChannel(
        user_id=db_user.id,
        channel_id=db_channel.id,
    )
    db.add(user_channel_entry)
    db.commit()
            
    user_role_entry = UserRole(
        user_id = db_user.id,
        role_id = db_role.id
    )
    db.add(user_role_entry)
    db.commit()
    
    return db_user