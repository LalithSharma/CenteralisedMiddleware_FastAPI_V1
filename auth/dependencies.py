from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from .utils import ALGORITHM, SECRET_KEY, verify_password, get_password_hash, create_access_token
from .models import TokenData
from users.models import Channel, User, UserChannel
from .database import SessionLocal, engine, Base
from users import models
from sqlalchemy import select
        
models.Base.metadata.create_all(bind=engine)
#Base.metadata.drop_all(bind=engine)
bearer_scheme = HTTPBearer()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_user(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def authenticate_user(db: Session, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def get_current_user(
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
):
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(username=email)
    except JWTError:
        raise credentials_exception
    user = get_user(db, email=token_data.username)
    if user is None:
        raise credentials_exception
    
    user_channels = (
        db.query(Channel.name)
        .join(UserChannel, Channel.id == UserChannel.channel_id)
        .filter(UserChannel.user_id == user.id)
        .all()
    )
    channels = [channel.name for channel in user_channels]
    user.channels = channels
     
    return user

def fetch_channel_data(channel_name: str, db: Session = Depends(get_db)):
    query = select(Channel.name, Channel.base_url, Channel.auth_url, Channel.api_key).where(Channel.name == channel_name)  
    result = db.execute(query)
    channel = result.fetchone() 
    if channel:
        name, base_url, auth_url, api_key = channel
        return {
            "name": name,
            "BaseUrl": base_url,
            "AuthUrl": auth_url,
            "ApiKey": api_key
        }

    return {"error": "Channel not found"}
