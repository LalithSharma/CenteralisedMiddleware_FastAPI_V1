from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import httpx
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from .utils import ALGORITHM, SECRET_KEY, SUPERLOGIN_ALGORITHM, SUPERLOGIN_API_KEY, SUPERLOGIN_SECRET_KEY, verify_password, get_password_hash, create_access_token
from .models import TokenData
from users.models import APIRoute, Channel, Role, User, UserChannel, UserRole
from .database import SessionLocal, engine
from users import models
from sqlalchemy import select
from logger import log_info, log_error

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

def get_channel_by_name(db: Session, channel_name: str):
    return db.query(Channel).filter(Channel.name.ilike(channel_name)).first()

# Function to check if a user is already associated with a channel
def get_user_channel(db: Session, user_id: int, channel_id: int):
    return db.query(UserChannel).filter(
        UserChannel.user_id == user_id, UserChannel.channel_id == channel_id
    ).first()
    
def authenticate_user(db: Session, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def get_user_role(db: Session, user_id: int, client_ip="unknown", host="unknown", token="none") -> str:
    try:
        log_info(client_ip, host, "/get_user_role", token, f"Fetching roles for user_id: {user_id}")
        user_role_ids = db.query(UserRole.role_id).filter(UserRole.user_id == user_id).all()

        if not user_role_ids:
            log_error(client_ip, host, "/get_user_role", token, "User role not found")
            raise HTTPException(status_code=404, detail="User role not found")

        role_ids = [role_id[0] for role_id in user_role_ids]
        roles = db.query(Role.name).filter(Role.id.in_(role_ids)).all()
        result = [role[0] for role in roles] if roles else ["Null"]

        log_info(client_ip, host, "/get_user_role", token, f"Roles fetched: {result}")
        return result
    except httpx.HTTPStatusError as e:
        error_message = f"Error fetching User role: {e.response.text}"
        log_error(client_ip, host, "/get_user_role", token, error_message)
        raise HTTPException(status_code=e.response.status_code, detail=error_message)
    
def get_current_user(request: Request,
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
):
    client_ip = request.client.host
    host = request.headers.get("host", "unknown")
    
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
            log_error(client_ip, host, "/get_current_user", token, "Email missing in token payload")
            raise credentials_exception
        token_data = TokenData(username=email)
    except JWTError:
        log_error(client_ip, host, "/get_current_user", token, "Invalid token")
        raise credentials_exception
    user = get_user(db, email=token_data.username)
    if user is None:
        raise credentials_exception
    
    try:
        user_channels = (
            db.query(Channel.name)
            .join(UserChannel, Channel.id == UserChannel.channel_id)
            .filter(UserChannel.user_id == user.id)
            .all()
        )
        channels = [channel.name for channel in user_channels]
        user.channels = channels
    except Exception as e:
        log_error(client_ip, host, "/get_current_user", token, f"Error fetching user channels: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch user channels")
    
    try:
        user_role = (
            db.query(Role.name)
            .join(UserRole, Role.id == UserRole.role_id)
            .filter(UserRole.user_id == user.id)
            .all()
        )
        roles = [role.name for role in user_role]
        user.role = roles
    except Exception as e:
        log_error(client_ip, host, "/get_current_user", token, f"Error fetching user roles: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch user roles")

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

def fetch_urls(db: Session = Depends(get_db)):
    try:
        query_urlsPath = select(
            APIRoute.path, 
            APIRoute.maxcache,
            APIRoute.status
        ).where(APIRoute.status == "active")
        result = db.execute(query_urlsPath)
        patterns = [
            {"path": row[0], "maxcache": row[1]}
            for row in result.fetchall()
        ]
        return patterns

    except Exception as e:
        print("Error fetching urls from API routes table:", str(e))
        return []
    
def validate_token(token: str):
    try:
        payload = jwt.decode(token, SUPERLOGIN_SECRET_KEY, algorithms=[SUPERLOGIN_ALGORITHM])
        email = payload.get("sub")
        role = payload.get("role")
        if not email or not role:
            raise HTTPException(status_code=403, detail="Invalid token")
        if SUPERLOGIN_API_KEY != "U2FsdGVkX1+2//gQlVR8f9KABqEnXEdt81azc4Mx2zQpQJUfdBFpiolrD52Z3XSj":
            raise HTTPException(status_code=500, detail="Internal server error.  $Validatekey@")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=403, detail="Invalid token")
    return {"email": email, "role": role}