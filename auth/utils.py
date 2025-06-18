from dotenv import load_dotenv
import os
from fastapi import HTTPException
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta

load_dotenv()
SECRET_KEY = os.getenv("MIDDLEWARE_SECRET_KEY")
ALGORITHM = os.getenv("MIDDLEWARE_ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("MIDDLEWARE_TOKEN_EXPIRE",15))

SUPERLOGIN_SECRET_KEY = os.getenv("SUPERUSER_SECRET_KEY")
SUPERLOGIN_ALGORITHM = os.getenv("SUPERUSER_ALGORITHM")
SUPERLOGIN_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("SUPERUSER_TOKEN_EXPIRE",15))

REDISURL = os.getenv("REDIS_URL")

SUPERLOGIN_API_KEY = os.getenv("SUPER_API_KEY")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = datetime.utcnow() + expires_delta
    to_encode = data.copy()
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt, expire

def UserLogged_access_token(email, role):
    if SUPERLOGIN_API_KEY != "your_secure_api_key_here":
        raise HTTPException(status_code=500, detail="Internal server error. $key@")
    access_token_expires = timedelta(minutes=SUPERLOGIN_ACCESS_TOKEN_EXPIRE_MINUTES)
    encoded_jwt = jwt.encode({"sub": email, "role": role, "exp": datetime.utcnow() + access_token_expires},
        SUPERLOGIN_SECRET_KEY,
        algorithm=SUPERLOGIN_ALGORITHM,)
    return encoded_jwt