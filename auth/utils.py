from dotenv import load_dotenv
import os
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta

load_dotenv()
SECRET_KEY = os.getenv("MIDDLEWARE_SECRET_KEY")
ALGORITHM = os.getenv("MIDDLEWARE_ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("MIDDLEWARE_TOKEN_EXPIRE",15))

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

