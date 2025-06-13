from dotenv import load_dotenv
import os
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta

load_dotenv()
SECRET_KEY = os.getenv("MIDDLEWARE_SECRET_KEY")
ALGORITHM = os.getenv("MIDDLEWARE_ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("MIDDLEWARE_TOKEN_EXPIRE",15))

Login_SECRET_KEY = os.getenv("LOGINMIDDLEWARE_SECRET_KEY")
Login_ALGORITHM = os.getenv("LOGINMIDDLEWARE_ALGORITHM")
Login_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("LOGINMIDDLEWARE_ADMIN_TOKEN_EXPIRE",15))
Login_API_KEY = os.getenv("STATIC_API_KEY")
SESSION_DURATION = os.getenv("API_KEY_DURATION")
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

# def access_tokenLoggin(data: dict, expires_delta: timedelta = None):
#     to_encode = data.copy()
#     expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
#     to_encode.update({"exp": int(expire.timestamp())})
#     encoded_jwt = jwt.encode(to_encode, Login_SECRET_KEY, algorithm=Login_ALGORITHM)
#     return encoded_jwt
