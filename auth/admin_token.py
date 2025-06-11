import os
from jose import jwt
from datetime import datetime, timedelta

SECRET_KEY = os.getenv("MIDDLEWARE_ADMIN_SECRET_KEY")
ALGORITHM = os.getenv("MIDDLEWARE_ADMIN_ALGORITHM")
TOKEN_EXPIRATION_MINUTES = os.getenv("MIDDLEWARE_ADMIN_TOKEN_EXPIRE")

def generate_admin_token():
    payload = {
        "role": "admin",  
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRATION_MINUTES),
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

if __name__ == "__main__":
    token = generate_admin_token()
    print("Admin Token:", token)
