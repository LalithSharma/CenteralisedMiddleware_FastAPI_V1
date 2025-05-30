from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, HTTPException
from jose import jwt

from auth.utils import ALGORITHM, SECRET_KEY

class RoleMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, allowed_roles):
        super().__init__(app)
        self.allowed_roles = allowed_roles

    async def dispatch(self, request: Request, call_next):
        authorization: str = request.headers.get("Authorization")
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=403, detail="Authorization header missing or invalid")

        token = authorization.split(" ")[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            user_role = payload.get("role")
            if user_role not in self.allowed_roles:
                raise HTTPException(status_code=403, detail="Access forbidden for this role")
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=403, detail="Token has expired")
        except jwt.JWTError:
            raise HTTPException(status_code=403, detail="Invalid token")

        response = await call_next(request)
        return response
