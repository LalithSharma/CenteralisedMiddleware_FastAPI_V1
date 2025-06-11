import os
from fastapi import FastAPI
from redis import Redis
from auth.middleware import RoleMiddleware
from auth.routes import router as auth_router

from users.routes import router as users_router
from products.routes import router as products_router
from clients.routes import router as clients_router
from bookings.routes import router as bookings_router

app = FastAPI()

@app.on_event("startup")
async def startup_event():
    global redis_client
    redis_url = os.getenv("REDIS_URL")
    redis_client = Redis.from_url(redis_url, decode_responses=True)

@app.on_event("shutdown")
async def shutdown_event():
    if redis_client:
        redis_client.close()

app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(users_router, prefix="/user", tags=["user"])
app.include_router(clients_router, prefix="/{channel}", tags=["clients"])
app.include_router(clients_router, prefix="/{channel}", tags=["clients"])
app.include_router(products_router, prefix="/{channel}", tags=["products"])
app.include_router(products_router, prefix="/{channel}", tags=["products"])
app.include_router(products_router, prefix="/{channel}", tags=["products"])

app.include_router(bookings_router, prefix="/{channel}", tags=["Bookings"])
app.include_router(bookings_router, prefix="/{channel}", tags=["bookings"])
app.include_router(bookings_router, prefix="/{channel}", tags=["bookings"])

admin_app =FastAPI()
admin_app.add_middleware(RoleMiddleware, allowed_roles=["admin"])

manager_app = FastAPI()
manager_app.add_middleware(RoleMiddleware, allowed_roles=["manager", "admin"])


admin_app.include_router(users_router, prefix="/Login", tags=["user"])
admin_app.include_router(products_router, prefix="/products", tags=["product list"])

manager_app.include_router(users_router, prefix="/Login", tags=["user"])
manager_app.include_router(products_router, prefix="/products", tags=["product list"])

# app.mount("/admin", admin_app)
# app.mount("/manager", manager_app)

@app.get("/")
def read_root():
    return {"message": "Welcome to Centeralized getway to Web API access..!"}


# Using Dependencies for Role-Based Access
# Alternatively, you can use dependencies for finer control instead of middleware:
# from fastapi import Depends, HTTPException

# async def get_current_user_role(token: str = Depends(...)):  # Replace with actual token decoding logic
#     payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
#     return payload.get("role")

# def role_required(allowed_roles: list):
#     async def check_role(role: str = Depends(get_current_user_role)):
#         if role not in allowed_roles:
#             raise HTTPException(status_code=403, detail="Access forbidden for this role")
#     return check_role

# @app.get("/staff-dashboard", dependencies=[Depends(role_required(["staff"]))])
# async def staff_dashboard():
#     return {"message": "Staff-only dashboard"}
