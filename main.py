import os
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from redis import Redis
from auth.dependencies import authenticate_user, get_db
from auth.middleware import RoleMiddleware
from auth.routes import router as auth_router
from sqlalchemy.orm import Session
from auth.utils import ALGORITHM, SECRET_KEY, SESSION_DURATION, Login_API_KEY, create_access_token
from users.routes import router as users_router
from products.routes import router as products_router
from clients.routes import router as clients_router
from bookings.routes import router as bookings_router
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

templates = Jinja2Templates(directory="users/templates")
app.mount("/static", StaticFiles(directory="users/static"), name="static")

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
    #return {"message": "Welcome to Centeralized getway to Web API access..!"}
    return RedirectResponse("/login", status_code=302)

@app.get("/APIGatewaySchema")
async def custom_openapi(request: Request):
    api_key = request.cookies.get("API_Key")
    
    if api_key != Login_API_KEY:
        return RedirectResponse(url="/login", status_code=302)
    
    return get_openapi(title="Secure API Docs", version="1.0.0", routes=app.routes)

@app.get("/APIGateway")
async def secure_docs(request: Request):
    api_key = request.cookies.get("API_Key")
    if api_key != Login_API_KEY:
        return RedirectResponse(url="/login", status_code=302)
        
    return get_swagger_ui_html(openapi_url="/APIGatewaySchema", title="Secure API Docs")

@app.get("/login")
def login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def PerformLogin(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = authenticate_user(db, email, password)
    if not user:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    
    response = RedirectResponse("/APIGateway", status_code=302)
    #response.set_cookie("user", email)  # Save user info in a cookie
    response.set_cookie("API_Key", Login_API_KEY, httponly=True, secure=False,max_age=SESSION_DURATION)
    return response
