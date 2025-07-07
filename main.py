import os
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import httpx
from redis import Redis
from auth.dependencies import authenticate_user, get_db, get_user_role, validate_token
from auth.middleware import ApiGateway_Middleware
from auth.routes import router as auth_router
from sqlalchemy.orm import Session
from auth.database import engine
from auth.static_seeder import seed_api_routes, seed_channels, seed_roles, seed_users
from auth.utils import SUPERLOGIN_ACCESS_TOKEN_EXPIRE_MINUTES, UserLogged_access_token
from logger import log_error, log_info
from users.routes import router as users_router
# from products.routes import router as products_router
# from clients.routes import router as clients_router
# from bookings.routes import router as bookings_router
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from DLL.API_routes import router as api_router

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
ApiGateway_Middleware(app)
templates = Jinja2Templates(directory="users/templates")
app.mount("/static/logs", StaticFiles(directory="users/static"), name="logs")

@app.on_event("startup")
async def startup_event():
    with Session(engine) as session:
        seed_roles(session)
        seed_channels(session)
        seed_users(session)
        seed_api_routes(session)

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
app.include_router(api_router, prefix="/{channel}", tags=["api_urls"])
# app.include_router(clients_router, prefix="/{channel}", tags=["clients"])
# app.include_router(clients_router, prefix="/{channel}", tags=["clients"])
# app.include_router(products_router, prefix="/{channel}", tags=["products"])
# app.include_router(products_router, prefix="/{channel}", tags=["products"])
# app.include_router(products_router, prefix="/{channel}", tags=["products"])

# app.include_router(bookings_router, prefix="/{channel}", tags=["Bookings"])
# app.include_router(bookings_router, prefix="/{channel}", tags=["bookings"])
# app.include_router(bookings_router, prefix="/{channel}", tags=["bookings"])


@app.get("/")
def read_root():
    #return {"message": "Welcome to Centeralized getway to Web API access..!"}
    return RedirectResponse("/login", status_code=302)

@app.get("/APIGateway")
async def secure_docs(request: Request):
    access_token = request.cookies.get("access_token")
    if not access_token:
        return RedirectResponse(url="/login", status_code=302)    
    try:
        LoginData = validate_token(access_token)
        LoginEmail = LoginData["email"]
        LoginRole = LoginData["role"]
        print(f"Authenticated email: {LoginEmail, LoginRole}")
    except httpx.RequestError as e:
        return HTTPException(status_code=302, detail=f"Error fetching token data: {e}")    
    return get_swagger_ui_html(openapi_url="/APIGatewaySchema", title="API Gateway Panel")

@app.get("/APIGatewaySchema")
async def custom_openapi(request: Request):
    access_token = request.cookies.get("access_token")    
    if not access_token:
        return RedirectResponse(url="/login", status_code=302)    
    try:
        LoginData = validate_token(access_token)
        LoginEmail = LoginData["email"]
        LoginRole = LoginData["role"]
    except HTTPException as e:
        return RedirectResponse(url="/login", status_code=302)    
    return get_openapi(title=f"Secured API Gateway, {LoginEmail} - {LoginRole}", version="1.0.0", routes=app.routes)

@app.get("/login")
def login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def PerformLogin(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    client_ip = request.client.host
    host = request.headers.get("host", "unknown")
    token = request.headers.get("Authorization", "none")
    user = authenticate_user(db, email, password)
    if not user:
        log_error(client_ip, host, "/Login user validate", token, "Invalid credentials!")
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    role = get_user_role(db, user.id)
    log_info(client_ip, host, "/Login", token, "Logged Role!")
    access_token = UserLogged_access_token(email, role)
    log_info(client_ip, host, "/Login", token, "Logged token validated!")
    response = RedirectResponse("/APIGateway", status_code=302)
    response.set_cookie(key="access_token", value=access_token, httponly=True, max_age=SUPERLOGIN_ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    return response    
