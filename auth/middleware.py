from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import os
import time
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from auth.dependencies import validate_token
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from logger import log_error, log_info

logger = logging.getLogger('uvicorn.access')
logger.disabled = False

def ApiGateway_Middleware(app:FastAPI):
    Middle_logs_dir = os.path.join(os.getcwd(), "static", "middleware_logs")
    os.makedirs(Middle_logs_dir, exist_ok=True)
    
    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    Middlelog_file_name = os.path.join(Middle_logs_dir, f"{current_time}.log")
    
    log_formatter = logging.Formatter(
        "%(asctime)s - IP: %(client_ip)s - Domain: %(host)s - URL: %(url)s - Token: %(token)s - Method: %(method)s - LogMessage: %(log_message)s"
    )
    log_handler = RotatingFileHandler(
        Middlelog_file_name, maxBytes=10 * 1024 * 1024, backupCount=5
    )
    log_handler.setFormatter(log_formatter)
    logger = logging.getLogger("api_gateway_logger")
    logger.setLevel(logging.INFO)
    logger.addHandler(log_handler)
    
    @app.middleware('http')
    async def custom_logging(request: Request, call_next):
        start_time = time.time()
        client_ip = request.client.host
        domain = request.headers.get("host", "unknown")
        token = request.headers.get("Authorization", "none")
        url = str(request.url)
        method = request.method

        incoming_log_data = {
        "client_ip": client_ip,
        "host": domain,
            "url": url,
            "token": token,
            "method": method,
            "log_message": "Incoming request received",
        }
        logger.info("", extra=incoming_log_data)
        print(incoming_log_data)
        try:
            response = await call_next(request)
            processed_time = time.time() - start_time
            outgoing_log_data = {
                "client_ip": client_ip,
                "host": domain,
                "url": url,
                "token": token,
                "method": method,
                "status_code": response.status_code,
                "processed_time": f"{processed_time:.2f}s",
                "log_message": "Outgoing response sent",
            }
            logger.info("", extra=outgoing_log_data) 
            print(outgoing_log_data)
            return response
        
        except Exception as e:
            processed_time = time.time() - start_time
            error_log_data = {
                "client_ip": client_ip,
                "host": domain,
                "url": url,
                "token": token,
                "method": method,
                "processed_time": f"{processed_time:.2f}s",
                "error": str(e),
                "log_message": "Error occurred while processing request",
            }
            logger.error("", extra=error_log_data)
            return JSONResponse(
                status_code=500,
                content={"detail": "An internal server error occurred."},
            )  

    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],allow_credentials= True,)
    app.add_middleware(TrustedHostMiddleware,  allowed_hosts=["centeralisedmiddleware.onrender.com","mpp-gateway-ewpuz.ondigitalocean.app","127.0.0.1", "localhost", "*.yourdomain.com"],)
    
def admin_only(request: Request):    
    # Get the role from the cookies
    client_ip = request.client.host
    host = request.headers.get("host", "unknown")
    token = request.headers.get("Authorization", "none")
    Logged_token = request.cookies.get("access_token")  
    if not Logged_token:
        log_error(client_ip, host, "/get admin", token, "Token is missing")
        raise HTTPException(status_code=401, detail="Token is missing")  
    user_Token = validate_token(Logged_token)
    log_info(client_ip, host, "/get admin", token, f"user token fetched to check user role: {user_Token}")
    UserLogged_Role = user_Token["role"]
    log_info(client_ip, host, "/get admin", token, f"Roles fetched: {UserLogged_Role}")
    if not UserLogged_Role:
        log_error(client_ip, host, "/get admin", token, "Not authenticated")
        raise HTTPException(status_code=401, detail="Not authenticated")    
    if "admin" not in UserLogged_Role:
        log_error(client_ip, host, "/get admin", token, "Permission denied")
        raise HTTPException(status_code=403, detail="Permission denied")    
    return True 

