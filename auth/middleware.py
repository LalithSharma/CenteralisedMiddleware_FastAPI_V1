import logging
import time
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from auth.dependencies import validate_token
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

logger = logging.getLogger('uvicorn.access')
logger.disabled = False

def ApiGateway_Middleware(app:FastAPI):
        
    @app.middleware('http')
    async def custom_logging(request: Request, call_next):
        start_time = time.time()
        try:
            response = await call_next(request)
            processed_time = time.time() - start_time
            message = f"Begins at {start_time} from {request.client.host}:{request.client.port} - {request.method} - {request.url.path} - {response.status_code} completed after {processed_time}s"
            print(message)        
            return response  
        except Exception as e:
            processed_time = time.time() - start_time
            error_message = (
                f"Begins at {start_time} from {request.client.host}:{request.client.port} - {request.method} "
                f"{request.url.path} - Error: {str(e)} occurred after {processed_time:.2f}s"
            )
            print(error_message)
            return JSONResponse(
                status_code=500,
                content={"detail": "An internal server error occurred."},
            )  

    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],allow_credentials= True,)
    app.add_middleware(TrustedHostMiddleware,  allowed_hosts=["centeralisedmiddleware.onrender.com","https://mpp-gateway-ewpuz.ondigitalocean.app/","127.0.0.1", "localhost", "*.yourdomain.com"],)
    
def admin_only(request: Request):    
    # Get the role from the cookies
    Logged_token = request.cookies.get("access_token")    
    user_Token = validate_token(Logged_token)
    UserLogged_Role = user_Token["role"]
    if not UserLogged_Role:
        raise HTTPException(status_code=401, detail="Not authenticated")    
    if UserLogged_Role != "admin":
        raise HTTPException(status_code=403, detail="Permission denied")    
    return True 

