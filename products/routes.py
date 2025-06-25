import logging
import os
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, HTTPException, Path, Request
from auth.dependencies import fetch_channel_data, get_current_user, get_db
import httpx
import json
from redis.asyncio import Redis

from logger import log_error, log_info
from .utils import RateLimitConfig, RateLimiter

router = APIRouter()
redis_url = os.getenv("REDIS_URL")
redis_client = Redis.from_url(redis_url, decode_responses=True)

config = RateLimitConfig(max_calls=5, period=3600)
rate_limiter = RateLimiter(redis_client, config)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@router.get("/clients/{client_id}/products", operation_id = "fecthAllProducts")
@rate_limiter.rate_limit()
async def get_products(request: Request, channel: str = Path(..., description="Service prefix from URL"), client_id: int = None, token_data: dict = Depends(get_current_user)
                       , db: Session = Depends(get_db)):
    user_channel = getattr(token_data, "channels", None)
    channel_data = fetch_channel_data(channel, db)
    client_ip = request.client.host
    host = request.headers.get("host", "unknown")
    token = request.headers.get("Authorization", "none")
        
    if "error" in channel_data:
        log_error(client_ip, host, "/products - user channel", token, f"Channel '{channel}' not found in the database")
        raise HTTPException(
        status_code=404, detail=f"Channel '{channel}' not found in the database"
    ) 
    channelName = channel_data.get("name")
    channelBaseURL = channel_data.get("BaseUrl")
    channelApiKey = channel_data.get("ApiKey")
    channelAuthURL = channel_data.get("AuthUrl")
    
    if not user_channel:
        log_error(client_ip, host, "/products - user channel", token, "User's channel is not defined")
        raise HTTPException(status_code=400, detail="User's channel is not defined")
    
    if channelName == 'Error':
        log_error(client_ip, host, "/products - user channel", token, "Malformed SOURCE_URL, channel missing")
        raise HTTPException(status_code=500, detail="Malformed SOURCE_URL, channel missing")
    
    if not channelName:
        log_error(client_ip, host, "/products - user channel", token, "Invalid API prefix provided")
        raise HTTPException(status_code=400, detail="Invalid API prefix provided")
    
    if channelName not in user_channel:
        log_error(client_ip, host, "/products - user channel", token, f"Invalid or unsupported API prefix - user:'{user_channel}', given prefix: '{channelName}' in the parameters..")
        raise HTTPException(status_code=400, detail=f"Invalid or unsupported API prefix - user:'{user_channel}', given prefix: '{channelName}' in the parameters..")
    
    if channelName not in channel:
        log_error(client_ip, host, "/products - user channel", token, f"Invalid or unsupported API prefix - parameter value:'{channel}', required prefix: '{channelName}' in the paramters..")
        raise HTTPException(status_code=400, detail=f"Invalid or unsupported API prefix - parameter value:'{channel}', required prefix: '{channelName}' in the paramters..")        
    
    core_api_url = f"{channelBaseURL}/{channelName}/clients/{client_id}/products"
    api_key = channelApiKey
    cache_key_CP = f"Client_products_cache_{channelName}"
    
    try:
        cached_data_CP = await redis_client.get(cache_key_CP)
        if cached_data_CP:
            log_info(client_ip, host, "/products", token, "products Data retrieved from Redis cache.")
            logger.info("Product Data retrieved from Redis cache.")
            return json.loads(cached_data_CP)

        log_info(client_ip, host, "/products", token, "Fetching products data from the core API.")
        logger.info("Fetching Client Product data from the core API.")
        async with httpx.AsyncClient() as client:
             headers = {"Authorization": api_key}
             response = await client.get(core_api_url, headers=headers)
             response.raise_for_status()
             ClientProduct_data = response.json()

        await redis_client.set(cache_key_CP, json.dumps(ClientProduct_data), ex=300)  # Cache for 5 minutes
        logger.info("Product Data fetched from core API and cached in Redis.")
        log_info(client_ip, host, "/products", token, "products Data fetched from core API and cached in Redis.")
        return ClientProduct_data

    except httpx.RequestError as e:
        log_error(client_ip, host, "/products", token, f"Error fetching products data: {e}")
        raise HTTPException(status_code=500, detail=f"Error fetching product data: {e}")
    except httpx.HTTPStatusError as e:
        log_error(client_ip, host, "/products", token, f"Error fetching products data: {e.response.text}")
        raise HTTPException(status_code=e.response.status_code,
                            detail=f"Error fetching product data: {e.response.text}")
        

@router.get("/clients/{client_id}/products/{product_id}",
            operation_id = "fecthProductbyIndex")
@rate_limiter.rate_limit()
async def get_productsbyIndex(request: Request, channel: str = Path(..., description="Service prefix from URL"), client_id: int = None, 
                       product_id: int = None,
                       token_data: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    user_channel = getattr(token_data, "channels", None)
    channel_data = fetch_channel_data(channel, db)
    client_ip = request.client.host
    host = request.headers.get("host", "unknown")
    token = request.headers.get("Authorization", "none")
    
    if not channel_data:
        log_error(client_ip, host, "/product ids - calendar - user channel", token, f"Channel '{channel}' not found in the database")
        raise HTTPException(
        status_code=404, detail=f"Channel '{channel}' not found in the database"
    ) 
    channelName = channel_data.get("name")
    channelBaseURL = channel_data.get("BaseUrl")
    channelApiKey = channel_data.get("ApiKey")
    channelAuthURL = channel_data.get("AuthUrl")
    
    if not user_channel:
        log_error(client_ip, host, "/product ids - user channel", token, "User's channel is not defined")
        raise HTTPException(status_code=400, detail="User's channel is not defined")
    
    if channelName == 'Error':
        log_error(client_ip, host, "/product ids - user channel", token, "Malformed SOURCE_URL, channel missing")
        raise HTTPException(status_code=500, detail="Malformed SOURCE_URL, channel missing")
    
    if not channelName:
        log_error(client_ip, host, "/product ids - user channel", token, "Invalid API prefix provided")
        raise HTTPException(status_code=400, detail="Invalid API prefix provided")
    
    if channelName not in user_channel:
        log_error(client_ip, host, "/product ids - user channel", token, f"Invalid or unsupported API prefix - user:'{user_channel}', prefix: '{channelName}' in the parameters..")
        raise HTTPException(status_code=400, detail=f"Invalid or unsupported API prefix - user:'{user_channel}', given prefix: '{channelName}' in the parameters..")
    
    if channelName not in channel:
        log_error(client_ip, host, "/product ids - user channel", token, f"Invalid or unsupported API prefix - parameter value:'{channel}', required prefix: '{channelName}' in the paramters..")
        raise HTTPException(status_code=400, detail=f"Invalid or unsupported API prefix - parameter value:'{channel}', required prefix: '{channelName}' in the paramters..")        
    
    core_api_url = f"{channelBaseURL}/{channelName}/clients/{client_id}/products/{product_id}"
    api_key = channelApiKey
    cache_key_PCIndex = f"Client_productsbyIndex_cache_{channelName}"
    
    try:
        cached_dataPCIndex = await redis_client.get(cache_key_PCIndex)
        if cached_dataPCIndex:
            productbyIndex_data = json.loads(cached_dataPCIndex)
            if 'error' in productbyIndex_data or 'data' not in productbyIndex_data:
                log_info(client_ip, host, "/product ids", token, "Invalid data found in Redis cache, refetching from API.")
                logger.warning("Invalid data found in Redis cache, refetching from API.")
            else:
                log_info(client_ip, host, "/product ids", token, "product Data retrieved from Redis cache.")
                logger.info("Product Data retrieved from Redis cache.")
                return productbyIndex_data
        log_info(client_ip, host, "/product ids", token, "Fetching product data by Index from the core API.")
        logger.info("Fetching Product data from the core API.")
        async with httpx.AsyncClient() as client:
             headers = {"Authorization": api_key}
             response = await client.get(core_api_url, headers=headers)
             response.raise_for_status()
             productbyIndex_data = response.json()
        
        await redis_client.set(cache_key_PCIndex, json.dumps(productbyIndex_data), ex=300)  # Cache for 5 minutes
        logger.info("Product Data fetched from core API and cached in Redis.")
        log_info(client_ip, host, "/product ids ", token, "product data by Index fetched from core API and cached in Redis.")
        return productbyIndex_data

    except httpx.RequestError as e:
        log_error(client_ip, host, "/product ids", token, f"Error fetching product data by Index: {e}")
        raise HTTPException(status_code=500, detail=f"Error fetching product data: {e}")
    except httpx.HTTPStatusError as e:
        log_error(client_ip, host, "/products ids", token, f"Error fetching product data by Index: {e.response.text}")
        raise HTTPException(status_code=e.response.status_code,
                            detail=f"Error fetching product data: {e.response.text}")


@router.get("/clients/{client_id}/products/{product_id}/calendar",
            operation_id = "fecthProductcalendar")
@rate_limiter.rate_limit()
async def get_productsbycalendar(request: Request, channel: str = Path(..., description="Service prefix from URL"), client_id: int = None, 
                       product_id: int = None,
                       token_data: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    user_channel = getattr(token_data, "channels", None)
    channel_data = fetch_channel_data(channel, db)
    client_ip = request.client.host
    host = request.headers.get("host", "unknown")
    token = request.headers.get("Authorization", "none")
    
    if not channel_data:
        log_error(client_ip, host, "/product ids - calendar - user channel", token, f"Channel '{channel}' not found in the database")
        raise HTTPException(
        status_code=404, detail=f"Channel '{channel}' not found in the database"
    ) 
    channelName = channel_data.get("name")
    channelBaseURL = channel_data.get("BaseUrl")
    channelApiKey = channel_data.get("ApiKey")
    channelAuthURL = channel_data.get("AuthUrl")
    
    if not user_channel:
        log_error(client_ip, host, "/product ids - calendar - user channel", token, "User's channel is not defined")
        raise HTTPException(status_code=400, detail="User's channel is not defined")
    
    if channelName == 'Error':
        log_error(client_ip, host, "/product ids - calendar - user channel", token, "Malformed SOURCE_URL, channel missing")
        raise HTTPException(status_code=500, detail="Malformed SOURCE_URL, channel missing")
    
    if not channelName:
        log_error(client_ip, host, "/product ids - calendar - user channel", token, "Invalid API prefix provided")
        raise HTTPException(status_code=400, detail="Invalid API prefix provided")
    
    if channelName not in user_channel:
        log_error(client_ip, host, "/product ids - calendar - user channel", token, f"Invalid or unsupported API prefix - user:'{user_channel}', prefix: '{channelName}' in the parameters..")
        raise HTTPException(status_code=400, detail=f"Invalid or unsupported API prefix - user:'{user_channel}', given prefix: '{channelName}' in the parameters..")
    
    if channelName not in channel:
        log_error(client_ip, host, "/product ids - calendar - user channel", token, f"Invalid or unsupported API prefix - parameter value:'{channel}', required prefix: '{channelName}' in the paramters..")
        raise HTTPException(status_code=400, detail=f"Invalid or unsupported API prefix - parameter value:'{channel}', required prefix: '{channelName}' in the paramters..")        
    
    core_api_url = f"{channelBaseURL}/{channelName}/clients/{client_id}/products/{product_id}/calendar"
    api_key = channelApiKey
    cache_key_PCIndex = f"Client_productsbycalendar_cache_{channelName}"
    
    try:
        cached_dataPCIndex = await redis_client.get(cache_key_PCIndex)
        if cached_dataPCIndex:
            productbycalndar_data = json.loads(cached_dataPCIndex)
            if 'error' in productbycalndar_data or 'data' not in productbycalndar_data:
                log_info(client_ip, host, "/product ids - calendar", token, "Invalid data found in Redis cache, refetching from API.")
                logger.warning("Invalid calendar found in Redis cache, refetching from API.")
            else:
                log_info(client_ip, host, "/product ids - calendar", token, "products Data retrieved from Redis cache.")
                logger.info("Product by calendar Data retrieved from Redis cache.")
                return productbycalndar_data
        log_info(client_ip, host, "/product ids - calendar", token, "Fetching products data by Index from the core API.")
        logger.info("Fetching Product by calendar data from the core API.")
        async with httpx.AsyncClient() as client:
             headers = {"Authorization": api_key}
             response = await client.get(core_api_url, headers=headers)
             response.raise_for_status()
             productbycalndar_data = response.json()
        
        await redis_client.set(cache_key_PCIndex, json.dumps(productbycalndar_data), ex=300)  # Cache for 5 minutes
        logger.info("Product by calendar Data fetched from core API and cached in Redis.")
        log_info(client_ip, host, "/product ids - calendar", token, "products data by Index fetched from core API and cached in Redis.")
        return productbycalndar_data

    except httpx.RequestError as e:
        log_error(client_ip, host, "/product ids - calendar", token, f"Error fetching products data by Index: {e}")
        raise HTTPException(status_code=500, detail=f"Error fetching product by calendar data: {e}")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code,
                            detail=f"Error fetching product by calendar data: {e.response.text}")
