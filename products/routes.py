from datetime import datetime, timezone
import logging
from dotenv import load_dotenv
import os
from fastapi import APIRouter, Depends, HTTPException
from auth.dependencies import get_current_user
import httpx
import json
from redis.asyncio import Redis
from .utils import RateLimitConfig, RateLimiter

router = APIRouter()
load_dotenv()

# Initialize Redis client
#redis_client = Redis(host="localhost", port=6379, db=0)
redis_url = os.getenv("REDIS_URL")
redis_client = Redis.from_url(redis_url, decode_responses=True)

# Define rate-limiting configuration
config = RateLimitConfig(max_calls=5, period=60)

rate_limiter = RateLimiter(redis_client, config)

VALID_TOKEN = os.getenv("MTM_PRD_VALID_TOKEN")
TOKEN_EXPIRY = os.getenv("MTM_PRD_TOKEN_EXPIRY")
SOURCEURL = os.getenv("MTM_PRD_SOURCE_URL")
API_PREFIX = os.getenv("API_URL")
URLprefix = SOURCEURL.split('.')[1]

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@router.get("/{services}")
@rate_limiter.rate_limit()
async def get_products(services: str, token_data: dict = Depends(get_current_user)):
    try:
        URLprefix = SOURCEURL.split('.')[1]
    except IndexError:
        raise HTTPException(status_code=500, detail="Malformed SOURCE_URL, unable to extract prefix")
    
    if not URLprefix:
        raise HTTPException(status_code=400, detail="Invalid API prefix provided")
    
    if URLprefix != services: 
        raise HTTPException(status_code=400, detail=f"Invalid or unsupported API prefix - '{services}' in SOURCE_URL")    
    
    services = URLprefix
    try:
        expiry_datetime = datetime.fromisoformat(TOKEN_EXPIRY).replace(tzinfo=timezone.utc)
    except ValueError:
        raise HTTPException(status_code=500, detail="Invalid token expiry format")

    current_time = datetime.now(timezone.utc)
    if current_time > expiry_datetime:
        raise HTTPException(status_code=401, detail="Token has expired")
    
    core_api_url = SOURCEURL
    cache_key = f"products_cache_{services}"
    
    try:
        cached_data = await redis_client.get(cache_key)
        if cached_data:
            logger.info("Product Data retrieved from Redis cache.")
            return json.loads(cached_data)

        logger.info("Fetching Product data from the core API.")
        async with httpx.AsyncClient() as client:
             headers = {
                "Authorization": f"Bearer {VALID_TOKEN}" 
            }
             response = await client.get(core_api_url, headers=headers)
             response.raise_for_status()
             product_data = response.json()

        await redis_client.set(cache_key, json.dumps(product_data), ex=300)  # Cache for 5 minutes
        logger.info("Product Data fetched from core API and cached in Redis.")
        return product_data

    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"Error fetching product data: {e}")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code,
                            detail=f"Error fetching product data: {e.response.text}")
