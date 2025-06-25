import json
import logging
import os
import httpx
from redis import Redis
from sqlalchemy.orm import Session
from dotenv import load_dotenv
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Request

from auth.dependencies import fetch_channel_data, get_current_user, get_db
from logger import log_error, log_info
from products.utils import RateLimitConfig, RateLimiter

router = APIRouter()
load_dotenv()

redis_url = os.getenv("REDIS_URL")
redis_client = Redis.from_url(redis_url, decode_responses=True)
config = RateLimitConfig(max_calls=5, period=60)
rate_limiter = RateLimiter(redis_client, config)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# POST: /bookings/checkout
@router.post("/bookings/checkout", operation_id="checkoutBooking")
@rate_limiter.rate_limit()
async def checkout_booking(request: Request,
    channel: str = Path(..., description="Service prefix from URL"),
    booking_data: dict = Body(..., description="Booking details"),
    token_data: dict = Depends(get_current_user),
    db: Session = Depends(get_db)):
    
    client_ip = request.client.host
    host = request.headers.get("host", "unknown")
    token = request.headers.get("Authorization", "none")    
    user_id = getattr(token_data, "user_id", None)
    if not user_id:
        log_error(client_ip, host, "/Booking - user token", token, "User ID not found in token data")
        raise HTTPException(status_code=400, detail="User ID not found in token data")
    
    user_channel = getattr(token_data, "channels", None)
    channel_data = fetch_channel_data(channel, db)
        
    if not channel_data:
        log_error(client_ip, host, "/Booking - user channel", token, f"Channel '{channel}' not found in the database")
        raise HTTPException(
        status_code=404, detail=f"Channel '{channel}' not found in the database"
    ) 
    channelName = channel_data.get("name")
    channelBaseURL = channel_data.get("BaseUrl")
    channelApiKey = channel_data.get("ApiKey")
    channelAuthURL = channel_data.get("AuthUrl")

    if not user_channel:
        log_error(client_ip, host, "/Booking - user channel", token, "User's channel is not defined")
        raise HTTPException(status_code=400, detail="User's channel is not defined")
    
    if channelName == 'Error':
        log_error(client_ip, host, "/Booking - user channel", token, "Malformed SOURCE_URL, channel missing")
        raise HTTPException(status_code=500, detail="Malformed SOURCE_URL, channel missing")
    
    if not channelName:
        log_error(client_ip, host, "/Booking - user channel", token, "Invalid API prefix provided")
        raise HTTPException(status_code=400, detail="Invalid API prefix provided")
    
    if channelName not in user_channel:
        log_error(client_ip, host, "/Booking - user channel", token, f"Invalid or unsupported API prefix - user:'{user_channel}', given prefix: '{channelName}' in the parameters..")
        raise HTTPException(status_code=400, detail=f"Invalid or unsupported API prefix - user:'{user_channel}', given prefix: '{channelName}' in the parameters..")
    
    if channelName not in channel:
        log_error(client_ip, host, "/Booking - user channel", token, f"Invalid or unsupported API prefix - parameter value:'{channel}', required prefix: '{channelName}' in the paramters..")
        raise HTTPException(status_code=400, detail=f"Invalid or unsupported API prefix - parameter value:'{channel}', required prefix: '{channelName}' in the paramters..")        
    
    core_api_url = f"{channelBaseURL}/{channelName}/bookings/checkout"
    api_key = channelApiKey
    cache_key_CP = f"Booking_checkout_cache_{channelName}"
    
    try:
        cached_data_CP = await redis_client.get(cache_key_CP)
        if cached_data_CP:
            log_info(client_ip, host, "/Booking", token, "booking Data retrieved from Redis cache.")
            logger.info("Booking checkout Data retrieved from Redis cache.")
            return json.loads(cached_data_CP)
        log_info(client_ip, host, "/Booking", token, "Fetching Client data from the core API.")
        logger.info("Fetching Booking checkout data from the core API.")
        async with httpx.AsyncClient() as client:
             headers = {"Authorization": api_key}
             response = await client.post(core_api_url, json=booking_data, headers=headers)
             response.raise_for_status()
             checkout_response = response.json()

        await redis_client.set(cache_key_CP, json.dumps(checkout_response), ex=300)  # Cache for 5 minutes
        logger.info("Booking checkout Data fetched from core API and cached in Redis.")
        log_info(client_ip, host, "/Booking", token, "booking Data fetched from core API and cached in Redis.")
        return checkout_response
    
    except httpx.RequestError as e:
        log_error(client_ip, host, "/Booking", token, f"Error fetching booking data: {e}")
        raise HTTPException(status_code=500, detail=f"Error during checkout: {e}")
    except httpx.HTTPStatusError as e:
        log_error(client_ip, host, "/Booking", token, f"Error fetching booking data: {e.response.text}")
        raise HTTPException(
            status_code=e.response.status_code,
            detail=f"Error during checkout: {e.response.text}"
        )

# PATCH: /bookings/{order_id}
@router.patch("/bookings/{order_id}", operation_id="updateBooking")
@rate_limiter.rate_limit()
async def update_booking(request: Request,
    channel: str = Path(..., description="Service prefix from URL"),
    order_id: int = Path(..., description="Order ID to update"),
    update_data: dict = Body(..., description="Update details"),
    token_data: dict = Depends(get_current_user),
    db: Session = Depends(get_db)):
    
    client_ip = request.client.host
    host = request.headers.get("host", "unknown")
    token = request.headers.get("Authorization", "none") 
    user_id = getattr(token_data, "user_id", None)
    if not user_id:
        log_error(client_ip, host, "/Update Booking id- user token", token, "User ID not found in token data")
        raise HTTPException(status_code=400, detail="User ID not found in token data")
    
    user_channel = getattr(token_data, "channels", None)
    channel_data = fetch_channel_data(channel, db)
        
    if "error" in channel_data:
        log_error(client_ip, host, "/Update Booking id - user channel", token, f"Channel '{channel}' not found in the database")
        raise HTTPException(
        status_code=404, detail=f"Channel '{channel}' not found in the database"
    ) 
    channelName = channel_data.get("name")
    channelBaseURL = channel_data.get("BaseUrl")
    channelApiKey = channel_data.get("ApiKey")
    channelAuthURL = channel_data.get("AuthUrl")

    if not user_channel:
        log_error(client_ip, host, "/Update Booking id - user channel", token, "User's channel is not defined")
        raise HTTPException(status_code=400, detail="User's channel is not defined")
    
    if channelName == 'Error':
        log_error(client_ip, host, "/Update Booking id - user channel", token, "Malformed SOURCE_URL, channel missing")
        raise HTTPException(status_code=500, detail="Malformed SOURCE_URL, channel missing")
    
    if not channelName:
        log_error(client_ip, host, "/Update Booking id - user channel", token, "Invalid API prefix provided")
        raise HTTPException(status_code=400, detail="Invalid API prefix provided")
    
    if channelName not in user_channel:
        log_error(client_ip, host, "/Update Booking id - user channel", token, f"Invalid or unsupported API prefix - user:'{user_channel}', given prefix: '{channelName}' in the parameters..")
        raise HTTPException(status_code=400, detail=f"Invalid or unsupported API prefix - user:'{user_channel}', given prefix: '{channelName}' in the parameters..")
    
    if channelName not in channel:
        log_error(client_ip, host, "/Update Booking id - user channel", token, f"Invalid or unsupported API prefix - parameter value:'{channel}', required prefix: '{channelName}' in the paramters..")
        raise HTTPException(status_code=400, detail=f"Invalid or unsupported API prefix - parameter value:'{channel}', required prefix: '{channelName}' in the paramters..")
    
    core_api_url = f"{channelBaseURL}/{channelName}/bookings/{order_id}"
    api_key = channelApiKey
    cache_key_CP = f"Booking_update_cache_{channelName}"
    
    try:
        cached_data_CP = await redis_client.get(cache_key_CP)
        if cached_data_CP:
            log_info(client_ip, host, "/Update Booking id", token, "Client Data retrieved from Redis cache.")
            logger.info("Booking update Data retrieved from Redis cache.")
            return json.loads(cached_data_CP)
        
        log_info(client_ip, host, "/Update Booking id", token, "Fetching Client data from the core API.")
        logger.info("Fetching Booking update data from the core API.")
        async with httpx.AsyncClient() as client:
             headers = {"Authorization": api_key}
             response = await client.post(core_api_url, json=update_data, headers=headers)
             response.raise_for_status()
             update_response  = response.json()

        await redis_client.set(cache_key_CP, json.dumps(update_response), ex=300)  # Cache for 5 minutes
        logger.info("Booking update Data fetched from core API and cached in Redis.")
        log_info(client_ip, host, "/Update Booking id", token, "Client Data fetched from core API and cached in Redis.")
        return update_response
    
    except httpx.RequestError as e:
        log_error(client_ip, host, "/Update Booking id", token, f"Error fetching Client data: {e}")
        raise HTTPException(status_code=500, detail=f"Error during checkout: {e}")
    except httpx.HTTPStatusError as e:
        log_error(client_ip, host, "/Update Booking id", token, f"Error fetching Client data: {e.response.text}")
        raise HTTPException(
            status_code=e.response.status_code,
            detail=f"Error during checkout: {e.response.text}"
        )


# DELETE: /bookings/{order_id}
@router.delete("/bookings/{order_id}", operation_id="deleteBooking")
@rate_limiter.rate_limit()
async def delete_booking(request: Request,
    channel: str = Path(..., description="Service prefix from URL"),
    order_id: int = Path(..., description="Order ID to delete"),
    token_data: dict = Depends(get_current_user),
    db: Session = Depends(get_db)):
    
    client_ip = request.client.host
    host = request.headers.get("host", "unknown")
    token = request.headers.get("Authorization", "none")
    user_id = getattr(token_data, "user_id", None)
    if not user_id:
        log_error(client_ip, host, "/Delete Booking id- user token", token, "User ID not found in token data")
        raise HTTPException(status_code=400, detail="User ID not found in token data")
    
    user_channel = getattr(token_data, "channels", None)
    channel_data = fetch_channel_data(channel, db)
        
    if "error" in channel_data:
        log_error(client_ip, host, "/Delete Booking id - user channel", token, f"Channel '{channel}' not found in the database")
        raise HTTPException(
        status_code=404, detail=f"Channel '{channel}' not found in the database"
    ) 
    channelName = channel_data.get("name")
    channelBaseURL = channel_data.get("BaseUrl")
    channelApiKey = channel_data.get("ApiKey")
    channelAuthURL = channel_data.get("AuthUrl")

    if not user_channel:
        log_error(client_ip, host, "/Delete Booking id - user channel", token, "User's channel is not defined")
        raise HTTPException(status_code=400, detail="User's channel is not defined")
    
    if channelName == 'Error':
        log_error(client_ip, host, "/Delete Booking id - user channel", token, "Malformed SOURCE_URL, channel missing")
        raise HTTPException(status_code=500, detail="Malformed SOURCE_URL, channel missing")
    
    if not channelName:
        log_error(client_ip, host, "/Delete Booking id - user channel", token, "Invalid API prefix provided")
        raise HTTPException(status_code=400, detail="Invalid API prefix provided")
    
    if channelName not in user_channel:
        log_error(client_ip, host, "/Delete Booking id - user channel", token, f"Invalid or unsupported API prefix - user:'{user_channel}', given prefix: '{channelName}' in the parameters..")
        raise HTTPException(status_code=400, detail=f"Invalid or unsupported API prefix - user:'{user_channel}', given prefix: '{channelName}' in the parameters..")
    
    if channelName not in channel:
        log_error(client_ip, host, "/Delete Booking id - user channel", token, f"Invalid or unsupported API prefix - parameter value:'{channel}', required prefix: '{channelName}' in the paramters..")
        raise HTTPException(status_code=400, detail=f"Invalid or unsupported API prefix - parameter value:'{channel}', required prefix: '{channelName}' in the paramters..")
    
    core_api_url = f"{channelBaseURL}/{channelName}/bookings/{order_id}"
    api_key = channelApiKey
    cache_key_CP = f"Booking_delete_cache_{channelName}"
    
    try:
        cached_data_CP = await redis_client.get(cache_key_CP)
        if cached_data_CP:
            log_info(client_ip, host, "/Delete Booking id", token, "Client Data retrieved from Redis cache.")
            logger.info("Booking delete Data retrieved from Redis cache.")
            return json.loads(cached_data_CP)
        log_info(client_ip, host, "/Delete Booking id", token, "Fetching Client data from the core API.")
        logger.info("Fetching Booking delete data from the core API.")
        async with httpx.AsyncClient() as client:
             headers = {"Authorization": api_key}
             response = await client.post(core_api_url, headers=headers)
             response.raise_for_status()
             update_response  = response.json()

        await redis_client.set(cache_key_CP, json.dumps(update_response), ex=300)  # Cache for 5 minutes
        logger.info("Booking delete Data fetched from core API and cached in Redis.")
        log_info(client_ip, host, "/Delete Booking id", token, "Client Data fetched from core API and cached in Redis.")
        return update_response
    
    except httpx.RequestError as e:
        log_error(client_ip, host, "/Delete Booking id", token, f"Error fetching Client data: {e}")
        raise HTTPException(status_code=500, detail=f"Error during checkout: {e}")
    except httpx.HTTPStatusError as e:
        log_error(client_ip, host, "/Delete Booking id", token, f"Error fetching Client data: {e.response.text}")
        raise HTTPException(
            status_code=e.response.status_code,
            detail=f"Error during checkout: {e.response.text}"
        )
