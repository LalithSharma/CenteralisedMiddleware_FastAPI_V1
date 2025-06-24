import logging
from fastapi import APIRouter, Depends, HTTPException, Path, Request
from auth.dependencies import fetch_channel_data, get_current_user, get_db
import httpx, json, os
from redis.asyncio import Redis
from logger import log_error, log_info
from products.utils import RateLimitConfig, RateLimiter
from sqlalchemy.orm import Session

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()

redis_url = os.getenv("REDIS_URL")
# Initialize Redis client
redis_client = Redis.from_url(redis_url, decode_responses=True)

config = RateLimitConfig(max_calls=5, period=60)
rate_limiter = RateLimiter(redis_client, config)

@router.get("/clients", operation_id = "fecthAllClients")
@rate_limiter.rate_limit()
async def get_clients(request: Request, channel: str = Path(..., description="Service prefix from URL"), token_data: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    user_channel = getattr(token_data, "channels", None)
    
    channel_data = fetch_channel_data(channel, db)
    client_ip = request.client.host
    host = request.headers.get("host", "unknown")
    token = request.headers.get("Authorization", "none")
            
    if "error" in channel_data:
        log_error(client_ip, host, "/clients - user channel", token, f"Channel '{channel}' not found in the database")
        raise HTTPException(
        status_code=404, detail=f"Channel '{channel}' not found in the database"
    ) 
    channelName = channel_data.get("name")
    channelBaseURL = channel_data.get("BaseUrl")
    channelApiKey = channel_data.get("ApiKey")
    channelAuthURL = channel_data.get("AuthUrl")
    
    if not user_channel:
        log_error(client_ip, host, "/clients - user channel", token, "User's channel is not defined")
        raise HTTPException(status_code=400, detail="User's channel is not defined")
    
    if channelName == 'Error':
        log_error(client_ip, host, "/clients - user channel", token, "Malformed SOURCE_URL, channel missing")
        raise HTTPException(status_code=500, detail="Malformed SOURCE_URL, channel missing")
    
    if not channelName:
        log_error(client_ip, host, "/clients - user channel", token, "Invalid API prefix provided")
        raise HTTPException(status_code=400, detail="Invalid API prefix provided")
    
    if channelName not in user_channel:
        log_error(client_ip, host, "/clients - user channel", token, f"Invalid or unsupported API prefix - user:'{user_channel}', given prefix: '{channelName}' in the parameters..")
        raise HTTPException(status_code=400, detail=f"Invalid or unsupported API prefix - user:'{user_channel}', given prefix: '{channelName}' in the parameters..")
    
    if channelName not in channel:
        log_error(client_ip, host, "/clients - user channel", token, f"Invalid or unsupported API prefix - parameter value:'{channel}', required prefix: '{channelName}' in the paramters..")
        raise HTTPException(status_code=400, detail=f"Invalid or unsupported API prefix - parameter value:'{channel}', required prefix: '{channelName}' in the paramters..")        
    
    core_api_url = f"{channelBaseURL}/{channelName}/clients"
    api_key = channelApiKey
    cache_key = f"clients_cache_{channelName}"
    
    try:
        cached_data = await redis_client.get(cache_key)
        if cached_data:
            log_info(client_ip, host, "/clients - user channel", token, "Client Data retrieved from Redis cache.")
            logger.info("Client Data retrieved from Redis cache.")
            return json.loads(cached_data)

        log_info(client_ip, host, "/clients - user channel", token, "Fetching Client data from the core API.")
        logger.info("Fetching Client data from the core API.")
        async with httpx.AsyncClient() as client:
             headers = {"Authorization": api_key}
             response = await client.get(core_api_url, headers=headers)
             response.raise_for_status()
             Client_data = response.json()

        await redis_client.set(cache_key, json.dumps(Client_data), ex=300)  # Cache for 5 minutes
        logger.info("Client Data fetched from core API and cached in Redis.")
        log_info(client_ip, host, "/clients - user channel", token, "Client Data fetched from core API and cached in Redis.")
        return Client_data

    except httpx.RequestError as e:
        log_error(client_ip, host, "/clients - user channel", token, f"Error fetching Client data: {e}")
        raise HTTPException(status_code=500, detail=f"Error fetching Client data: {e}")
    except httpx.HTTPStatusError as e:
        log_error(client_ip, host, "/clients - user channel", token, f"Error fetching Client data: {e.response.text}")
        raise HTTPException(status_code=e.response.status_code,
                            detail=f"Error fetching Client data: {e.response.text}")


@router.get("/clients/{client_id}", operation_id = "fecthClientsbyIndex")
@rate_limiter.rate_limit()
async def get_clientsbyIndex(request: Request, channel: str = Path(..., description="Service prefix from URL"), client_id: int = None , token_data: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    user_channel = getattr(token_data, "channels", None)
    channel_data = fetch_channel_data(channel, db)
    
    client_ip = request.client.host
    host = request.headers.get("host", "unknown")
    token = request.headers.get("Authorization", "none")
    
    if not channel_data:
        log_error(client_ip, host, "/client ids - user channel", token, f"Channel '{channel}' not found in the database")
        raise HTTPException(
            status_code=404, detail=f"Channel '{channel}' not found in the database"
        )    
    channelName = channel_data.get("name")
    channelBaseURL = channel_data.get("BaseUrl")
    channelApiKey = channel_data.get("ApiKey")
    channelAuthURL = channel_data.get("AuthUrl")
    
    if not user_channel:
        log_error(client_ip, host, "/client ids - user channel", token, "User's channel is not defined")
        raise HTTPException(status_code=400, detail="User's channel is not defined")
    
    if channelName == 'Error':
        log_error(client_ip, host, "/client ids - user channel", token, "Malformed SOURCE_URL, channel missing")
        raise HTTPException(status_code=500, detail="Malformed SOURCE_URL, channel missing")
    
    if not channelName:
        log_error(client_ip, host, "/client ids - user channel", token, "Invalid API prefix provided")
        raise HTTPException(status_code=400, detail="Invalid API prefix provided")
    
    if channelName not in user_channel:
        log_error(client_ip, host, "/client ids - user channel", token, f"Invalid or unsupported API prefix - user:'{user_channel}', prefix: '{channelName}' in the parameters..")
        raise HTTPException(status_code=400, detail=f"Invalid or unsupported API prefix - user:'{user_channel}', prefix: '{channelName}' in the parameters..")
    
    if channelName not in channel:
        log_error(client_ip, host, "/client ids - user channel", token, f"Invalid or unsupported API prefix - parameter value:'{channel}', required prefix: '{channelName}' in the paramters..")
        raise HTTPException(status_code=400, detail=f"Invalid or unsupported API prefix - parameter value:'{channel}', required prefix: '{channelName}' in the paramters..")
    
    core_api_url = f"{channelBaseURL}/{channelName}/clients/{client_id}"
    api_key = channelApiKey
    cache_key_Clindx = f"clientsByIndex_cache_{channelName}"
    
    try:
        cached_data_ClIndex = await redis_client.get(cache_key_Clindx)
        if cached_data_ClIndex:
            # logger.info("client data by Index retrieved from Redis cache.")
            # return json.loads(cached_data_ClbyIndex)
            ClientbyIndex_data = json.loads(cached_data_ClIndex)
            if 'error' in ClientbyIndex_data or 'data' not in ClientbyIndex_data:
                log_info(client_ip, host, "/client ids", token, "Invalid data found in Redis cache, refetching from API.")
                logger.warning("Invalid data found in Redis cache, refetching from API.")
            else:
                log_info(client_ip, host, "/client ids", token, "Client Data retrieved from Redis cache.")
                logger.info("Product Data retrieved from Redis cache.")
                return ClientbyIndex_data

        log_info(client_ip, host, "/client ids", token, "Fetching client data by Index from the core API.")
        logger.info("Fetching client data by Index from the core API.")
        async with httpx.AsyncClient() as client:
             headers = {"Authorization": api_key}
             response = await client.get(core_api_url, headers=headers)
             response.raise_for_status()
             ClientbyIndex_data = response.json()

        await redis_client.set(cache_key_Clindx, json.dumps(ClientbyIndex_data), ex=300)  # Cache for 5 minutes
        logger.info("client data by Index fetched from core API and cached in Redis.")
        log_info(client_ip, host, "/client ids ", token, "client data by Index fetched from core API and cached in Redis.")
        return ClientbyIndex_data

    except httpx.RequestError as e:
        log_error(client_ip, host, "/client ids", token, f"Error fetching client data by Index: {e}")
        raise HTTPException(status_code=500, detail=f"Error fetching client data by Index: {e}")
    except httpx.HTTPStatusError as e:
        log_error(client_ip, host, "/client ids", token, f"Error fetching client data by Index: {e.response.text}")
        raise HTTPException(status_code=e.response.status_code,
                            detail=f"Error fetching client data by Index: {e.response.text}")


