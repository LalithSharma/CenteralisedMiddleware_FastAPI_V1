import logging
import os
from typing import Optional
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from auth.dependencies import fetch_channel_data, fetch_urls, get_current_user, get_db
import httpx
import json
from redis.asyncio import Redis
from logger import log_error, log_info
from DLL.utils import RateLimitConfig, RateLimiter

router = APIRouter()
redis_url = os.getenv("REDIS_URL")
redis_client = Redis.from_url(redis_url, decode_responses=True)

config = RateLimitConfig(max_calls=60, period=60)
rate_limiter = RateLimiter(redis_client, config)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@router.get("/clients",
            operation_id = "fecthAPIRoutes")
@rate_limiter.rate_limit()
async def get_APIresponse(
                        request: Request,
                        channel: str = Path(..., description="Service prefix from URL"),
                        client_id: int = None,
                        searchPath: Optional[str] = Query(None, description="Enter searching path"),
                        id: Optional[int] = Query(None, description="Enter ID will revented to the searchpath"),
                        token_data: dict = Depends(get_current_user),
                        db: Session = Depends(get_db)):
    client_ip = request.client.host
    host = request.headers.get("host", "unknown")
    token = request.headers.get("Authorization", "none")
    
    user_channel = getattr(token_data, "channels", None)
    channel_data = fetch_channel_data(channel, db)
    urls_patterns = fetch_urls(db)    
    print("displaye url patterns", urls_patterns)
    if not channel_data:
        #log_error(client_ip, host, "/product ids - calendar - user channel", token, f"Channel '{channel}' not found in the database")
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
    
    if not client_id and id:
        raise HTTPException(status_code=400, detail=f"client_id is mandatory when providing product_id, receptionist_id, or order_id.")
    
    #core_api_url = f"{channelBaseURL}/{channelName}/clients/{client_no}/products/{product_no}"
    core_api_url = f"{channelBaseURL}/{channelName}"
    api_key = channelApiKey
    
    #Step1 checks only clients with channel name...............................
    if channel and not client_id:
        try:
            search_channels= searchChannel(urls_patterns)
            if search_channels:                              
                first_match   = search_channels[0] 
                core_api_url  += first_match["url"]
                MaxTime    = first_match["time"]
                log_info(
                        client_ip, host, first_match["url"], token,
                        f"Matched channel '{channel}' → {core_api_url} (cache={MaxTime}s)",
                    )
                request_url = core_api_url
                cacheTime = MaxTime
                print("requestd url ", request_url)
            else:
                log_info(
                    client_ip, host, "/", token,
                    f"No /clients entry for channel '{channel}' – using base URL only",
                )
        except Exception as e:
                log_error(client_ip, host, "/", token, f"Error while processing channel match: {e}",)
        
    #step2 checks clients with client_id.......................................
    elif client_id and not searchPath and not id:
        try:
            searchClient = searchwithClientid(urls_patterns)
            if searchClient:
                url_match = searchClient[0]
                formatted_path = url_match["url"]
                MaxTime = url_match["time"]                
                if client_id:
                    core_api_url += formatted_path.replace("{client_id}", str(client_id)) 
                request_url = core_api_url
                cacheTime = MaxTime
                log_info(
                            client_ip, host, formatted_path, token,
                            f"Matched client '{client_id}' → {core_api_url} (cache={MaxTime}s)",
                        )
            else:
                log_info(
                    client_ip, host, "/", token,
                    f"No path pattern found for client '{client_id}' – using base URL only",
                )
            
        except Exception as e:
                log_error(
                    client_ip, host, "/", token,
                    f"Error while processing client match: {e}",
                )
    
    #step3 find only searchpath str....................................................
    if searchPath and not id:
        try:
            ## a.Match all paths that include the searchPath
            matched_paths = searchwithPath(urls_patterns, searchPath, id)
            ## b.Format the final path
            if matched_paths:
                matched_path_template = matched_paths[0]["path"]
                cacheTime = matched_paths[1]["maxcache"]
                formatted_path = matched_path_template
                if client_id:
                    formatted_path = formatted_path.replace("{client_id}", str(client_id))       
                     
                request_url = f"{core_api_url}{formatted_path}"
                log_info(
                            client_ip, host, formatted_path, token,
                            f"Matched client '{client_id}' → {core_api_url} (cache={cacheTime}s)",
                        )
            else:
                log_info(
                    client_ip, host, "/", token,
                    f"No path pattern found for client '{client_id}' – using base URL only",
                )
        except Exception as e:
                log_error(
                    client_ip, host, searchPath, token,
                    f"Path search failed for '{searchPath}': {e}",
                )
                raise HTTPException(status_code=404, detail=f"Path search failed for '{searchPath}': {e}")
    
    #step4 find If `id` is provided and searchpath, refine further..........................
    if id and searchPath:
        try:
            print("search with path id begin")
            requestpath_urls = searchPathwithId(urls_patterns, searchPath, id)
            if requestpath_urls:
                raw_urls = requestpath_urls["url"]
                cacheTime = requestpath_urls["maxcache"]
                if client_id:
                    raw_urls = raw_urls.replace("{client_id}", str(client_id))
                
                request_url = f"{core_api_url}{raw_urls}"
                log_info(
                            client_ip, host, raw_urls, token,
                            f"Matched client '{client_id}' → {core_api_url} (cache={cacheTime}s)",
                        )            
        except Exception as e:
                log_error(
                    client_ip, host, searchPath, token,
                    f"searchPathwithId failed for '{searchPath}' + id '{id}': {e}",
                )
                raise HTTPException(status_code=404, detail=f"Path search failed for '{searchPath}': {e}")

    print('base url', request_url)
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
             response = await client.get(request_url, headers=headers)
             response.raise_for_status()
             productbyIndex_data = response.json()
        
        await redis_client.set(cache_key_PCIndex, json.dumps(productbyIndex_data), ex=cacheTime)  # Cache for 60 minutes
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
        

def searchChannel(urls_patterns):
    return [
        {"url": p["path"], "time": p["maxcache"]}
        for p in urls_patterns
        if p["path"] == "/clients"
    ]

def searchwithClientid(urls_patterns):
    return [
        {"url": p["path"], "time": p["maxcache"]}
        for p in urls_patterns
        if p["path"] == "/clients/{client_id}"
    ]

def searchwithPath(urls_patterns, search_path: str, id: str = None):
    matched_paths = []
    search_segments = search_path.lower().split("/")
    
    # 1. Match all paths that contain all segments from search_path
    for path in urls_patterns:
        path_segments = path["path"].lower().split("/")
        if all(seg in path_segments for seg in search_segments):
            matched_paths.append(path)
    print("check matched seaarch", matched_paths)
    if not matched_paths:
        raise HTTPException(
            status_code=404,
            detail=f"No matching path found for searchPath: {search_path}"
        )
    return matched_paths
        
def searchPathwithId(urls_patterns, search_path: str, id: str = None):
    matched_paths = []
    search_segments = search_path.lower().split("/")
    
    # 1. Match all paths that contain all segments from search_path
    for path in urls_patterns:
        path_segments = path["path"].lower().split("/")
        if all(seg in path_segments for seg in search_segments):
            matched_paths.append(path)

    if not matched_paths:
        raise HTTPException(
            status_code=404,
            detail=f"No matching path found for searchPath: {search_path}"
        )

    # 2. If id is provided, refine further using placeholder pattern
    if id:
        singular = search_segments[0].rstrip("s")  # crude singular
        placeholder = f"{{{singular}_id}}"
        matched_paths = [
            path for path in matched_paths
            if "{client_id}" in path["path"] and placeholder in path["path"]
        ]
        if not matched_paths:
            raise HTTPException(
                status_code=404,
                detail=f"No matching path found for searchPath: {search_path} with ID: {placeholder}"
            )
        chosen_url = matched_paths[0]["path"].replace(placeholder, str(id))
    else:
        chosen_url = matched_paths[0]["path"]
    return {
        "url": chosen_url,
        "maxcache": matched_paths[0]["maxcache"],
    }
