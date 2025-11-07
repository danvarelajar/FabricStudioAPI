import base64
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging

logger = logging.getLogger(__name__)

# Create a session with connection pooling and retry strategy
_session = None

def get_session():
    """Get or create a requests session with connection pooling"""
    global _session
    if _session is None:
        _session = requests.Session()
        # Configure retry strategy
        retry_strategy = Retry(
            total=2,  # Only retry twice
            backoff_factor=0.5,  # Wait 0.5s, then 1s between retries
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,  # Number of connection pools
            pool_maxsize=20,  # Max connections per pool
        )
        _session.mount("https://", adapter)
        _session.mount("http://", adapter)
    return _session

def get_access_token(client_id, client_secret, fabric_host):
    """Get access token from FabricStudio OAuth2 endpoint with optimized connection handling"""
    logger.info("Requesting access token from host %s", fabric_host)
    credentials = f"{client_id}:{client_secret}".encode("utf-8")
    encoded_credentials = base64.b64encode(credentials).decode("utf-8")
    headers = {
        "Authorization": f"Basic {encoded_credentials}",
        "Cache-Control": "no-cache",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "client_credentials"
    }
    url = f"https://{fabric_host}/oauth2/token/"
    
    session = get_session()
    try:
        # Reduced timeout: 10 seconds connection, 15 seconds read (was 30 total)
        response = session.post(
            url, 
            headers=headers, 
            data=data, 
            verify=False, 
            timeout=(10, 15)  # (connect timeout, read timeout)
        )
    except requests.Timeout:
        logger.error("Access token request timed out for host %s", fabric_host)
        return None
    except requests.RequestException as exc:
        logger.error("Error requesting access token from %s: %s", fabric_host, exc)
        return None

    if response.status_code != 200:
        logger.error("Access token request failed: %s - %s", response.status_code, response.text)
        return None

    try:
        token_data = response.json()
        token = token_data.get("access_token")
        expires_in = token_data.get("expires_in")  # Seconds until expiration
    except ValueError:
        logger.error("Error parsing token response as JSON")
        return None

    if not token:
        logger.error("Access token not found in response")
        return None
    
    logger.info("Access token received successfully")
    # Return both token and expires_in as a dictionary
    return {"access_token": token, "expires_in": expires_in}