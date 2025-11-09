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
    
    # Ensure credentials are strings and trimmed
    if not client_id or not client_secret:
        logger.error("Client ID or Client Secret is missing or empty")
        return None
    
    client_id = str(client_id).strip()
    client_secret = str(client_secret).strip()
    
    if not client_id or not client_secret:
        logger.error("Client ID or Client Secret is empty after trimming")
        return None
    
    # Debug logging (mask secret for security)
    logger.info(f"Client ID length: {len(client_id)}, Client Secret length: {len(client_secret)}")
    logger.info(f"Client ID (first 20 chars): {client_id[:20]}...")
    logger.info(f"Client Secret (first 5 chars): {client_secret[:5]}...")
    logger.info(f"Client Secret (last 5 chars): ...{client_secret[-5:]}")
    
    # Verify no hidden characters or encoding issues
    if '\n' in client_id or '\r' in client_id:
        logger.warning("Client ID contains newline characters!")
    if '\n' in client_secret or '\r' in client_secret:
        logger.warning("Client Secret contains newline characters!")
    
    credentials = f"{client_id}:{client_secret}".encode("utf-8")
    encoded_credentials = base64.b64encode(credentials).decode("utf-8")
    
    # Log the base64 encoded value (first 20 chars) for comparison with curl
    logger.info(f"Base64 encoded credentials (first 30 chars): {encoded_credentials[:30]}...")
    headers = {
        "Authorization": f"Basic {encoded_credentials}",
        "Cache-Control": "no-cache",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "client_credentials"
    }
    # Try the standard OAuth2 token endpoint
    url = f"https://{fabric_host}/oauth2/token/"
    
    logger.debug(f"OAuth2 URL: {url}")
    logger.debug(f"Request headers: {list(headers.keys())}")
    logger.debug(f"Request data: grant_type=client_credentials")
    
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
        
        # If 404, try without trailing slash
        if response.status_code == 404:
            url_no_slash = f"https://{fabric_host}/oauth2/token"
            logger.debug(f"Trying alternative URL without trailing slash: {url_no_slash}")
            response = session.post(
                url_no_slash,
                headers=headers,
                data=data,
                verify=False,
                timeout=(10, 15)
            )
    except requests.Timeout as e:
        logger.error("Access token request timed out for host %s", fabric_host)
        logger.error("Connection timeout indicates host %s is not reachable from this network", fabric_host)
        logger.error("Possible causes: host is down, network unreachable, VPN required, or firewall blocking")
        return None
    except requests.ConnectionError as e:
        logger.error("Connection error requesting access token from %s: %s", fabric_host, e)
        logger.error("Host %s may be unreachable - check network connectivity, VPN, or firewall rules", fabric_host)
        return None
    except requests.RequestException as exc:
        logger.error("Error requesting access token from %s: %s", fabric_host, exc)
        return None

    if response.status_code != 200:
        error_detail = response.text
        logger.error("Access token request failed: %s - %s", response.status_code, error_detail)
        
        # Provide more specific error messages
        if response.status_code == 401:
            if "invalid_client" in error_detail.lower():
                logger.error("Invalid client credentials - check that client_id and client_secret are correct and match the registered OAuth2 application")
            else:
                logger.error("Authentication failed - credentials may be incorrect or expired")
        elif response.status_code == 404:
            logger.error("OAuth2 endpoint not found - check that the host URL is correct (should be https://hostname/oauth2/token/)")
        elif response.status_code >= 500:
            logger.error("FabricStudio server error - the service may be unavailable")
        
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