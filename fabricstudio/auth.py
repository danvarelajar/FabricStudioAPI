import base64
import requests
import logging

logger = logging.getLogger(__name__)
def get_access_token(client_id, client_secret, fabric_host):
    logger.info("Requesting access token from host %s", fabric_host)
    credentials = f"{client_id}:{client_secret}".encode("utf-8")
    encoded_credentials = base64.b64encode(credentials).decode("utf-8")
    headers = {
        "Authorization": f"Basic {encoded_credentials}",
        "Cache-Control": "no-cache",
        "Content-Type": "application/x-www-form-urlencoded",
        # Only in headers if required by your auth server, usually grant_type is in the body
    }
    data = {
        "grant_type": "client_credentials"
    }
    url = f"https://{fabric_host}/oauth2/token/"
    try:
        response = requests.post(url, headers=headers, data=data, verify=False, timeout=30)
    except requests.RequestException as exc:
        logger.error("Error requesting access token: %s", exc)
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