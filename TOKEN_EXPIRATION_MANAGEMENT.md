# Token Expiration Management in Session-Based Architecture

## Token Lifecycle Overview

### Token States:
1. **Valid** - Token exists and hasn't expired
2. **Expiring Soon** - Token expires within threshold (e.g., 5 minutes)
3. **Expired** - Token has passed expiration time
4. **Missing** - No token for this host

### Session States:
1. **Active** - Session is valid and has tokens
2. **Expiring** - Session will expire soon
3. **Expired** - Session has expired
4. **Invalid** - Session invalidated/revoked

---

## Token Expiration Storage

### Database Schema
```sql
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    nhi_credential_id INTEGER,
    tokens_encrypted TEXT,  -- JSON: {host: {token, expires_at, refresh_at}}
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,  -- Session expiration
    FOREIGN KEY (nhi_credential_id) REFERENCES nhi_credentials(id)
);

-- Token structure in tokens_encrypted:
{
    "fs1.fortipoc.io": {
        "token": "encrypted_token",
        "expires_at": "2025-01-01T12:00:00Z",  -- When token expires
        "refresh_at": "2025-01-01T11:55:00Z",  -- When to refresh (5 min before)
        "created_at": "2025-01-01T10:00:00Z"
    }
}
```

---

## Token Expiration Management Strategies

### Strategy 1: Proactive Refresh (Recommended)

**How it works:**
- Tokens are refreshed automatically before expiration
- Refresh threshold: 5 minutes before expiration
- Background task checks and refreshes tokens
- Transparent to user - no interruptions

**Implementation:**
```python
async def refresh_expiring_tokens():
    """Background task to refresh tokens before expiration"""
    sessions = get_active_sessions()
    for session in sessions:
        tokens = decrypt_session_tokens(session.tokens_encrypted, session.session_id)
        now = datetime.now()
        
        for host, token_info in tokens.items():
            refresh_at = datetime.fromisoformat(token_info['refresh_at'])
            
            # If token needs refresh (within 5 min of expiration)
            if now >= refresh_at:
                # Get NHI credential
                nhi_cred = get_nhi_credential(session.nhi_credential_id)
                
                # Refresh token
                new_token_data = get_access_token(
                    nhi_cred.client_id,
                    nhi_cred.client_secret,
                    host
                )
                
                if new_token_data:
                    # Update token in session
                    token_info['token'] = encrypt_token(new_token_data['access_token'])
                    token_info['expires_at'] = calculate_expiration(new_token_data['expires_in'])
                    token_info['refresh_at'] = calculate_refresh_time(token_info['expires_at'])
        
        # Save updated tokens
        save_session_tokens(session.session_id, tokens)
```

**Advantages:**
- ✅ No user interruption
- ✅ Tokens always fresh
- ✅ Seamless experience

**Disadvantages:**
- ⚠️ Requires background task
- ⚠️ More complex implementation

---

### Strategy 2: Lazy Refresh (On-Demand)

**How it works:**
- Check token expiration on each API request
- If expired or expiring soon, refresh immediately
- Cache refreshed token for subsequent requests

**Implementation:**
```python
def get_access_token_from_session(request: Request, fabric_host: str) -> Optional[str]:
    """Get token from session, refresh if needed"""
    session_id = request.cookies.get("fabricstudio_session")
    if not session_id:
        return None
    
    session = get_session(session_id)
    if not session:
        return None
    
    tokens = decrypt_session_tokens(session.tokens_encrypted, session.session_id)
    token_info = tokens.get(fabric_host)
    
    if not token_info:
        return None
    
    expires_at = datetime.fromisoformat(token_info['expires_at'])
    now = datetime.now()
    
    # Check if token expired or expiring soon (within 1 minute)
    if now >= expires_at - timedelta(minutes=1):
        # Refresh token
        nhi_cred = get_nhi_credential(session.nhi_credential_id)
        new_token_data = get_access_token(
            nhi_cred.client_id,
            nhi_cred.client_secret,
            fabric_host
        )
        
        if new_token_data:
            # Update token
            token_info['token'] = encrypt_token(new_token_data['access_token'])
            token_info['expires_at'] = calculate_expiration(new_token_data['expires_in'])
            token_info['refresh_at'] = calculate_refresh_time(token_info['expires_at'])
            
            # Save updated session
            save_session_tokens(session.session_id, tokens)
            
            return decrypt_token(token_info['token'])
        else:
            # Failed to refresh - return None
            return None
    
    # Token is still valid
    return decrypt_token(token_info['token'])
```

**Advantages:**
- ✅ Simple implementation
- ✅ No background tasks needed
- ✅ Refresh only when needed

**Disadvantages:**
- ⚠️ First request after expiration may be slower
- ⚠️ Multiple simultaneous requests may trigger multiple refreshes

---

### Strategy 3: Hybrid Approach (Best of Both)

**How it works:**
- Background task refreshes tokens proactively
- Lazy refresh as fallback if background task missed
- Combines reliability of proactive with simplicity of lazy

**Implementation:**
```python
# Background task (runs every 2 minutes)
async def refresh_expiring_tokens_background():
    sessions = get_active_sessions()
    for session in sessions:
        refresh_tokens_if_needed(session, threshold_minutes=5)

# Request-time check (fallback)
def get_access_token_from_session(request: Request, fabric_host: str):
    session = get_session_from_request(request)
    tokens = get_session_tokens(session)
    token_info = tokens.get(fabric_host)
    
    # Check expiration
    if is_token_expired_or_expiring_soon(token_info, threshold_minutes=1):
        # Lazy refresh as fallback
        refresh_token_for_host(session, fabric_host)
    
    return get_token_from_info(token_info)
```

---

## Token Expiration Handling

### Scenario 1: Token Expired During Request

```python
@app.get("/tasks/status")
def tasks_status(request: Request, fabric_host: str):
    token = get_access_token_from_session(request, fabric_host)
    
    if not token:
        # Try to refresh
        refreshed = refresh_session_token(request, fabric_host)
        if not refreshed:
            raise HTTPException(401, "Session expired or invalid. Please reload NHI credential.")
        token = get_access_token_from_session(request, fabric_host)
    
    if not token:
        raise HTTPException(401, "Failed to get access token")
    
    count = get_running_task_count(fabric_host, token)
    return {"running_count": count}
```

### Scenario 2: Multiple Tokens Expiring

```python
def refresh_all_expiring_tokens(session_id: str):
    """Refresh all tokens that are expiring soon"""
    session = get_session(session_id)
    tokens = decrypt_session_tokens(session.tokens_encrypted, session.session_id)
    nhi_cred = get_nhi_credential(session.nhi_credential_id)
    
    refreshed_count = 0
    failed_hosts = []
    
    for host, token_info in tokens.items():
        if is_expiring_soon(token_info):
            new_token = get_access_token(
                nhi_cred.client_id,
                nhi_cred.client_secret,
                host
            )
            
            if new_token:
                update_token_info(token_info, new_token)
                refreshed_count += 1
            else:
                failed_hosts.append(host)
    
    if refreshed_count > 0:
        save_session_tokens(session.session_id, tokens)
    
    return {
        "refreshed": refreshed_count,
        "failed": failed_hosts
    }
```

### Scenario 3: Token Refresh Failure

```python
def handle_token_refresh_failure(session_id: str, host: str, error: Exception):
    """Handle case when token refresh fails"""
    logger.warning(f"Token refresh failed for {host} in session {session_id}: {error}")
    
    # Option 1: Mark token as invalid, require user action
    mark_token_invalid(session_id, host)
    
    # Option 2: Return error to user
    raise HTTPException(
        401,
        f"Failed to refresh token for {host}. Please reload NHI credential."
    )
    
    # Option 3: Retry with exponential backoff
    schedule_retry(session_id, host, retry_count=0)
```

---

## Session Expiration vs Token Expiration

### Session Expiration
- **Purpose**: Security timeout for user inactivity
- **Default**: 1 hour of inactivity
- **Behavior**: Entire session invalidated, all tokens cleared
- **User Action**: Re-enter encryption password

### Token Expiration
- **Purpose**: API token lifetime from FabricStudio API
- **Default**: Varies (typically 1-24 hours)
- **Behavior**: Only that token refreshed, session continues
- **User Action**: None (automatic refresh)

### Relationship:
```
Session (1 hour) > Token (variable)
├── Session expires → All tokens cleared, user must re-authenticate
├── Token expires → Token refreshed automatically, session continues
└── Both expire → User must re-authenticate
```

---

## Recommended Implementation

### 1. Token Storage with Expiration
```python
class TokenInfo:
    token: str  # Encrypted
    expires_at: datetime
    refresh_at: datetime  # 5 minutes before expiration
    created_at: datetime
    
def create_token_info(token_data: dict) -> TokenInfo:
    expires_at = datetime.now() + timedelta(seconds=token_data['expires_in'])
    refresh_at = expires_at - timedelta(minutes=5)  # Refresh 5 min before
    
    return TokenInfo(
        token=encrypt_token(token_data['access_token']),
        expires_at=expires_at,
        refresh_at=refresh_at,
        created_at=datetime.now()
    )
```

### 2. Token Validation Function
```python
def is_token_valid(token_info: TokenInfo) -> bool:
    """Check if token is still valid"""
    return datetime.now() < token_info.expires_at

def is_token_expiring_soon(token_info: TokenInfo, minutes: int = 5) -> bool:
    """Check if token should be refreshed soon"""
    return datetime.now() >= token_info.refresh_at
```

### 3. Token Refresh Function
```python
async def refresh_token_for_host(session_id: str, host: str) -> bool:
    """Refresh token for a specific host"""
    session = get_session(session_id)
    if not session:
        return False
    
    nhi_cred = get_nhi_credential(session.nhi_credential_id)
    if not nhi_cred:
        return False
    
    # Get decrypted credentials (using session key)
    client_id, client_secret = decrypt_nhi_credential(nhi_cred, session.session_key)
    
    # Fetch new token
    token_data = get_access_token(client_id, client_secret, host)
    if not token_data:
        return False
    
    # Update token in session
    tokens = get_session_tokens(session)
    tokens[host] = create_token_info(token_data)
    save_session_tokens(session.session_id, tokens)
    
    return True
```

### 4. Background Refresh Task
```python
from apscheduler.schedulers.asyncio import AsyncIOScheduler

scheduler = AsyncIOScheduler()

@scheduler.scheduled_job('interval', minutes=2)
async def refresh_expiring_tokens_job():
    """Background job to refresh tokens before expiration"""
    active_sessions = get_active_sessions()
    
    for session in active_sessions:
        tokens = get_session_tokens(session)
        now = datetime.now()
        
        for host, token_info in tokens.items():
            # Refresh if within 5 minutes of expiration
            if now >= token_info.refresh_at and now < token_info.expires_at:
                await refresh_token_for_host(session.session_id, host)
                logger.info(f"Refreshed token for {host} in session {session.session_id}")

# Start scheduler
scheduler.start()
```

### 5. Request-Time Token Access
```python
def get_access_token_from_session(request: Request, fabric_host: str) -> Optional[str]:
    """Get token from session, refresh if needed"""
    session = get_session_from_request(request)
    if not session:
        return None
    
    tokens = get_session_tokens(session)
    token_info = tokens.get(fabric_host)
    
    if not token_info:
        return None
    
    # Check if token expired
    if not is_token_valid(token_info):
        # Try to refresh
        if refresh_token_for_host(session.session_id, fabric_host):
            # Get updated token info
            tokens = get_session_tokens(session)
            token_info = tokens.get(fabric_host)
        else:
            # Refresh failed
            logger.warning(f"Failed to refresh token for {fabric_host}")
            return None
    
    # Check if token expiring soon (fallback if background task missed)
    if is_token_expiring_soon(token_info, minutes=1):
        # Refresh proactively
        refresh_token_for_host(session.session_id, fabric_host)
        tokens = get_session_tokens(session)
        token_info = tokens.get(fabric_host)
    
    return decrypt_token(token_info.token)
```

---

## Token Expiration Flow Diagram

```
User Request
    ↓
Get Token from Session
    ↓
Token Valid? ──No──→ Refresh Token ──Success?──No──→ Return 401
    ↓ Yes                                    ↓ Yes
    ↓                                        ↓
    ↓                                    Update Token in Session
    ↓                                        ↓
    ↓                                    Return Token
    ↓                                        ↓
Use Token for API Call ←─────────────────────┘
```

---

## Error Handling

### Token Refresh Failures
```python
class TokenRefreshError(Exception):
    pass

def handle_token_refresh_error(session_id: str, host: str, error: Exception):
    """Handle token refresh errors"""
    
    # Log error
    logger.error(f"Token refresh failed for {host}: {error}")
    
    # Options:
    # 1. Return error to user
    raise HTTPException(401, f"Failed to refresh token for {host}")
    
    # 2. Mark token as invalid
    mark_token_invalid(session_id, host)
    
    # 3. Schedule retry
    schedule_retry(session_id, host)
    
    # 4. Clear session if multiple failures
    if get_failure_count(session_id) > 3:
        invalidate_session(session_id)
```

### Expired Session Handling
```python
def handle_expired_session(request: Request):
    """Handle expired session"""
    # Clear session cookie
    response = JSONResponse({"error": "Session expired"})
    response.delete_cookie("fabricstudio_session")
    
    # Log session expiration
    logger.info(f"Session expired for {request.client.host}")
    
    return response
```

---

## Frontend Token Expiration Handling

### Session Status Check
```javascript
async function checkSessionStatus() {
  const res = await api('/auth/session/status', {
    credentials: 'include' // Include cookie
  });
  
  if (res.ok) {
    const data = await res.json();
    return data;
  } else if (res.status === 401) {
    // Session expired
    handleSessionExpired();
    return null;
  }
  return null;
}

function handleSessionExpired() {
  // Clear any cached data
  // Show message to user
  showStatus('Session expired. Please reload NHI credential.');
  // Optionally redirect to reload
}
```

### Automatic Token Refresh (Frontend)
```javascript
// Frontend doesn't need to manage tokens, but can check session status
setInterval(async () => {
  const status = await checkSessionStatus();
  if (status && status.session_expires_at) {
    const expiresAt = new Date(status.session_expires_at);
    const now = new Date();
    const minutesUntilExpiry = (expiresAt - now) / 60000;
    
    if (minutesUntilExpiry < 5) {
      // Refresh session
      await api('/auth/session/refresh', {
        method: 'POST',
        credentials: 'include'
      });
    }
  }
}, 60000); // Check every minute
```

---

## Summary

### Token Expiration Management:

1. **Proactive Refresh** (Background Task)
   - Runs every 2 minutes
   - Refreshes tokens 5 minutes before expiration
   - Transparent to user

2. **Lazy Refresh** (On-Demand)
   - Checks token expiration on each request
   - Refreshes if expired or expiring soon (< 1 minute)
   - Fallback if background task missed

3. **Error Handling**
   - Failed refresh → Return 401 error
   - Multiple failures → Invalidate session
   - User must re-authenticate

4. **Session vs Token Expiration**
   - Session expires → User re-authenticates
   - Token expires → Auto-refreshed transparently

### Benefits:
- ✅ **Seamless Experience** - Tokens refreshed automatically
- ✅ **Reliability** - Multiple refresh strategies
- ✅ **Security** - Tokens never exposed, automatic expiration
- ✅ **Error Recovery** - Graceful handling of failures

This ensures tokens are always fresh and users never experience interruptions due to expired tokens!

