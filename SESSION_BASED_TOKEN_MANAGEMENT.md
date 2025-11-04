# Session-Based Token Management Architecture Proposal

## Current Architecture (Token-Based)

### Current Flow:
1. User enters Encryption Password and loads NHI credential
2. Frontend decrypts credentials and stores tokens in JavaScript `Map` (`accessTokens`)
3. Frontend sends tokens via `Authorization: Bearer <token>` header
4. Tokens are visible in browser memory, DevTools, Network tab

### Security Issues:
- ✅ Tokens no longer in URLs (fixed)
- ⚠️ Tokens still in browser memory (JavaScript Map)
- ⚠️ Tokens visible in DevTools Network tab
- ⚠️ Tokens accessible via browser console
- ⚠️ XSS vulnerabilities could expose tokens

---

## Proposed Architecture (Session-Based)

### New Flow:
1. User enters Encryption Password and loads NHI credential
2. Frontend sends Encryption Password to backend
3. Backend validates password, creates secure session
4. Backend stores tokens server-side (encrypted with session key)
5. Backend returns session cookie (HTTP-only, Secure, SameSite)
6. Frontend sends session cookie with requests (automatic)
7. Backend extracts tokens from session, uses them for API calls

### Security Benefits:
- ✅ **Tokens never exposed to frontend** - stored server-side only
- ✅ **Browser memory safe** - no tokens in JavaScript
- ✅ **XSS protection** - HTTP-only cookies not accessible via JavaScript
- ✅ **Network tab** - cookies visible but tokens never in headers
- ✅ **Session management** - automatic expiration, revocation
- ✅ **Centralized token management** - easier rotation, refresh

---

## Implementation Plan

### Phase 1: Backend Session Management

#### 1.1 Add Session Dependencies
```python
# requirements.txt additions
fastapi-sessions = "^0.4.0"  # or use starlette sessions
itsdangerous = "^2.1.0"  # For signed cookies
```

#### 1.2 Session Storage Structure
```python
# Store tokens encrypted in session
session_data = {
    "session_id": "unique_session_id",
    "user_id": "optional_user_id",
    "nhi_credential_id": nhi_id,
    "tokens_by_host": {
        "fs1.fortipoc.io": {
            "token": "encrypted_token",
            "expires_at": "2025-01-01T12:00:00"
        }
    },
    "created_at": timestamp,
    "last_used": timestamp,
    "expires_at": timestamp  # Session expiration
}
```

#### 1.3 Session Management Endpoints

**POST /auth/session/create**
- Input: `{ encryption_password: str, nhi_credential_id: int }`
- Validates encryption password
- Decrypts NHI credential
- Creates session
- Stores tokens in session (encrypted)
- Returns: `{ session_id: str, expires_at: str }`
- Sets HTTP-only cookie

**POST /auth/session/refresh**
- Validates existing session
- Refreshes expiration
- Returns updated session info

**POST /auth/session/revoke**
- Invalidates session
- Clears tokens
- Clears cookie

**GET /auth/session/status**
- Returns session status
- Returns token status per host

#### 1.4 Token Extraction Middleware
```python
@app.middleware("http")
async def session_token_middleware(request: Request, call_next):
    # Extract session from cookie
    session_id = request.cookies.get("fabricstudio_session")
    if session_id:
        # Get session data
        session_data = get_session(session_id)
        if session_data:
            # Extract tokens and add to request state
            request.state.session_tokens = session_data.get("tokens_by_host", {})
    response = await call_next(request)
    return response
```

#### 1.5 Update API Endpoints
- Modify `get_access_token_from_request()` to check `request.state.session_tokens`
- Prioritize session tokens over Authorization header
- Fallback to Authorization header for backward compatibility

### Phase 2: Frontend Changes

#### 2.1 Session Management
```javascript
// Replace token storage with session management
async function createSession(encryptionPassword, nhiId) {
  const res = await api('/auth/session/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include', // Important for cookies
    body: JSON.stringify({
      encryption_password: encryptionPassword,
      nhi_credential_id: nhiId
    })
  });
  return res.ok;
}

// Remove accessTokens Map
// Remove mergeAuth() function
// Requests automatically include session cookie
```

#### 2.2 Update API Calls
```javascript
// Simplified - no token management needed
async function api(path, options = {}) {
  // Cookie automatically included with credentials: 'include'
  return fetch(url, {
    ...options,
    credentials: 'include' // Include cookies
  });
}
```

#### 2.3 Session Lifecycle
- Create session when NHI credential loaded
- Refresh session periodically
- Revoke session on logout/navigation
- Handle session expiration gracefully

---

## Security Considerations

### Session Cookie Security
```python
# Secure cookie settings
response.set_cookie(
    key="fabricstudio_session",
    value=session_id,
    httponly=True,        # Not accessible via JavaScript
    secure=True,          # HTTPS only
    samesite="strict",   # CSRF protection
    max_age=3600,        # 1 hour expiration
    path="/"
)
```

### Session Storage Options

**Option 1: Signed Cookies (Simple)**
- Store session data in signed cookie
- Pros: Stateless, simple
- Cons: Size limits, server-side decryption needed

**Option 2: Database Sessions (Recommended)**
- Store session data in database
- Cookie contains only session ID
- Pros: Scalable, no size limits, easier revocation
- Cons: Requires database lookup

**Option 3: Redis/Memcached (Production)**
- Store sessions in Redis
- Pros: Fast, scalable, built-in expiration
- Cons: Additional infrastructure

### Token Encryption
- Encrypt tokens in session using session-specific key
- Derive key from Encryption Password + Session ID
- Use AES-256-GCM for authenticated encryption

### Session Expiration
- Session expires after inactivity (e.g., 1 hour)
- Tokens expire based on their own expiration
- Auto-refresh session on activity
- Clear session on logout

---

## Migration Strategy

### Option A: Gradual Migration (Recommended)
1. **Phase 1**: Add session support alongside existing token system
2. **Phase 2**: Allow both session and token auth (backward compatibility)
3. **Phase 3**: Migrate frontend to use sessions
4. **Phase 4**: Remove token support after migration period

### Option B: Complete Replacement
1. Implement session system
2. Update all endpoints simultaneously
3. Update frontend
4. Remove old token system

---

## Implementation Details

### Backend Session Store
```python
# New table: sessions
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    nhi_credential_id INTEGER,
    tokens_encrypted TEXT,  # JSON encrypted with session key
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    FOREIGN KEY (nhi_credential_id) REFERENCES nhi_credentials(id)
);

CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
```

### Session Key Derivation
```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets

def derive_session_key(encryption_password: str, session_id: str) -> bytes:
    """Derive encryption key for session"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=session_id.encode(),
        iterations=100000,
    )
    return kdf.derive(encryption_password.encode())
```

### Token Encryption in Session
```python
def encrypt_tokens_for_session(tokens: dict, session_key: bytes) -> str:
    """Encrypt tokens dictionary for storage in session"""
    tokens_json = json.dumps(tokens)
    fernet = Fernet(base64.urlsafe_b64encode(session_key[:32]))
    encrypted = fernet.encrypt(tokens_json.encode())
    return base64.urlsafe_b64encode(encrypted).decode()
```

---

## API Endpoint Changes

### New Endpoints

**POST /auth/session/create**
```json
Request:
{
  "encryption_password": "user_password",
  "nhi_credential_id": 1
}

Response:
{
  "session_id": "abc123...",
  "expires_at": "2025-01-01T13:00:00Z",
  "tokens_count": 2
}
```

**GET /auth/session/status**
```json
Response:
{
  "session_id": "abc123...",
  "nhi_credential_id": 1,
  "tokens_by_host": {
    "fs1.fortipoc.io": {
      "expires_at": "2025-01-01T12:00:00Z",
      "valid": true
    }
  },
  "session_expires_at": "2025-01-01T13:00:00Z"
}
```

**POST /auth/session/refresh**
- Extends session expiration
- Returns new expiration time

**POST /auth/session/revoke**
- Invalidates session
- Clears all tokens

### Modified Endpoints
- All existing endpoints work with session tokens automatically
- `get_access_token_from_request()` checks session first, then Authorization header

---

## Frontend Changes Summary

### Removed:
- `accessTokens` Map
- `mergeAuth()` function
- Token storage logic
- Token acquisition logic (moved to backend)

### Added:
- Session creation on NHI load
- Session refresh logic
- Session expiration handling
- Cookie-based authentication

### Simplified:
- API calls - no token management
- Authorization logic - handled by backend
- Token refresh - handled by backend

---

## Security Comparison

| Aspect | Current (Token-Based) | Proposed (Session-Based) |
|--------|----------------------|--------------------------|
| Token Storage | Browser Memory (Map) | Server-Side (Encrypted) |
| Token Visibility | DevTools, Console | None (Server-Side) |
| XSS Risk | High (Tokens in JS) | Low (HTTP-only cookies) |
| CSRF Risk | Low (Same-origin) | Mitigated (SameSite) |
| Token Theft | Possible via XSS | Not possible |
| Session Management | Manual | Automatic |
| Token Rotation | Manual | Automated |
| Revocation | Manual | Immediate |

---

## Benefits Summary

1. **Enhanced Security**
   - Tokens never exposed to frontend
   - XSS cannot steal tokens
   - Centralized token management

2. **Better User Experience**
   - Seamless session management
   - Automatic token refresh
   - Single sign-on experience

3. **Easier Maintenance**
   - Token logic centralized
   - Easier to implement token rotation
   - Better audit trail

4. **Scalability**
   - Can scale to multiple sessions
   - Support for concurrent sessions
   - Better load balancing support

---

## Implementation Effort Estimate

- **Backend Changes**: 2-3 days
  - Session storage (database)
  - Session endpoints
  - Middleware updates
  - Token encryption/decryption

- **Frontend Changes**: 1-2 days
  - Remove token management
  - Add session management
  - Update API calls
  - Handle session expiration

- **Testing**: 1 day
  - Unit tests
  - Integration tests
  - Security testing

**Total**: ~4-6 days

---

## Recommendations

1. **Use Database Sessions** (SQLite for now, PostgreSQL for production)
2. **Implement Gradual Migration** (support both systems initially)
3. **Add Session Monitoring** (log session creation/usage)
4. **Implement Session Cleanup** (cron job to remove expired sessions)
5. **Add Rate Limiting** (prevent session brute force)

---

## Next Steps

1. Review and approve architecture
2. Create implementation plan
3. Start with backend session infrastructure
4. Add session endpoints
5. Update frontend to use sessions
6. Test thoroughly
7. Deploy gradually

