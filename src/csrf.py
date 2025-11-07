"""CSRF protection middleware for FastAPI"""
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from fastapi.responses import JSONResponse, FileResponse
from typing import Optional
import hmac
import hashlib
from .config import Config

class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    """
    CSRF protection middleware.
    
    For state-changing operations (POST, PUT, DELETE, PATCH), validates CSRF token
    from header 'X-CSRF-Token' against session cookie.
    """
    
    # Methods that require CSRF protection
    PROTECTED_METHODS = {"POST", "PUT", "DELETE", "PATCH"}
    
    # Paths that are exempt from CSRF protection
    EXEMPT_PATHS = {
        "/",  # Frontend routes
        "/health",  # Health check
        "/docs",  # API documentation
        "/redoc",  # API documentation
        "/openapi.json",  # OpenAPI schema
        "/auth/session/create",  # Session creation endpoint
    }
    
    def _is_exempt(self, path: str) -> bool:
        """Check if path is exempt from CSRF protection"""
        if path in self.EXEMPT_PATHS:
            return True
        # Exempt static/frontend routes
        if path.startswith("/static/") or path == '/' or path.endswith(('.html', '.js', '.css', '.woff2', '.svg', '.ico', '.png', '.jpg', '.jpeg')):
            return True
        return False
    
    def _generate_csrf_token(self, session_id: str) -> str:
        """Generate CSRF token for a session"""
        if not Config.CSRF_SECRET:
            raise ValueError("CSRF_SECRET is not configured")
        message = f"{session_id}:{Config.CSRF_SECRET}"
        return hmac.new(
            Config.CSRF_SECRET.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def _verify_csrf_token(self, session_id: str, token: str) -> bool:
        """Verify CSRF token against session"""
        if not session_id or not token:
            return False
        try:
            expected_token = self._generate_csrf_token(session_id)
            return hmac.compare_digest(expected_token, token)
        except Exception:
            return False
    
    async def dispatch(self, request: Request, call_next):
        """Process request with CSRF protection"""
        # Get session ID from request cookie (might be old session)
        request_session_id = request.cookies.get("fabricstudio_session")
        
        # Skip CSRF check for exempt paths
        if self._is_exempt(request.url.path):
            response = await call_next(request)
            # Check if response set a new session cookie
            session_id = self._get_session_from_response(response) or request_session_id
            if session_id:
                try:
                    new_token = self._generate_csrf_token(session_id)
                    if hasattr(response, 'headers'):
                        response.headers["X-CSRF-Token"] = new_token
                except Exception:
                    pass  # Skip if CSRF_SECRET not configured
            return response
        
        # Only protect state-changing methods
        if request.method not in self.PROTECTED_METHODS:
            # For GET/HEAD/OPTIONS, just add CSRF token to response if session exists
            response = await call_next(request)
            # Check if response set a new session cookie
            session_id = self._get_session_from_response(response) or request_session_id
            if session_id:
                try:
                    new_token = self._generate_csrf_token(session_id)
                    if hasattr(response, 'headers'):
                        response.headers["X-CSRF-Token"] = new_token
                except Exception:
                    pass  # Skip if CSRF_SECRET not configured
            return response
        
        # For POST/PUT/DELETE/PATCH - validate CSRF token
        if not request_session_id:
            # No session cookie - allow (might be API call with Bearer token or session creation)
            # CSRF protection is primarily for browser-based requests with existing sessions
            response = await call_next(request)
            # If a new session was created, add CSRF token for it
            new_session_id = self._get_session_from_response(response)
            if new_session_id and hasattr(response, 'headers'):
                try:
                    new_token = self._generate_csrf_token(new_session_id)
                    response.headers["X-CSRF-Token"] = new_token
                except Exception:
                    pass
            return response
        
        # Get CSRF token from header
        csrf_token = request.headers.get("X-CSRF-Token")
        if not csrf_token:
            raise HTTPException(
                status_code=403,
                detail="CSRF token missing. Include 'X-CSRF-Token' header."
            )
        
        # Verify CSRF token against request session
        if not self._verify_csrf_token(request_session_id, csrf_token):
            # Log for debugging (remove in production if needed)
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"CSRF token validation failed for session {request_session_id[:8] if request_session_id else 'None'}... (token length: {len(csrf_token) if csrf_token else 0})")
            raise HTTPException(
                status_code=403,
                detail="Invalid CSRF token"
            )
        
        # Process request
        response = await call_next(request)
        
        # Add CSRF token to response headers for subsequent requests
        # Use new session from response if available, otherwise use request session
        session_id = self._get_session_from_response(response) or request_session_id
        if session_id and hasattr(response, 'headers'):
            try:
                new_token = self._generate_csrf_token(session_id)
                response.headers["X-CSRF-Token"] = new_token
            except Exception:
                pass  # Skip if CSRF_SECRET not configured
        
        return response
    
    def _get_session_from_response(self, response) -> Optional[str]:
        """Extract session ID from response Set-Cookie header"""
        if not hasattr(response, 'headers'):
            return None
        
        # FastAPI/Starlette stores cookies in response.headers as "set-cookie"
        # Check Set-Cookie header (case-insensitive)
        set_cookie_header = None
        
        # Try direct access first
        if hasattr(response.headers, 'get'):
            set_cookie_header = response.headers.get("set-cookie") or response.headers.get("Set-Cookie")
        
        # Also check by iterating (headers might be case-insensitive dict)
        if not set_cookie_header:
            for key, value in response.headers.items():
                if key.lower() == "set-cookie":
                    set_cookie_header = value
                    break
        
        # Also check raw_headers if available (Starlette stores cookies there)
        if not set_cookie_header and hasattr(response, 'raw_headers'):
            try:
                for header_name, header_value in response.raw_headers:
                    if isinstance(header_name, bytes):
                        header_name_str = header_name.decode().lower()
                    else:
                        header_name_str = str(header_name).lower()
                    
                    if header_name_str == "set-cookie":
                        if isinstance(header_value, bytes):
                            set_cookie_header = header_value.decode()
                        else:
                            set_cookie_header = str(header_value)
                        break
            except (AttributeError, TypeError):
                pass
        
        if not set_cookie_header:
            return None
        
        # Parse Set-Cookie header to find fabricstudio_session
        # Format: "fabricstudio_session=session_id; HttpOnly; SameSite=lax; Path=/; Max-Age=3600"
        import re
        # Handle multiple cookies - split by comma first (multiple Set-Cookie headers)
        # Then check each cookie string
        cookie_strings = [set_cookie_header] if isinstance(set_cookie_header, str) else []
        if ',' in set_cookie_header:
            cookie_strings = [c.strip() for c in set_cookie_header.split(',')]
        
        for cookie_str in cookie_strings:
            # Look for fabricstudio_session=value
            match = re.search(r'fabricstudio_session=([^;,\s]+)', cookie_str)
            if match:
                return match.group(1)
        
        return None

