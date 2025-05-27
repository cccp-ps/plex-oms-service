"""
Security middleware for FastAPI application.

Provides CSRF protection, rate limiting, and security headers middleware
for the Plex Online Media Sources Manager with OAuth and API protection.
"""

import hashlib
import hmac
import secrets
import time
from collections.abc import Awaitable
from typing import Callable, override

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.types import ASGIApp

from app.config import get_settings


class CSRFTokenValidator:
    """
    CSRF token validator with secure token generation and validation.
    
    Provides cryptographically secure CSRF token generation with HMAC-based
    validation and expiration handling. Can be integrated with OAuth state
    parameters for unified security.
    """
    
    def __init__(self, secret_key: str, token_ttl: int = 3600) -> None:
        """
        Initialize CSRF token validator.
        
        Args:
            secret_key: Secret key for HMAC signature generation
            token_ttl: Token time-to-live in seconds (default: 1 hour)
        """
        self.secret_key: bytes = secret_key.encode('utf-8')
        self.token_ttl: int = token_ttl
    
    def generate_token(self) -> str:
        """
        Generate a secure CSRF token.
        
        Creates a token in format: timestamp.random_value.signature
        where signature is HMAC(secret_key, timestamp.random_value)
        
        Returns:
            Secure CSRF token string
        """
        # Current timestamp for expiration tracking
        timestamp = str(int(time.time()))
        
        # Generate cryptographically secure random value
        random_value = secrets.token_urlsafe(24)
        
        # Create token payload (timestamp.random_value)
        token_payload = f"{timestamp}.{random_value}"
        
        # Generate HMAC signature
        signature = hmac.new(
            self.secret_key,
            token_payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        # Return complete token: timestamp.random_value.signature
        return f"{token_payload}.{signature}"
    
    def validate_token(self, token: object) -> bool:
        """
        Validate a CSRF token.
        
        Checks token format, signature, and expiration.
        
        Args:
            token: Token to validate
            
        Returns:
            True if token is valid, False otherwise
        """
        if not isinstance(token, str):
            return False
        
        if not token or not token.strip():
            return False
        
        # Split token into components
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        timestamp_str, random_value, provided_signature = parts
        
        # Validate timestamp format
        try:
            timestamp = int(timestamp_str)
        except ValueError:
            return False
        
        # Check token expiration
        current_time = int(time.time())
        if current_time - timestamp > self.token_ttl:
            return False
        
        # Regenerate signature for comparison
        token_payload = f"{timestamp_str}.{random_value}"
        expected_signature = hmac.new(
            self.secret_key,
            token_payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        # Use secure comparison to prevent timing attacks
        return hmac.compare_digest(expected_signature, provided_signature)
    
    def validate_oauth_state(self, state: object) -> bool:
        """
        Validate OAuth state parameter using CSRF token validation.
        
        This allows CSRF tokens to be used as OAuth state parameters
        for unified security across authentication flows.
        
        Args:
            state: OAuth state parameter to validate
            
        Returns:
            True if state is valid, False otherwise
        """
        return self.validate_token(state)
    
    async def async_validate_token(self, token: object) -> bool:
        """
        Async version of token validation for middleware use.
        
        Args:
            token: Token to validate
            
        Returns:
            True if token is valid, False otherwise
        """
        # Token validation is CPU-bound, not I/O-bound, so we don't need
        # to use asyncio.to_thread() for this operation
        return self.validate_token(token)


class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    """
    CSRF protection middleware for FastAPI/Starlette applications.
    
    Validates CSRF tokens for state-changing HTTP methods (POST, PUT, PATCH, DELETE)
    while allowing safe methods (GET, HEAD, OPTIONS) and excluded paths to pass through.
    """
    
    # HTTP methods that require CSRF protection
    PROTECTED_METHODS: set[str] = {"POST", "PUT", "PATCH", "DELETE"}
    
    # Safe HTTP methods that don't require CSRF protection
    SAFE_METHODS: set[str] = {"GET", "HEAD", "OPTIONS"}
    
    def __init__(
        self,
        app: ASGIApp,
        secret_key: str | None = None,
        excluded_paths: list[str] | None = None,
        token_header: str = "X-CSRF-Token",
        token_ttl: int = 3600
    ) -> None:
        """
        Initialize CSRF protection middleware.
        
        Args:
            app: ASGI application
            secret_key: Secret key for token generation (uses config if None)
            excluded_paths: List of paths to exclude from CSRF protection
            token_header: Header name for CSRF token (default: X-CSRF-Token)
            token_ttl: Token time-to-live in seconds
        """
        super().__init__(app)
        
        # Use provided secret key or get from settings
        if secret_key is None:
            settings = get_settings()
            secret_key = settings.secret_key.get_secret_value()
        
        self.csrf_validator: CSRFTokenValidator = CSRFTokenValidator(secret_key, token_ttl)
        self.excluded_paths: list[str] = excluded_paths or []
        self.token_header: str = token_header
    
    @override
    async def dispatch(
        self, 
        request: Request, 
        call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """
        Process request through CSRF protection middleware.
        
        Args:
            request: Incoming request
            call_next: Next middleware/handler in chain
            
        Returns:
            Response or CSRF validation error
        """
        # Skip CSRF protection for safe HTTP methods
        if request.method in self.SAFE_METHODS:
            return await call_next(request)
        
        # Skip CSRF protection for excluded paths
        if self._is_path_excluded(request.url.path):
            return await call_next(request)
        
        # Only protected methods (POST, PUT, PATCH, DELETE) need CSRF validation
        if request.method not in self.PROTECTED_METHODS:
            return await call_next(request)
        
        # Get CSRF token from headers
        csrf_token = request.headers.get(self.token_header)
        
        # Check if CSRF token is present
        if not csrf_token:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Forbidden",
                    "detail": "CSRF token required for this operation"
                }
            )
        
        # Validate CSRF token
        is_valid = await self.csrf_validator.async_validate_token(csrf_token)
        if not is_valid:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Forbidden", 
                    "detail": "Invalid CSRF token"
                }
            )
        
        # CSRF token is valid, proceed with request
        return await call_next(request)
    
    def _is_path_excluded(self, path: str) -> bool:
        """
        Check if request path is excluded from CSRF protection.
        
        Args:
            path: Request path to check
            
        Returns:
            True if path is excluded, False otherwise
        """
        for excluded_path in self.excluded_paths:
            if path.startswith(excluded_path):
                return True
        return False 