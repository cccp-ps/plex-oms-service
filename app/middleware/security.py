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

from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from limits import parse_many
from limits.storage import MemoryStorage
from limits.strategies import FixedWindowRateLimiter
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


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware using slowapi for per-IP rate limiting.
    
    Provides configurable rate limiting for different endpoints with
    proper error responses and time window reset functionality.
    """
    
    def __init__(
        self,
        app: ASGIApp,
        default_rate_limit: str = "100/minute",
        endpoint_limits: dict[str, str] | None = None,
        enabled: bool | None = None
    ) -> None:
        """
        Initialize rate limiting middleware.
        
        Args:
            app: ASGI application
            default_rate_limit: Default rate limit string (e.g., "10/minute")
            endpoint_limits: Dict mapping endpoint paths to rate limit strings
            enabled: Whether rate limiting is enabled (uses config if None)
        """
        super().__init__(app)
        
        # Use provided enabled setting or get from configuration
        if enabled is None:
            settings = get_settings()
            enabled = settings.rate_limit_enabled
        
        self.enabled: bool = enabled
        self.default_rate_limit: str = default_rate_limit
        self.endpoint_limits: dict[str, str] = endpoint_limits or {}
        
        # Initialize slowapi limiter with per-IP key function  
        # For now, we'll create a simple limiter without default limits
        # and handle rate limiting manually in the middleware
        self.limiter: Limiter = Limiter(key_func=get_remote_address)
        
        # Initialize storage for rate limiting
        self._storage: MemoryStorage = MemoryStorage()
        self._rate_limiter: FixedWindowRateLimiter = FixedWindowRateLimiter(self._storage)
    
    @override
    async def dispatch(
        self, 
        request: Request, 
        call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """
        Process request through rate limiting middleware.
        
        Args:
            request: Incoming request
            call_next: Next middleware/handler in chain
            
        Returns:
            Response or rate limit error response
        """
        # Skip rate limiting if disabled
        if not self.enabled:
            return await call_next(request)
        
        # Get the request path
        path = request.url.path
        
        # Determine rate limit for this endpoint
        rate_limit = self._get_rate_limit_for_path(path)
        if not rate_limit:
            # No rate limit for this path
            return await call_next(request)
        
        try:
            # Check rate limit using slowapi-compatible approach
            await self._check_rate_limit(request, rate_limit)
            
            # Rate limit not exceeded, proceed with request
            return await call_next(request)
            
        except RateLimitExceeded as e:
            # Rate limit exceeded, return error response
            return self._create_rate_limit_response(e)
    
    def _get_rate_limit_for_path(self, path: str) -> str | None:
        """
        Get the rate limit string for a given path.
        
        Args:
            path: Request path
            
        Returns:
            Rate limit string or None if no limit applies
        """
        # Check for exact path match in endpoint_limits
        if path in self.endpoint_limits:
            return self.endpoint_limits[path]
        
        # Check for prefix matches in endpoint_limits
        for endpoint_path, limit in self.endpoint_limits.items():
            if path.startswith(endpoint_path):
                return limit
        
        # Return default rate limit
        return self.default_rate_limit
    
    async def _check_rate_limit(self, request: Request, rate_limit: str) -> None:
        """
        Check rate limit for the request using slowapi-compatible approach.
        
        Args:
            request: The incoming request
            rate_limit: Rate limit string to apply
            
        Raises:
            RateLimitExceeded: If rate limit is exceeded
        """
        # Simple rate limit checking implementation
        # This is a basic implementation that can be enhanced
        
        # Parse the rate limit string
        try:
            rate_limits = parse_many(rate_limit)
            if not rate_limits:
                return
                
            rate_limit_obj = rate_limits[0]
        except Exception:
            # If parsing fails, skip rate limiting for this request
            return
        
        # Get client identifier
        client_key = get_remote_address(request)
        if not client_key:
            client_key = "unknown"
        
        # Create a unique key for this endpoint and client
        endpoint_key = f"{request.url.path}:{request.method}"
        full_key = f"{client_key}:{endpoint_key}"
        
        # Check the rate limit using the initialized rate limiter
        try:
            if not self._rate_limiter.test(rate_limit_obj, full_key):  # pyright: ignore[reportArgumentType]
                # Rate limit exceeded
                _ = self._calculate_retry_after(rate_limit)  # Store in _ to avoid unused warning
                raise RateLimitExceeded(f"Rate limit exceeded: {rate_limit}")
            
            # Hit the rate limit (consume one request)
            _ = self._rate_limiter.hit(rate_limit_obj, full_key)  # pyright: ignore[reportArgumentType]
        except Exception as e:
            # If rate limiting fails for any reason, log and continue
            # In production, you might want to handle this differently
            if isinstance(e, RateLimitExceeded):
                raise  # Re-raise rate limit exceeded
            # For other exceptions, allow the request to proceed
    
    def _calculate_retry_after(self, rate_limit: str) -> int:
        """
        Calculate retry-after time based on rate limit string.
        
        Args:
            rate_limit: Rate limit string (e.g., "10/minute")
            
        Returns:
            Retry-after time in seconds
        """
        try:
            # Parse rate limit to get time period
            parts = rate_limit.split("/")
            if len(parts) == 2:
                period = parts[1].strip()
                return self._convert_period_to_seconds(period)
        except Exception:
            pass
        
        # Default to 60 seconds
        return 60
    
    def _convert_period_to_seconds(self, period: str) -> int:
        """
        Convert period string to seconds.
        
        Args:
            period: Period string (e.g., "minute", "hour", "day", "second")
            
        Returns:
            Number of seconds in the period
        """
        period_map = {
            "second": 1,
            "minute": 60,
            "hour": 3600,
            "day": 86400
        }
        
        # Handle plural forms
        if period.endswith("s"):
            period = period[:-1]
        
        if period not in period_map:
            return 60  # Default to 60 seconds if unknown
        
        return period_map[period]
    
    def _create_rate_limit_response(self, exception: RateLimitExceeded) -> JSONResponse:
        """
        Create a JSON response for rate limit exceeded.
        
        Args:
            exception: The RateLimitExceeded exception
            
        Returns:
            JSON response with error details and retry-after header
        """
        # Calculate retry-after time
        retry_after = 60  # Default retry after
        
        # Try to extract rate limit info from exception message
        exc_str = str(exception)
        if ":" in exc_str:
            try:
                rate_limit_part = exc_str.split(":")[1].strip()
                retry_after = self._calculate_retry_after(rate_limit_part)
            except Exception:
                pass
        
        response = JSONResponse(
            status_code=429,
            content={
                "error": "Too Many Requests",
                "detail": f"Rate limit exceeded. {str(exception)}"
            }
        )
        
        # Add Retry-After header
        response.headers["Retry-After"] = str(retry_after)
        
        return response 