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
            
        except Exception as e:
            # Rate limit exceeded, return error response
            if isinstance(e, RateLimitExceeded) or e.__class__.__name__ == "CustomRateLimitExceeded":
                return self._create_rate_limit_response(e)
            else:
                raise  # Re-raise non-rate-limit exceptions
    
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
            if not self._rate_limiter.test(rate_limit_obj, full_key):
                # Rate limit exceeded
                _ = self._calculate_retry_after(rate_limit)  # Store in _ to avoid unused warning
                # Create our own rate limit exception to avoid type issues
                class CustomRateLimitExceeded(Exception):
                    rate_limit: str
                    
                    def __init__(self, message: str, rate_limit: str) -> None:
                        super().__init__(message)
                        self.rate_limit = rate_limit
                
                raise CustomRateLimitExceeded(f"Rate limit exceeded: {rate_limit}", rate_limit)
            
            # Hit the rate limit (consume one request)
            _ = self._rate_limiter.hit(rate_limit_obj, full_key)
        except Exception as e:
            # If rate limiting fails for any reason, log and continue
            # In production, you might want to handle this differently
            if isinstance(e, RateLimitExceeded) or e.__class__.__name__ == "CustomRateLimitExceeded":
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
    
    def _create_rate_limit_response(self, exception: Exception) -> JSONResponse:
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


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Security headers middleware for FastAPI/Starlette applications.
    
    Provides comprehensive security headers including HSTS, CSP, CORS,
    secure cookie attributes, and server information sanitization.
    """
    
    def __init__(
        self,
        app: ASGIApp,
        include_hsts: bool = True,
        include_csp: bool = True,
        include_security_headers: bool = True,
        hsts_max_age: int = 31536000,  # 1 year
        hsts_include_subdomains: bool = True,
        hsts_preload: bool = True,
        csp_policy: str | None = None,
        cors_allowed_origins: list[str] | None = None,
        cors_allowed_methods: list[str] | None = None,
        cors_allowed_headers: list[str] | None = None,
        cors_allow_credentials: bool = False,
        cors_max_age: int = 86400,  # 24 hours
        custom_server_header: str | None = None,
        secure_cookies: bool = True
    ) -> None:
        """
        Initialize security headers middleware.
        
        Args:
            app: ASGI application
            include_hsts: Whether to include HSTS header
            include_csp: Whether to include Content Security Policy
            include_security_headers: Whether to include general security headers
            hsts_max_age: HSTS max-age in seconds
            hsts_include_subdomains: Include subdomains in HSTS
            hsts_preload: Include preload directive in HSTS
            csp_policy: Custom CSP policy (uses default if None)
            cors_allowed_origins: List of allowed CORS origins
            cors_allowed_methods: List of allowed CORS methods
            cors_allowed_headers: List of allowed CORS headers
            cors_allow_credentials: Allow credentials in CORS
            cors_max_age: CORS preflight cache max-age
            custom_server_header: Custom server header value
            secure_cookies: Whether to secure cookie attributes
        """
        super().__init__(app)
        
        self.include_hsts: bool = include_hsts
        self.include_csp: bool = include_csp
        self.include_security_headers: bool = include_security_headers
        self.hsts_max_age: int = hsts_max_age
        self.hsts_include_subdomains: bool = hsts_include_subdomains
        self.hsts_preload: bool = hsts_preload
        self.cors_allowed_origins: list[str] = cors_allowed_origins or []
        self.cors_allowed_methods: list[str] = cors_allowed_methods or ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
        self.cors_allowed_headers: list[str] = cors_allowed_headers or ["Content-Type", "Authorization", "X-CSRF-Token"]
        self.cors_allow_credentials: bool = cors_allow_credentials
        self.cors_max_age: int = cors_max_age
        self.custom_server_header: str | None = custom_server_header
        self.secure_cookies: bool = secure_cookies
        
        # Default CSP policy if none provided
        self.csp_policy: str = csp_policy or self._get_default_csp_policy()
    
    def _get_default_csp_policy(self) -> str:
        """
        Get default Content Security Policy.
        
        Returns:
            Default CSP policy string
        """
        return (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
    
    @override
    async def dispatch(
        self, 
        request: Request, 
        call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """
        Process request through security headers middleware.
        
        Args:
            request: Incoming request
            call_next: Next middleware/handler in chain
            
        Returns:
            Response with security headers applied
        """
        # Handle CORS preflight requests
        if request.method == "OPTIONS" and self._is_cors_preflight(request):
            return self._handle_cors_preflight(request)
        
        # Process request through next middleware/handler
        response = await call_next(request)
        
        # Apply security headers
        self._apply_security_headers(response)
        
        # Apply CORS headers for actual requests
        self._apply_cors_headers(request, response)
        
        # Secure cookies
        if self.secure_cookies:
            self._secure_cookies(response)
        
        # Sanitize server information
        self._sanitize_server_headers(response)
        
        return response
    
    def _is_cors_preflight(self, request: Request) -> bool:
        """
        Check if request is a CORS preflight request.
        
        Args:
            request: Incoming request
            
        Returns:
            True if preflight request, False otherwise
        """
        return (
            request.method == "OPTIONS" and
            "Origin" in request.headers and
            "Access-Control-Request-Method" in request.headers
        )
    
    def _handle_cors_preflight(self, request: Request) -> Response:
        """
        Handle CORS preflight request.
        
        Args:
            request: CORS preflight request
            
        Returns:
            CORS preflight response
        """
        origin = request.headers.get("Origin")
        
        # Check if origin is allowed
        if not self._is_origin_allowed(origin):
            return Response(status_code=403)
        
        # Create preflight response
        response = Response(status_code=200)
        
        # Set CORS preflight headers
        if origin is not None:  # Type guard for mypy
            response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Methods"] = ", ".join(self.cors_allowed_methods)
        response.headers["Access-Control-Allow-Headers"] = ", ".join(self.cors_allowed_headers)
        response.headers["Access-Control-Max-Age"] = str(self.cors_max_age)
        
        if self.cors_allow_credentials:
            response.headers["Access-Control-Allow-Credentials"] = "true"
        
        return response
    
    def _is_origin_allowed(self, origin: str | None) -> bool:
        """
        Check if origin is allowed for CORS.
        
        Args:
            origin: Origin header value
            
        Returns:
            True if origin is allowed, False otherwise
        """
        if not origin or not self.cors_allowed_origins:
            return False
        
        return origin in self.cors_allowed_origins
    
    def _apply_security_headers(self, response: Response) -> None:
        """
        Apply general security headers to response.
        
        Args:
            response: Response to modify
        """
        if not self.include_security_headers:
            return
        
        # X-Content-Type-Options
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # X-Frame-Options
        response.headers["X-Frame-Options"] = "DENY"
        
        # X-XSS-Protection (legacy header for older browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer-Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Permissions-Policy (replaces Feature-Policy)
        permissions_policy = (
            "camera=(), microphone=(), geolocation=(), "
            "interest-cohort=(), browsing-topics=()"
        )
        response.headers["Permissions-Policy"] = permissions_policy
        
        # Apply HSTS if enabled
        if self.include_hsts:
            hsts_value = f"max-age={self.hsts_max_age}"
            if self.hsts_include_subdomains:
                hsts_value += "; includeSubDomains"
            if self.hsts_preload:
                hsts_value += "; preload"
            response.headers["Strict-Transport-Security"] = hsts_value
        
        # Apply CSP if enabled
        if self.include_csp and self.csp_policy:
            response.headers["Content-Security-Policy"] = self.csp_policy
    
    def _apply_cors_headers(self, request: Request, response: Response) -> None:
        """
        Apply CORS headers to response for actual requests.
        
        Args:
            request: Incoming request
            response: Response to modify
        """
        origin = request.headers.get("Origin")
        
        if not self._is_origin_allowed(origin):
            return
        
        # Set CORS headers
        if origin is not None:  # Type guard for mypy
            response.headers["Access-Control-Allow-Origin"] = origin
        
        if self.cors_allow_credentials:
            response.headers["Access-Control-Allow-Credentials"] = "true"
        
        # Expose headers that client can access
        response.headers["Access-Control-Expose-Headers"] = "Content-Length, Content-Type"
    
    def _secure_cookies(self, response: Response) -> None:
        """
        Add secure attributes to cookies.
        
        Args:
            response: Response to modify
        """
        if not hasattr(response, 'headers'):
            return
        
        # Get all Set-Cookie headers using proper Starlette method
        set_cookie_headers: list[str] = []
        for name, value in response.headers.items():
            if name.lower() == "set-cookie":
                set_cookie_headers.append(value)
        
        if not set_cookie_headers:
            return
        
        # Remove existing Set-Cookie headers
        try:
            del response.headers["set-cookie"]
        except KeyError:
            pass
        
        # Re-add with secure attributes
        for cookie_header in set_cookie_headers:
            secured_cookie = self._add_secure_cookie_attributes(cookie_header)
            response.headers.append("Set-Cookie", secured_cookie)
    
    def _add_secure_cookie_attributes(self, cookie_header: str) -> str:
        """
        Add secure attributes to a cookie header.
        
        Args:
            cookie_header: Original cookie header
            
        Returns:
            Cookie header with secure attributes
        """
        # Don't modify if already has security attributes
        if "Secure" in cookie_header and "HttpOnly" in cookie_header and "SameSite" in cookie_header:
            return cookie_header
        
        parts = [cookie_header.rstrip(";")]
        
        # Add HttpOnly if not present
        if "HttpOnly" not in cookie_header:
            parts.append("HttpOnly")
        
        # Add Secure if not present (only for HTTPS)
        if "Secure" not in cookie_header:
            parts.append("Secure")
        
        # Add SameSite if not present
        if "SameSite" not in cookie_header:
            parts.append("SameSite=Strict")
        
        return "; ".join(parts)
    
    def _sanitize_server_headers(self, response: Response) -> None:
        """
        Sanitize server information headers.
        
        Args:
            response: Response to modify
        """
        # Remove or replace sensitive headers
        try:
            del response.headers["x-powered-by"]
        except KeyError:
            pass
        
        # Set custom server header or default
        if self.custom_server_header:
            response.headers["Server"] = self.custom_server_header
        else:
            response.headers["Server"] = "PlexOMS" 