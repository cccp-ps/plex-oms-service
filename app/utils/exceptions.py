"""
Custom exception classes for Plex Online Media Sources Manager.

Provides application-specific exceptions for better error handling
and privacy-focused error reporting. Builds upon PlexAPI native exceptions.
Also includes global FastAPI exception handlers for proper HTTP responses.

Exception Hierarchy:
- PlexAPIException: Base for all PlexAPI-related errors
- AuthenticationException: Authentication failures  
- AuthorizationException: Permission/access errors
- ConnectionException: Network/connection issues
- RateLimitException: Rate limiting errors
"""

import logging
import re
from datetime import datetime
from typing import override, Any

from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError


# Configure logger for exception handling
logger = logging.getLogger(__name__)


class PlexAPIException(Exception):
    """
    Base exception for PlexAPI-related errors.
    
    Provides a foundation for all Plex API integration errors with
    privacy-focused error messaging and optional detail preservation.
    """
    
    message: str
    original_error: Exception | None
    
    def __init__(self, message: str, original_error: Exception | None = None) -> None:
        """
        Initialize PlexAPI exception.
        
        Args:
            message: User-friendly error message
            original_error: Original exception that caused this error (for debugging)
        """
        super().__init__(message)
        self.message = message
        self.original_error = original_error
    
    @override
    def __str__(self) -> str:
        """Return user-friendly error message."""
        return self.message


class AuthenticationException(PlexAPIException):
    """
    Exception for authentication-related errors.
    
    Raised when authentication fails due to invalid tokens,
    expired sessions, or other authentication issues.
    """
    
    def __init__(self, message: str = "Authentication failed", original_error: Exception | None = None) -> None:
        """
        Initialize authentication exception.
        
        Args:
            message: Authentication error message
            original_error: Original exception that caused this error
        """
        super().__init__(message, original_error)


class AuthorizationException(PlexAPIException):
    """
    Exception for authorization/permission-related errors.
    
    Raised when user lacks permission to access specific resources
    or perform certain operations.
    """
    
    def __init__(self, message: str = "Access denied", original_error: Exception | None = None) -> None:
        """
        Initialize authorization exception.
        
        Args:
            message: Authorization error message  
            original_error: Original exception that caused this error
        """
        super().__init__(message, original_error)


class ConnectionException(PlexAPIException):
    """
    Exception for network/connection-related errors.
    
    Raised when unable to connect to Plex services due to
    network issues, timeouts, or service unavailability.
    """
    
    def __init__(self, message: str = "Connection failed", original_error: Exception | None = None) -> None:
        """
        Initialize connection exception.
        
        Args:
            message: Connection error message
            original_error: Original exception that caused this error
        """
        super().__init__(message, original_error)


class RateLimitException(PlexAPIException):
    """
    Exception for rate limiting errors.
    
    Raised when API rate limits are exceeded and requests
    are being throttled or rejected.
    """
    
    def __init__(self, message: str = "Rate limit exceeded", original_error: Exception | None = None) -> None:
        """
        Initialize rate limit exception.
        
        Args:
            message: Rate limit error message
            original_error: Original exception that caused this error
        """
        super().__init__(message, original_error)


class ValidationException(PlexAPIException):
    """
    Exception for input validation errors.
    
    Raised when input data fails validation checks before
    making API calls or processing requests.
    """
    
    def __init__(self, message: str = "Validation failed", original_error: Exception | None = None) -> None:
        """
        Initialize validation exception.
        
        Args:
            message: Validation error message
            original_error: Original exception that caused this error
        """
        super().__init__(message, original_error)


def handle_plexapi_error(error: Exception, context: str = "PlexAPI operation") -> PlexAPIException:
    """
    Convert PlexAPI native exceptions to application-specific exceptions.
    
    Maps PlexAPI exceptions to our custom exception hierarchy while
    preserving privacy and providing user-friendly error messages.
    
    Args:
        error: Original PlexAPI exception
        context: Context description for the error
        
    Returns:
        Appropriate custom exception instance
    """
    from plexapi.exceptions import BadRequest, Unauthorized, NotFound  # pyright: ignore[reportMissingTypeStubs]
    
    error_message = str(error)
    
    # Map specific PlexAPI exceptions to our custom ones
    if isinstance(error, Unauthorized):
        if "token" in error_message.lower() or "authentication" in error_message.lower():
            return AuthenticationException(
                f"Authentication failed during {context}",
                original_error=error
            )
        else:
            return AuthorizationException(
                f"Access denied during {context}",
                original_error=error
            )
    
    elif isinstance(error, BadRequest):
        if "connection" in error_message.lower() or "network" in error_message.lower():
            return ConnectionException(
                f"Failed to connect to Plex API during {context}",
                original_error=error
            )
        else:
            return PlexAPIException(
                f"Invalid request during {context}",
                original_error=error
            )
    
    elif isinstance(error, NotFound):
        return PlexAPIException(
            f"Resource not found during {context}",
            original_error=error
        )
    
    # Handle rate limiting (HTTP 429 or rate limit related errors)
    elif "rate" in error_message.lower() or "429" in error_message:
        return RateLimitException(
            f"Rate limit exceeded during {context}",
            original_error=error
        )
    
    # Default to generic PlexAPI exception
    return PlexAPIException(
        f"Unexpected error during {context}: {_sanitize_error_message(str(error))}",
        original_error=error
    )


def _sanitize_error_message(message: str) -> str:
    """
    Sanitize error message to prevent information leakage.
    
    Removes sensitive information like server URLs, tokens, etc.
    
    Args:
        message: Original error message
        
    Returns:
        Sanitized error message safe for client consumption
    """
    # Remove common sensitive patterns
    sanitized = re.sub(
        r'https?://[^\s]+',  # URLs
        '[URL]',
        message,
        flags=re.IGNORECASE
    )
    
    sanitized = re.sub(
        r'token[:\s=]+[\w\-\.]+',  # Tokens  
        'token=[REDACTED]',
        sanitized,
        flags=re.IGNORECASE
    )
    
    sanitized = re.sub(
        r'key[:\s=]+[\w\-\.]+',  # API keys
        'key=[REDACTED]',
        sanitized,
        flags=re.IGNORECASE
    )
    
    # Sanitize password patterns
    sanitized = re.sub(
        r'password[:\s=]+[\w\-\.]+',  # Passwords
        'password=***',
        sanitized,
        flags=re.IGNORECASE
    )
    
    # Sanitize host patterns
    sanitized = re.sub(
        r'host[:\s=]+[\w\-\.]+',  # Host names
        'host=***',
        sanitized,
        flags=re.IGNORECASE
    )
    
    return sanitized


def _create_error_response(
    status_code: int,
    error_message: str,
    request: Request,
    detail: str | None = None,
    extra_data: dict[str, Any] | None = None  # pyright: ignore[reportExplicitAny]
) -> JSONResponse:
    """
    Create standardized error response for FastAPI.
    
    Args:
        status_code: HTTP status code
        error_message: Error message for client
        request: FastAPI request object
        detail: Optional additional detail
        extra_data: Optional extra data to include in response
        
    Returns:
        JSONResponse with standardized error format
    """
    # Sanitize the error message
    sanitized_message = _sanitize_error_message(error_message)
    
    # Build response data
    response_data: dict[str, Any] = {  # pyright: ignore[reportExplicitAny]
        "error": sanitized_message,
        "detail": detail,
        "timestamp": datetime.now().isoformat(),
    }
    
    # Add request ID if available
    request_id = request.headers.get("x-request-id")
    if request_id:
        response_data["request_id"] = request_id
    
    # Add any extra data
    if extra_data:
        response_data.update(extra_data)
    
    return JSONResponse(
        status_code=status_code,
        content=response_data
    )


def _log_exception_securely(
    exception: Exception,
    request: Request,
    handler_name: str
) -> None:
    """
    Log exception details securely without exposing sensitive information.
    
    Args:
        exception: The exception that occurred
        request: FastAPI request object
        handler_name: Name of the exception handler
    """
    # Create log message without sensitive headers
    safe_headers: dict[str, str] = {
        k: str(v) for k, v in request.headers.items()
        if k.lower() not in ["authorization", "x-api-key", "cookie"]
    }
    
    # Get original error details if available
    original_error: Exception | None = getattr(exception, 'original_error', None)
    original_error_type: str = type(original_error).__name__ if original_error else "None"
    
    logger.error(
        "Exception handled by %s: %s at %s %s (headers: %s, original_error: %s)",
        handler_name,
        type(exception).__name__,
        str(request.method),
        str(request.url.path),
        str(safe_headers),
        original_error_type,
    )


async def plexapi_exception_handler(request: Request, exc: PlexAPIException) -> JSONResponse:
    """
    Handle PlexAPIException and its subclasses.
    
    Args:
        request: FastAPI request object
        exc: PlexAPIException instance
        
    Returns:
        JSONResponse with 500 status and user-friendly error message
    """
    _log_exception_securely(exc, request, "plexapi_exception_handler")
    
    return _create_error_response(
        status_code=500,
        error_message=exc.message,
        request=request
    )


async def authentication_exception_handler(request: Request, exc: AuthenticationException) -> JSONResponse:
    """
    Handle AuthenticationException.
    
    Args:
        request: FastAPI request object
        exc: AuthenticationException instance
        
    Returns:
        JSONResponse with 401 status and authentication error message
    """
    _log_exception_securely(exc, request, "authentication_exception_handler")
    
    return _create_error_response(
        status_code=401,
        error_message=exc.message,
        request=request
    )


async def authorization_exception_handler(request: Request, exc: AuthorizationException) -> JSONResponse:
    """
    Handle AuthorizationException.
    
    Args:
        request: FastAPI request object
        exc: AuthorizationException instance
        
    Returns:
        JSONResponse with 403 status and authorization error message
    """
    _log_exception_securely(exc, request, "authorization_exception_handler")
    
    return _create_error_response(
        status_code=403,
        error_message=exc.message,
        request=request
    )


async def validation_exception_handler(request: Request, exc: ValidationException) -> JSONResponse:
    """
    Handle ValidationException.
    
    Args:
        request: FastAPI request object
        exc: ValidationException instance
        
    Returns:
        JSONResponse with 422 status and validation error message
    """
    _log_exception_securely(exc, request, "validation_exception_handler")
    
    return _create_error_response(
        status_code=422,
        error_message=exc.message,
        request=request
    )


async def connection_exception_handler(request: Request, exc: ConnectionException) -> JSONResponse:
    """
    Handle ConnectionException.
    
    Args:
        request: FastAPI request object
        exc: ConnectionException instance
        
    Returns:
        JSONResponse with 503 status and connection error message
    """
    _log_exception_securely(exc, request, "connection_exception_handler")
    
    return _create_error_response(
        status_code=503,
        error_message=exc.message,
        request=request
    )


async def rate_limit_exception_handler(request: Request, exc: RateLimitException) -> JSONResponse:
    """
    Handle RateLimitException.
    
    Args:
        request: FastAPI request object
        exc: RateLimitException instance
        
    Returns:
        JSONResponse with 429 status and rate limit error message
    """
    _log_exception_securely(exc, request, "rate_limit_exception_handler")
    
    return _create_error_response(
        status_code=429,
        error_message=exc.message,
        request=request,
        extra_data={"retry_after": 60}  # Default retry after 60 seconds
    )


async def pydantic_validation_exception_handler(request: Request, exc: ValidationError) -> JSONResponse:
    """
    Handle Pydantic ValidationError.
    
    Args:
        request: FastAPI request object
        exc: Pydantic ValidationError instance
        
    Returns:
        JSONResponse with 422 status and formatted validation errors
    """
    _log_exception_securely(exc, request, "pydantic_validation_exception_handler")
    
    # Format validation errors for client consumption
    validation_errors: list[dict[str, str]] = []
    for error in exc.errors():
        validation_errors.append({
            "field": ".".join(str(loc) for loc in error["loc"]),
            "message": error["msg"],
            "type": error["type"]
        })
    
    return _create_error_response(
        status_code=422,
        error_message="Validation failed",
        request=request,
        extra_data={"validation_errors": validation_errors}
    ) 