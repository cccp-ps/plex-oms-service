"""
Custom exception classes for Plex Online Media Sources Manager.

Provides application-specific exceptions for better error handling
and privacy-focused error reporting. Builds upon PlexAPI native exceptions.

Exception Hierarchy:
- PlexAPIException: Base for all PlexAPI-related errors
- AuthenticationException: Authentication failures  
- AuthorizationException: Permission/access errors
- ConnectionException: Network/connection issues
- RateLimitException: Rate limiting errors
"""

from typing import override


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
    
    else:
        # Handle any other unexpected errors
        return PlexAPIException(
            f"Unexpected error during {context}: {error_message}",
            original_error=error
        ) 