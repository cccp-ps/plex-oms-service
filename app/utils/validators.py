"""
OAuth and request validation utilities for Plex Online Media Sources Manager.

Provides secure validation functions for OAuth state parameters, Plex token formats,
redirect URIs, and callback parameter sanitization.

Features:
- OAuth state parameter validation with CSRF protection
- Plex authentication token format validation
- Redirect URI validation with security checks
- Callback parameter sanitization against XSS and injection attacks
"""

import re
import html
from urllib.parse import urlparse

from app.utils.exceptions import ValidationException

# Re-export ValidationException for convenience
ValidationError = ValidationException


def validate_oauth_state(state: object) -> bool:
    """
    Validate OAuth state parameter for CSRF protection.
    
    Ensures state parameters meet security requirements:
    - At least 32 characters for sufficient entropy
    - Contains only URL-safe characters
    - Not empty or whitespace-only
    - Free from injection attack patterns
    
    Args:
        state: State parameter to validate
        
    Returns:
        True if state is valid
        
    Raises:
        ValidationError: If state parameter is invalid or insecure
    """
    # Check if state is string
    if not isinstance(state, str):
        raise ValidationError("State parameter cannot be empty")
    
    # Strip whitespace and check if empty
    state_stripped = state.strip()
    if not state_stripped:
        raise ValidationError("State parameter cannot be empty")
    
    # Check for URL-safe characters first (catches injection attempts)
    url_safe_pattern = re.compile(r'^[A-Za-z0-9_-]+$')
    if not url_safe_pattern.match(state_stripped):
        raise ValidationError("State parameter contains invalid characters")
    
    # Check minimum length for security (after character validation)
    if len(state_stripped) < 32:
        raise ValidationError("State parameter must be at least 32 characters")
    
    return True


def validate_plex_token_format(token: object) -> bool:
    """
    Validate Plex authentication token format.
    
    Ensures tokens meet expected Plex token requirements:
    - At least 20 characters for typical Plex tokens
    - Contains only alphanumeric characters
    - Not excessively long (max 200 characters)
    - Not empty or None
    
    Args:
        token: Plex token to validate
        
    Returns:
        True if token format is valid
        
    Raises:
        ValidationError: If token format is invalid
    """
    # Check if token is string
    if not isinstance(token, str):
        raise ValidationError("Plex token cannot be empty")
    
    # Strip whitespace and check if empty
    token_stripped = token.strip()
    if not token_stripped:
        raise ValidationError("Plex token cannot be empty")
    
    # Check minimum length
    if len(token_stripped) < 20:
        raise ValidationError("Plex token must be at least 20 characters")
    
    # Check maximum length to prevent abuse
    if len(token_stripped) > 200:
        raise ValidationError("Plex token is too long")
    
    # Check for alphanumeric characters only
    alphanumeric_pattern = re.compile(r'^[A-Za-z0-9]+$')
    if not alphanumeric_pattern.match(token_stripped):
        raise ValidationError("Plex token contains invalid characters")
    
    return True


def validate_redirect_uri(uri: object) -> bool:
    """
    Validate OAuth redirect URI for security.
    
    Ensures redirect URIs meet security requirements:
    - Uses HTTP or HTTPS scheme only
    - HTTP only allowed for localhost
    - No fragments for security
    - No embedded credentials
    - Well-formed URI structure
    
    Args:
        uri: Redirect URI to validate
        
    Returns:
        True if URI is valid and secure
        
    Raises:
        ValidationError: If URI is invalid or insecure
    """
    # Check if URI is string
    if not isinstance(uri, str):
        raise ValidationError("Redirect URI cannot be empty")
    
    # Strip whitespace and check if empty
    uri_stripped = uri.strip()
    if not uri_stripped:
        raise ValidationError("Redirect URI cannot be empty")
    
    try:
        # Parse URI
        parsed = urlparse(uri_stripped)
        
        # Check if this looks like a malformed URI (no scheme and no obvious structure)
        if not parsed.scheme and not parsed.netloc and '://' not in uri_stripped:
            raise ValidationError("Invalid redirect URI format")
            
    except Exception:
        raise ValidationError("Invalid redirect URI format")
    
    # Check scheme
    if parsed.scheme not in ('http', 'https'):
        raise ValidationError("Redirect URI must use HTTP or HTTPS scheme")
    
    # For HTTP, only allow localhost
    if parsed.scheme == 'http':
        if parsed.hostname not in ('localhost', '127.0.0.1', '::1'):
            raise ValidationError("HTTP redirect URIs are only allowed for localhost")
    
    # Check for fragments (security risk)
    if parsed.fragment:
        raise ValidationError("Redirect URI cannot contain fragments")
    
    # Check for embedded credentials (security risk)
    if parsed.username or parsed.password:
        raise ValidationError("Redirect URI cannot contain credentials")
    
    # Ensure hostname exists
    if not parsed.hostname:
        raise ValidationError("Invalid redirect URI format")
    
    return True


def sanitize_callback_parameters(params: object) -> dict[str, str]:
    """
    Sanitize OAuth callback parameters against injection attacks.
    
    Removes dangerous content from callback parameters:
    - XSS attack patterns
    - SQL injection attempts
    - Script injection patterns
    - Excessively long values
    - Non-string parameters
    
    Args:
        params: Parameter dictionary to sanitize
        
    Returns:
        Dictionary with sanitized parameters
    """
    # Handle None input
    if params is None:
        return {}
    
    # Ensure params is a dictionary
    if not isinstance(params, dict):
        return {}
    
    sanitized: dict[str, str] = {}
    
    # Maximum length for parameter values
    MAX_PARAM_LENGTH = 1000
    
    # Dangerous patterns to remove completely
    dangerous_patterns = [
        r'data:',
        r'javascript:',
        r'vbscript:',
        r'file://',
        r'<script[^>]*>',
        r'</script>',
        r'<img[^>]*onerror',
        r'on\w+\s*=',
        r'expression\s*\(',
    ]
    
    # SQL injection patterns to remove
    sql_patterns = [
        r'union\s+select',
        r'drop\s+table',
        r'delete\s+from',
        r'insert\s+into',
        r'update\s+set',
        r';\s*--',
        r'/\*.*?\*/',
    ]
    
    for key, value in params.items():  # pyright: ignore[reportUnknownVariableType]
        # Skip None values
        if value is None:
            continue
        
        # Only process string values
        if not isinstance(value, str):
            continue
        
        # Strip whitespace
        value_stripped = value.strip()
        if not value_stripped:
            continue
        
        # Truncate excessively long values
        if len(value_stripped) > MAX_PARAM_LENGTH:
            value_stripped = value_stripped[:MAX_PARAM_LENGTH]
        
        # Remove dangerous patterns (case-insensitive)
        for pattern in dangerous_patterns:
            value_stripped = re.sub(pattern, '', value_stripped, flags=re.IGNORECASE)
        
        # Remove SQL injection patterns (case-insensitive)
        for pattern in sql_patterns:
            value_stripped = re.sub(pattern, '', value_stripped, flags=re.IGNORECASE)
        
        # HTML escape remaining content
        value_stripped = html.escape(value_stripped, quote=True)
        
        # Only include if there's still content after sanitization
        if value_stripped:
            sanitized[key] = value_stripped
    
    return sanitized 