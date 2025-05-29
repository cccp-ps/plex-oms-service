"""
Authentication routes for OAuth flow.

Provides endpoints for Plex OAuth authentication including:
- OAuth initiation with MyPlexPinLogin(oauth=True)
- OAuth callback handling
- Session management (status, logout)

Following security best practices with proper error handling and rate limiting.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from plexapi.exceptions import BadRequest, Unauthorized  # pyright: ignore[reportMissingTypeStubs]

from app.config import Settings, get_settings
from app.models.plex_models import PlexUser
from app.schemas.auth_schemas import (
    OAuthInitiationRequest,
    OAuthInitiationResponse,
    OAuthCallbackRequest,
    OAuthCallbackResponse,
    AuthStatusResponse,
    LogoutResponse
)
from app.services.auth_service import PlexAuthService


# Create router for authentication endpoints
router = APIRouter(prefix="/auth", tags=["authentication"])

# Session cookie settings
SESSION_COOKIE_NAME = "plex_session_token"
SESSION_COOKIE_MAX_AGE = 3600  # 1 hour


def get_token_from_request(request: Request) -> str | None:
    """Extract authentication token from request cookies."""
    return request.cookies.get(SESSION_COOKIE_NAME)


def set_session_cookie(response: Response, token: str) -> None:
    """Set secure HTTP-only session cookie."""
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=SESSION_COOKIE_MAX_AGE,
        httponly=True,
        secure=True,  # Ensure HTTPS in production
        samesite="lax"
    )


def clear_session_cookie(response: Response) -> None:
    """Clear session cookie by setting it to expire."""
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value="",
        max_age=0,
        httponly=True,
        secure=True,
        samesite="lax",
        expires="Thu, 01 Jan 1970 00:00:00 GMT"
    )


@router.post(
    "/login",
    response_model=OAuthInitiationResponse,
    status_code=status.HTTP_200_OK,
    summary="Initiate OAuth flow",
    description="Start OAuth authentication flow with Plex using MyPlexPinLogin(oauth=True) for direct login"
)
async def initiate_oauth_flow(
    request: OAuthInitiationRequest,
    settings: Settings = Depends(get_settings)  # pyright: ignore[reportCallInDefaultInitializer]
) -> OAuthInitiationResponse:
    """
    Initiate OAuth flow using MyPlexPinLogin(oauth=True) for direct Plex account login.
    
    Creates a new OAuth flow with secure state parameter generation for CSRF protection.
    Always uses oauth=True for better user experience with direct Plex account login.
    
    Args:
        request: OAuth initiation request with optional forward_url
        settings: Application settings dependency
        
    Returns:
        OAuth initiation response with oauth_url, state, and code
        
    Raises:
        HTTPException 503: When PlexAPI connection fails
        HTTPException 401: When authentication credentials are invalid  
        HTTPException 500: For unexpected server errors
    """
    try:
        # Initialize PlexAuthService
        auth_service = PlexAuthService(settings)
        
        # Convert forward_url to string if provided
        forward_url = str(request.forward_url) if request.forward_url else None
        
        # Initiate OAuth flow with PlexAPI
        oauth_data = auth_service.initiate_oauth_flow(forward_url=forward_url)
        
        # Return structured response
        return OAuthInitiationResponse(
            oauth_url=oauth_data["oauth_url"],
            state=oauth_data["state"],
            code=oauth_data["code"]
        )
        
    except Unauthorized as e:
        # Handle authentication credential errors first (Unauthorized is subclass of BadRequest)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Plex authentication failed: {str(e)}"
        ) from e
        
    except BadRequest as e:
        # Handle other PlexAPI connection errors
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Unable to connect to Plex servers: {str(e)}"
        ) from e
        
    except Exception as e:
        # Handle unexpected errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during OAuth initiation"
        ) from e


@router.post(
    "/callback",
    response_model=OAuthCallbackResponse,
    status_code=status.HTTP_200_OK,
    summary="Complete OAuth flow",
    description="Complete OAuth authentication flow with authorization code and state validation"
)
async def complete_oauth_flow(
    request: OAuthCallbackRequest,
    response: Response,
    settings: Settings = Depends(get_settings)  # pyright: ignore[reportCallInDefaultInitializer]
) -> OAuthCallbackResponse:
    """
    Complete OAuth flow with authorization code and state validation.
    
    Validates the state parameter for CSRF protection, waits for OAuth completion,
    and retrieves the authenticated MyPlexAccount with user information.
    Sets secure HTTP-only session cookie for session management.
    
    Args:
        request: OAuth callback request with code and state
        response: HTTP response object for setting cookies
        settings: Application settings dependency
        
    Returns:
        OAuth callback response with access_token, user info, and session data
        
    Raises:
        HTTPException 401: When state is invalid, expired, or OAuth fails
        HTTPException 503: When PlexAPI connection fails
        HTTPException 500: For unexpected server errors
    """
    try:
        # Initialize PlexAuthService
        auth_service = PlexAuthService(settings)
        
        # Complete OAuth flow with state validation
        auth_data = auth_service.complete_oauth_flow(
            code=request.code,
            state=request.state
        )
        
        # Extract and validate the response data with proper type safety
        access_token = auth_data.get("access_token")
        user_data = auth_data.get("user")
        expires_in = auth_data.get("expires_in")
        
        # Ensure types are correct
        if not isinstance(access_token, str):
            raise ValueError("Access token must be a string")
        
        if not isinstance(user_data, dict):
            raise ValueError("User data must be a dictionary")
        
        if expires_in is not None and not isinstance(expires_in, int):
            raise ValueError("Expires in must be an integer or None")
        
        # Create PlexUser instance from user_data dict
        try:
            plex_user = PlexUser(**user_data)  # pyright: ignore[reportUnknownArgumentType]
        except Exception as e:
            raise ValueError(f"Invalid user data structure: {str(e)}") from e
        
        # Provide default expires_in if None (e.g., 1 hour)
        expires_in_seconds = expires_in if expires_in is not None else 3600
        
        # Set secure session cookie
        set_session_cookie(response, access_token)
        
        # Return structured response with proper type annotations
        return OAuthCallbackResponse(
            access_token=access_token,
            token_type="Bearer",
            user=plex_user,
            expires_in=expires_in_seconds
        )
        
    except Unauthorized as e:
        # Handle authentication failures first (Unauthorized is subclass of BadRequest)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"OAuth authentication failed: {str(e)}"
        ) from e
        
    except BadRequest as e:
        # Handle other PlexAPI connection errors
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Unable to connect to Plex servers: {str(e)}"
        ) from e
        
    except (ValueError, TypeError) as e:
        # Handle data validation errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Invalid response data from authentication service: {str(e)}"
        ) from e
        
    except Exception as e:
        # Handle unexpected errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during OAuth completion"
        ) from e


@router.get(
    "/me",
    response_model=AuthStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Get authentication status",
    description="Get current user authentication status and information"
)
async def get_authentication_status(
    request: Request,
    settings: Settings = Depends(get_settings)  # pyright: ignore[reportCallInDefaultInitializer]
) -> AuthStatusResponse:
    """
    Get current user authentication status.
    
    Validates the session token from HTTP-only cookie and returns user information
    if authenticated, or unauthenticated status if no valid session exists.
    
    Args:
        request: HTTP request object for extracting session cookie
        settings: Application settings dependency
        
    Returns:
        Authentication status response with user info if authenticated
    """
    # Get token from session cookie
    token = get_token_from_request(request)
    
    if not token:
        return AuthStatusResponse(
            authenticated=False,
            user=None
        )
    
    # Validate token using auth service
    auth_service = PlexAuthService(settings)
    validation_result = auth_service.validate_token(token)
    
    if validation_result.get("valid", False):
        # Return authenticated status with user info
        user_data = validation_result.get("user")
        # Ensure user_data is properly typed
        if user_data is not None and not isinstance(user_data, dict):
            user_data = None  # Fallback if user data is not a dict
        
        return AuthStatusResponse(
            authenticated=True,
            user=user_data  # pyright: ignore[reportGeneralTypeIssues]
        )
    else:
        # Token is invalid, return unauthenticated
        return AuthStatusResponse(
            authenticated=False,
            user=None
        )


@router.post(
    "/logout", 
    response_model=LogoutResponse,
    status_code=status.HTTP_200_OK,
    summary="Logout user",
    description="Clear user session and logout"
)
async def logout_user(
    response: Response,
    _settings: Settings = Depends(get_settings)  # pyright: ignore[reportCallInDefaultInitializer]
) -> LogoutResponse:
    """
    Logout user and clear session.
    
    Clears the session cookie and invalidates the user session. This endpoint
    succeeds even if the user is not currently authenticated.
    
    Args:
        response: HTTP response object for clearing cookies
        _settings: Application settings dependency (unused)
        
    Returns:
        Logout confirmation response
    """
    # Clear session cookie
    clear_session_cookie(response)
    
    return LogoutResponse(
        success=True,
        message="Successfully logged out"
    )


@router.post(
    "/refresh",
    response_model=OAuthCallbackResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh authentication token",
    description="Refresh expired authentication token"
)
async def refresh_authentication_token(
    request: Request,
    response: Response,
    settings: Settings = Depends(get_settings)  # pyright: ignore[reportCallInDefaultInitializer]
) -> OAuthCallbackResponse:
    """
    Refresh authentication token.
    
    Validates the current session token and refreshes it if valid. Updates the
    session cookie with the new token and returns updated user information.
    
    Args:
        request: HTTP request object for extracting current session
        response: HTTP response object for updating session cookie
        settings: Application settings dependency
        
    Returns:
        Refreshed token response with new access token and user info
        
    Raises:
        HTTPException 401: When no valid session exists or token cannot be refreshed
        HTTPException 503: When PlexAPI connection fails
        HTTPException 500: For unexpected server errors
    """
    # Get current token from session cookie
    current_token = get_token_from_request(request)
    
    if not current_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No authentication session found"
        )
    
    try:
        # Initialize PlexAuthService
        auth_service = PlexAuthService(settings)
        
        # Attempt to refresh the token
        refresh_result = auth_service.refresh_token(current_token)
        
        if not refresh_result.get("success", False):
            # Clear invalid session cookie
            clear_session_cookie(response)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token refresh failed: {refresh_result.get('error', 'Unknown error')}"
            )
        
        # Extract refreshed data
        new_access_token = refresh_result.get("access_token")
        user_data = refresh_result.get("user")
        expires_in_raw = refresh_result.get("expires_in", 3600)
        
        # Validate extracted data
        if not isinstance(new_access_token, str):
            raise ValueError("New access token must be a string")
        
        if not isinstance(user_data, dict):
            raise ValueError("User data must be a dictionary")
        
        # Ensure expires_in is properly typed
        if isinstance(expires_in_raw, int):
            expires_in = expires_in_raw
        else:
            expires_in = 3600  # Default fallback
        
        # Create PlexUser instance from refreshed user data
        try:
            plex_user = PlexUser(**user_data)  # pyright: ignore[reportUnknownArgumentType]
        except Exception as e:
            raise ValueError(f"Invalid user data structure: {str(e)}") from e
        
        # Update session cookie with new token
        set_session_cookie(response, new_access_token)
        
        # Return refreshed token response
        return OAuthCallbackResponse(
            access_token=new_access_token,
            token_type="Bearer",
            user=plex_user,
            expires_in=expires_in
        )
        
    except Unauthorized as e:
        # Handle authentication failures
        clear_session_cookie(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed during token refresh: {str(e)}"
        ) from e
        
    except BadRequest as e:
        # Handle PlexAPI connection errors
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Unable to connect to Plex servers: {str(e)}"
        ) from e
        
    except (ValueError, TypeError) as e:
        # Handle data validation errors
        clear_session_cookie(response)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Invalid response data from authentication service: {str(e)}"
        ) from e
        
    except Exception as e:
        # Handle unexpected errors
        clear_session_cookie(response)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during token refresh"
        ) from e 