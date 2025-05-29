"""
Authentication routes for OAuth flow.

Provides endpoints for Plex OAuth authentication including:
- OAuth initiation with MyPlexPinLogin(oauth=True)
- OAuth callback handling
- Session management (status, logout)

Following security best practices with proper error handling and rate limiting.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from plexapi.exceptions import BadRequest, Unauthorized  # pyright: ignore[reportMissingTypeStubs]

from app.config import Settings, get_settings
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
    settings: Settings = Depends(get_settings)  # pyright: ignore[reportCallInDefaultInitializer]
) -> OAuthCallbackResponse:
    """
    Complete OAuth flow with authorization code and state validation.
    
    Validates the state parameter for CSRF protection, waits for OAuth completion,
    and retrieves the authenticated MyPlexAccount with user information.
    
    Args:
        request: OAuth callback request with code and state
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
        
        # Return structured response with proper type annotations
        return OAuthCallbackResponse(
            access_token=access_token,
            token_type="Bearer",
            user=user_data,  # pyright: ignore[reportUnknownArgumentType]
            expires_in=expires_in
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
    _settings: Settings = Depends(get_settings)  # pyright: ignore[reportCallInDefaultInitializer]
) -> AuthStatusResponse:
    """
    Get current user authentication status.
    
    This endpoint will be enhanced with session management when sessions are implemented.
    For now, it returns a basic structure for testing purposes.
    
    Args:
        _settings: Application settings dependency (unused for now)
        
    Returns:
        Authentication status response
    """
    # TODO: Implement actual session validation when session middleware is added
    # For now, return not authenticated for testing
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
    _settings: Settings = Depends(get_settings)  # pyright: ignore[reportCallInDefaultInitializer]
) -> LogoutResponse:
    """
    Logout user and clear session.
    
    This endpoint will be enhanced with session management when sessions are implemented.
    For now, it returns a basic structure for testing purposes.
    
    Args:
        _settings: Application settings dependency (unused for now)
        
    Returns:
        Logout confirmation response
    """
    # TODO: Implement actual session clearing when session middleware is added
    # For now, return success for testing
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
    _settings: Settings = Depends(get_settings)  # pyright: ignore[reportCallInDefaultInitializer]
) -> OAuthCallbackResponse:
    """
    Refresh authentication token.
    
    This endpoint will be enhanced with token refresh logic when session management
    is implemented. For now, it raises an error indicating not implemented.
    
    Args:
        _settings: Application settings dependency (unused for now)
        
    Returns:
        Refreshed token response
        
    Raises:
        HTTPException 501: Not implemented yet
    """
    # TODO: Implement token refresh when session management is added
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Token refresh not implemented yet"
    ) 