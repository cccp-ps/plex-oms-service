"""
Media sources API routes.

This module provides endpoints for managing Plex online media sources,
including listing current sources, individual source management,
and bulk operations with privacy-first design principles.

Routes:
- GET /api/media-sources: List user's online media sources
- PATCH /api/media-sources/{source_id}: Toggle individual source
- POST /api/media-sources/disable-all: Bulk disable all sources

All endpoints require authentication and follow secure coding practices.
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.models.plex_models import OnlineMediaSource
from app.schemas.media_source_schemas import IndividualSourceToggleRequest
from app.services.plex_service import PlexMediaSourceService
from app.utils.exceptions import AuthenticationException, PlexAPIException, ValidationException

# Configure secure logging
logger = logging.getLogger(__name__)

# Initialize router and dependencies
router = APIRouter(prefix="/api/media-sources", tags=["media-sources"])

# Service instance
plex_service = PlexMediaSourceService()


async def get_current_user_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(HTTPBearer(auto_error=False))]
) -> str:
    """
    Extract and validate the current user's authentication token.
    
    Args:
        credentials: HTTP Bearer credentials from request header (can be None)
        
    Returns:
        Validated authentication token
        
    Raises:
        HTTPException: When authentication fails
    """
    if not credentials or not credentials.credentials:
        logger.warning("Authentication attempt with missing credentials")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Please authenticate with valid credentials",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    return credentials.credentials


@router.get(
    "",
    response_model=list[OnlineMediaSource],
    status_code=status.HTTP_200_OK,
    summary="List user's online media sources",
    description="Retrieve the current user's online media sources with privacy-focused filtering",
    responses={
        200: {
            "description": "Successfully retrieved media sources",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "identifier": "spotify",
                            "title": "Spotify",
                            "enabled": True,
                            "scrobble_types": ["track"]
                        },
                        {
                            "identifier": "tidal",
                            "title": "TIDAL",
                            "enabled": False,
                            "scrobble_types": ["track"]
                        }
                    ]
                }
            }
        },
        401: {
            "description": "Authentication required",
            "content": {
                "application/json": {
                    "example": {"detail": "Authentication credentials required"}
                }
            }
        },
        503: {
            "description": "Plex API service unavailable",
            "content": {
                "application/json": {
                    "example": {"detail": "Plex API service temporarily unavailable"}
                }
            }
        }
    }
)
async def get_media_sources(
    request: Request,  # pyright: ignore[reportUnusedParameter]
    token: Annotated[str, Depends(get_current_user_token)]
) -> list[OnlineMediaSource]:
    """
    Get user's online media sources.
    
    Retrieves the current user's online media sources from Plex API
    with privacy-focused data filtering. Only essential fields are
    returned to maintain data minimization principles.
    
    Args:
        request: FastAPI request object (for logging context)
        token: User's authentication token from Authorization header
        
    Returns:
        List of OnlineMediaSource objects with privacy-safe data
        
    Raises:
        HTTPException: When authentication fails or Plex API errors occur
    """
    try:
        # Log request without sensitive data
        logger.info("Media sources request initiated")
        
        # Get media sources from Plex service
        media_sources = plex_service.get_media_sources(token)
        
        # Log successful response without exposing data
        logger.info(f"Successfully retrieved {len(media_sources)} media sources")
        
        return media_sources
        
    except AuthenticationException as e:
        # Handle authentication errors
        logger.warning("Authentication failed for media sources request")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed. Please verify your credentials.",
            headers={"WWW-Authenticate": "Bearer"}
        ) from e
        
    except PlexAPIException as e:
        # Handle Plex API connection errors
        logger.error("Plex API error occurred during media sources request")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Plex API service temporarily unavailable. Please try again later."
        ) from e
        
    except Exception as e:
        # Handle unexpected errors
        logger.error("Unexpected error during media sources request")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred. Please try again later."
        ) from e 

@router.patch(
    "/{source_id}",
    response_model=OnlineMediaSource,
    status_code=status.HTTP_200_OK,
    summary="Toggle individual media source",
    description="Enable or disable a specific online media source with proper validation and authorization",
    responses={
        200: {
            "description": "Successfully toggled media source",
            "content": {
                "application/json": {
                    "example": {
                        "identifier": "spotify",
                        "title": "Spotify",
                        "enabled": True,
                        "scrobble_types": ["track"]
                    }
                }
            }
        },
        401: {
            "description": "Authentication required",
            "content": {
                "application/json": {
                    "example": {"detail": "Authentication credentials required"}
                }
            }
        },
        404: {
            "description": "Media source not found",
            "content": {
                "application/json": {
                    "example": {"detail": "Media source not found or doesn't belong to user"}
                }
            }
        },
        422: {
            "description": "Invalid request payload",
            "content": {
                "application/json": {
                    "example": {"detail": "Request payload validation failed"}
                }
            }
        },
        500: {
            "description": "Toggle operation failed",
            "content": {
                "application/json": {
                    "example": {"detail": "Failed to toggle media source"}
                }
            }
        },
        503: {
            "description": "Plex API service unavailable",
            "content": {
                "application/json": {
                    "example": {"detail": "Plex API service temporarily unavailable"}
                }
            }
        }
    }
)
async def toggle_individual_media_source(
    source_id: str,
    request: Request,  # pyright: ignore[reportUnusedParameter]
    toggle_request: "IndividualSourceToggleRequest",
    token: Annotated[str, Depends(get_current_user_token)]
) -> OnlineMediaSource:
    """
    Toggle an individual media source on/off.
    
    Enables or disables a specific online media source for the authenticated user.
    Validates that the source exists and belongs to the user before performing
    the toggle operation. Returns the updated source information on success.
    
    Args:
        source_id: Identifier for the media source to toggle
        request: FastAPI request object (for logging context)
        toggle_request: Request payload containing enabled status
        token: User's authentication token from Authorization header
        
    Returns:
        Updated OnlineMediaSource object with new enabled status
        
    Raises:
        HTTPException: When validation fails, source not found, or operations fail
    """
    try:
        # Validate source_id parameter
        if not source_id or not source_id.strip():
            logger.warning("Invalid source_id parameter provided")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Source ID cannot be empty"
            )
        
        # Log request without sensitive data
        logger.info(f"Individual source toggle request for source: {source_id[:10]}...")
        
        # Perform toggle operation using the service
        toggle_success = plex_service.toggle_individual_source(
            authentication_token=token,
            source_identifier=source_id.strip(),
            enable=toggle_request.enabled
        )
        
        # Check if toggle operation was successful
        if not toggle_success:
            logger.error(f"Toggle operation failed for source: {source_id[:10]}...")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to toggle media source operation. Please try again later."
            )
        
        # Get updated source status
        updated_source = plex_service.get_individual_source_status(
            authentication_token=token,
            source_identifier=source_id.strip()
        )
        
        # Log successful response without exposing data
        action = "enabled" if toggle_request.enabled else "disabled"
        logger.info(f"Successfully {action} media source: {source_id[:10]}...")
        
        return updated_source
        
    except HTTPException:
        # Re-raise HTTPExceptions (including the toggle failure case)
        raise
        
    except AuthenticationException as e:
        # Handle authentication errors
        logger.warning(f"Authentication failed for source toggle: {source_id[:10]}...")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed. Please verify your credentials.",
            headers={"WWW-Authenticate": "Bearer"}
        ) from e
        
    except ValidationException as e:
        # Handle validation errors (source not found)
        logger.warning(f"Source not found for toggle: {source_id[:10]}...")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Media source not found or doesn't belong to user"
        ) from e
        
    except PlexAPIException as e:
        # Handle Plex API connection errors
        logger.error(f"Plex API error during source toggle: {source_id[:10]}...")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Plex API service temporarily unavailable. Please try again later."
        ) from e
        
    except Exception as e:
        # Handle unexpected errors
        logger.error(f"Unexpected error during source toggle: {source_id[:10]}...")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred. Please try again later."
        ) from e 