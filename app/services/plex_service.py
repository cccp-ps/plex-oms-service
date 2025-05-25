"""
Plex media sources service module.

This service handles online media sources management using PlexAPI's MyPlexAccount.onlineMediaSources()
and AccountOptOut functionality. Provides privacy-first data filtering and robust error handling.

Features:
- Media sources retrieval using MyPlexAccount
- Data parsing and transformation with privacy filtering
- Empty sources list handling
- PlexAPI connection error handling
- Individual source management and bulk operations
"""

from typing import TYPE_CHECKING

from plexapi.exceptions import BadRequest, Unauthorized  # pyright: ignore[reportMissingTypeStubs]
from plexapi.myplex import MyPlexAccount  # pyright: ignore[reportMissingTypeStubs]

from app.config import get_settings
from app.models.plex_models import OnlineMediaSource
from app.utils.exceptions import (
    AuthenticationException,
    PlexAPIException
)

if TYPE_CHECKING:
    from app.config import Settings


class PlexMediaSourceService:
    """
    Plex media sources management service.
    
    Handles online media sources management using PlexAPI's MyPlexAccount
    for retrieving, parsing, and transforming media source data with 
    privacy-first principles and robust error handling.
    """
    
    def __init__(self, settings: "Settings | None" = None) -> None:
        """Initialize the PlexMediaSourceService."""
        self._settings: "Settings" = settings or get_settings()
    
    @property
    def settings(self) -> "Settings":
        """Get the current settings instance."""
        return self._settings
    
    def get_media_sources(self, authentication_token: str | None) -> list[OnlineMediaSource]:
        """
        Retrieve online media sources using MyPlexAccount.
        
        Args:
            authentication_token: Plex authentication token
            
        Returns:
            List of OnlineMediaSource objects
            
        Raises:
            AuthenticationException: When token is invalid or authentication fails
            PlexAPIException: When PlexAPI connection fails
        """
        # Validate authentication token
        if not authentication_token or not authentication_token.strip():
            raise AuthenticationException("Invalid authentication token provided")
        
        try:
            # Create MyPlexAccount instance with the token
            account = MyPlexAccount(token=authentication_token.strip())
            
            # Get online media sources from the account
            account_opt_outs: list[object] = account.onlineMediaSources()  # pyright: ignore[reportUnknownVariableType]
            
            # Transform and return the sources
            return [
                self.transform_account_opt_out(opt_out)  # pyright: ignore[reportUnknownArgumentType]
                for opt_out in account_opt_outs  # pyright: ignore[reportUnknownVariableType]
            ]
            
        except Unauthorized as e:
            # Handle authentication errors
            raise AuthenticationException(
                "Authentication failed with provided token",
                original_error=e
            )
        except BadRequest as e:
            # Handle connection errors
            raise PlexAPIException(
                "Failed to connect to Plex API",
                original_error=e
            )
        except Exception as e:
            # Handle any other unexpected errors
            raise PlexAPIException(
                "Unexpected error during Plex API operation",
                original_error=e
            )
    
    def transform_account_opt_out(self, account_opt_out: object) -> OnlineMediaSource:
        """
        Transform AccountOptOut object to OnlineMediaSource model.
        
        Converts PlexAPI AccountOptOut objects to our privacy-focused
        OnlineMediaSource model with proper field mapping and validation.
        
        Args:
            account_opt_out: AccountOptOut object from PlexAPI
            
        Returns:
            OnlineMediaSource model instance
        """
        # Extract basic data with safe attribute access
        identifier = str(getattr(account_opt_out, 'key', 'unknown'))
        value = str(getattr(account_opt_out, 'value', 'opt_out'))
        
        # Transform identifier to user-friendly title
        title = self._get_title_for_identifier(identifier)
        
        # Determine enabled status based on opt-out value
        enabled = value == "opt_in"
        
        # Set default scrobble types for all services
        scrobble_types = ["track"]  # Default for music services
        
        return OnlineMediaSource(
            identifier=identifier,
            title=title,
            enabled=enabled,
            scrobble_types=scrobble_types
        )
    
    def _get_title_for_identifier(self, identifier: str) -> str:
        """
        Get user-friendly title for service identifier.
        
        Maps service identifiers to display-friendly titles.
        
        Args:
            identifier: Service identifier (e.g., 'spotify', 'tidal')
            
        Returns:
            User-friendly title for the service
        """
        # Known service mappings
        title_mappings = {
            "spotify": "Spotify",
            "tidal": "TIDAL",
            "lastfm": "Last.fm",
            "youtube": "YouTube",
        }
        
        # Return mapped title or create default from identifier
        if identifier in title_mappings:
            return title_mappings[identifier]
        else:
            # Create default title from identifier
            return identifier.replace("_", " ").title() 