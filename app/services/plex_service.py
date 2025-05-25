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

import time
from typing import TYPE_CHECKING, TypedDict

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


class BulkOperationResult(TypedDict):
    """Type definition for bulk operation result."""
    success: bool
    total_requested: int
    successful_count: int
    failed_count: int
    disabled_sources: list[str]
    failed_sources: list[str]
    message: str


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
    
    def toggle_individual_source(
        self,
        authentication_token: str | None,
        source_identifier: str | None,
        enable: bool
    ) -> bool:
        """
        Toggle individual media source enable/disable status.
        
        Args:
            authentication_token: Plex authentication token
            source_identifier: Identifier for the media source to toggle
            enable: True to enable the source, False to disable it
            
        Returns:
            True if the operation was successful
            
        Raises:
            AuthenticationException: When token is invalid or authentication fails
            ValueError: When source identifier is invalid or not found
            PlexAPIException: When PlexAPI operation fails
        """
        # Validate authentication token
        if not authentication_token or not authentication_token.strip():
            raise AuthenticationException("Invalid authentication token provided")
        
        # Validate source identifier
        if not source_identifier or not source_identifier.strip():
            raise ValueError("Invalid source identifier provided")
        
        try:
            # Create MyPlexAccount instance with the token
            account = MyPlexAccount(token=authentication_token.strip())
            
            # Toggle the source based on enable flag
            if enable:
                account.enableOnlineMediaSource(source_identifier.strip())  # pyright: ignore[reportUnknownMemberType,reportAttributeAccessIssue]
            else:
                account.disableOnlineMediaSource(source_identifier.strip())  # pyright: ignore[reportUnknownMemberType,reportAttributeAccessIssue]
            
            return True
            
        except Unauthorized as e:
            # Handle authentication errors
            raise AuthenticationException(
                "Authentication failed with provided token",
                original_error=e
            )
        except BadRequest as e:
            # Handle bad request errors (e.g., invalid source)
            raise PlexAPIException(
                "Failed to toggle media source",
                original_error=e
            )
        except Exception as e:
            # Handle any other unexpected errors
            raise PlexAPIException(
                "Unexpected error during source toggle operation",
                original_error=e
            )
    
    def get_individual_source_status(
        self,
        authentication_token: str | None,
        source_identifier: str | None
    ) -> OnlineMediaSource:
        """
        Get status of an individual media source.
        
        Args:
            authentication_token: Plex authentication token
            source_identifier: Identifier for the media source
            
        Returns:
            OnlineMediaSource object with current status
            
        Raises:
            AuthenticationException: When token is invalid or authentication fails
            ValueError: When source identifier is invalid or not found
            PlexAPIException: When PlexAPI connection fails
        """
        # Validate authentication token
        if not authentication_token or not authentication_token.strip():
            raise AuthenticationException("Invalid authentication token provided")
        
        # Validate source identifier
        if not source_identifier or not source_identifier.strip():
            raise ValueError("Invalid source identifier provided")
        
        try:
            # Create MyPlexAccount instance with the token
            account = MyPlexAccount(token=authentication_token.strip())
            
            # Get online media sources from the account
            account_opt_outs: list[object] = account.onlineMediaSources()  # pyright: ignore[reportUnknownVariableType]
            
            # Find the specific source
            source_identifier_clean = source_identifier.strip()
            for opt_out in account_opt_outs:  # pyright: ignore[reportUnknownVariableType]
                opt_out_key = str(getattr(opt_out, 'key', ''))  # pyright: ignore[reportUnknownArgumentType]
                if opt_out_key == source_identifier_clean:
                    return self.transform_account_opt_out(opt_out)  # pyright: ignore[reportUnknownArgumentType]
            
            # Source not found
            raise ValueError(f"Media source with identifier '{source_identifier_clean}' not found")
            
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
            # Handle any other unexpected errors (except our ValueError)
            if isinstance(e, ValueError):
                raise  # Re-raise our ValueError
            raise PlexAPIException(
                "Unexpected error during Plex API operation",
                original_error=e
            )

    def bulk_disable_all_sources(self, authentication_token: str | None) -> BulkOperationResult:
        """
        Bulk disable all media sources using AccountOptOut.optOut().
        
        Uses individual AccountOptOut.optOut() calls for each source with proper
        retry logic and partial failure handling.
        
        Args:
            authentication_token: Plex authentication token
            
        Returns:
            BulkOperationResult with success/failure counts and source details
            
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
            
            # Handle empty sources list
            if not account_opt_outs:
                return {
                    "success": True,
                    "total_requested": 0,
                    "successful_count": 0,
                    "failed_count": 0,
                    "disabled_sources": [],
                    "failed_sources": [],
                    "message": "No media sources found to disable"
                }
            
            # Initialize operation tracking
            total_requested = len(account_opt_outs)  # pyright: ignore[reportUnknownArgumentType]
            successful_count = 0
            failed_count = 0
            disabled_sources: list[str] = []
            failed_sources: list[str] = []
            
            # Process each source with retry logic
            for opt_out in account_opt_outs:  # pyright: ignore[reportUnknownVariableType]
                source_key = str(getattr(opt_out, 'key', 'unknown'))  # pyright: ignore[reportUnknownArgumentType]
                
                # Attempt to disable the source with retry logic
                if self._disable_source_with_retry(opt_out):  # pyright: ignore[reportUnknownArgumentType]
                    successful_count += 1
                    disabled_sources.append(source_key)
                else:
                    failed_count += 1
                    failed_sources.append(source_key)
            
            # Determine overall success and generate message
            overall_success = failed_count == 0
            if total_requested == successful_count:
                message = f"Successfully disabled {successful_count} media sources"
            elif successful_count > 0:
                message = f"Disabled {successful_count} out of {total_requested} media sources"
            else:
                message = "Failed to disable any media sources"
            
            return {
                "success": overall_success,
                "total_requested": total_requested,
                "successful_count": successful_count,
                "failed_count": failed_count,
                "disabled_sources": disabled_sources,
                "failed_sources": failed_sources,
                "message": message
            }
            
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
                "Unexpected error during bulk operation",
                original_error=e
            )
    
    def _disable_source_with_retry(self, opt_out: object, max_retries: int = 3) -> bool:
        """
        Disable a single source with exponential backoff retry logic.
        
        Args:
            opt_out: AccountOptOut object from PlexAPI
            max_retries: Maximum number of retry attempts
            
        Returns:
            True if successful, False if all retries failed
        """
        for attempt in range(max_retries):
            try:
                # Call optOut method on the AccountOptOut object
                opt_out_method = getattr(opt_out, 'optOut', None)
                if opt_out_method and callable(opt_out_method):  # pyright: ignore[reportAny]
                    _ = opt_out_method()
                    return True
                else:
                    # Source doesn't have optOut method
                    return False
                    
            except (BadRequest, Exception):
                # If this is the last attempt, give up
                if attempt == max_retries - 1:
                    return False
                
                # Calculate exponential backoff delay
                delay: float = 2.0 ** attempt  # 1s, 2s, 4s...
                time.sleep(delay)
                
                # Continue to next retry attempt
                continue
        
        return False 