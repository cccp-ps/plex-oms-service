"""
Unit tests for PlexMediaSourceService module.

Tests the Plex API integration service for managing online media sources
using MyPlexAccount.onlineMediaSources() and AccountOptOut functionality.

Test Categories:
- Media sources retrieval using MyPlexAccount
- Data parsing and transformation
- Empty sources list handling
- PlexAPI connection error handling
- Privacy-focused data filtering
"""

from typing import Any, cast
from unittest.mock import MagicMock, Mock, patch

import pytest
from plexapi.exceptions import BadRequest, Unauthorized  # pyright: ignore[reportMissingTypeStubs]

from app.config import Settings
from app.models.plex_models import OnlineMediaSource, PlexUser
from app.services.plex_service import PlexMediaSourceService
from app.utils.exceptions import PlexAPIException, AuthenticationException


class TestPlexMediaSourceService:
    """Test suite for PlexMediaSourceService functionality."""

    @pytest.fixture
    def mock_settings(self, monkeypatch: pytest.MonkeyPatch) -> Settings:
        """Create mock settings for testing."""
        # Set environment variables for Settings to use
        monkeypatch.setenv("PLEX_CLIENT_ID", "test_client_id")
        monkeypatch.setenv("PLEX_CLIENT_SECRET", "test_secret_key_that_is_long_enough")
        monkeypatch.setenv("SECRET_KEY", "test_secret_key_that_is_long_enough_for_validation_32_chars")
        monkeypatch.setenv("ENVIRONMENT", "testing")
        
        return Settings()  # pyright: ignore[reportCallIssue]

    @pytest.fixture
    def mock_user(self) -> PlexUser:
        """Create mock PlexUser for testing."""
        return PlexUser(
            id=12345,
            uuid="test-uuid-1234",
            username="testuser",
            email="test@example.com",
            authentication_token="test_token_12345"
        )

    @pytest.fixture
    def service(self, mock_settings: Settings) -> PlexMediaSourceService:
        """Create PlexMediaSourceService instance for testing."""
        return PlexMediaSourceService(settings=mock_settings)

    @pytest.fixture
    def mock_account_opt_out(self) -> Mock:
        """Create mock AccountOptOut object."""
        mock_opt_out = Mock()
        mock_opt_out.key = "spotify"
        mock_opt_out.value = "opt_out"
        return mock_opt_out

    @pytest.fixture
    def mock_account_opt_outs(self) -> list[Mock]:
        """Create list of mock AccountOptOut objects."""
        mock_opt_outs = []
        
        # Spotify source - opted out
        spotify_opt_out = Mock()
        spotify_opt_out.key = "spotify"
        spotify_opt_out.value = "opt_out"
        mock_opt_outs.append(spotify_opt_out)
        
        # TIDAL source - opted in
        tidal_opt_out = Mock()
        tidal_opt_out.key = "tidal"
        tidal_opt_out.value = "opt_in"
        mock_opt_outs.append(tidal_opt_out)
        
        # Last.fm source - managed opt out
        lastfm_opt_out = Mock()
        lastfm_opt_out.key = "lastfm"
        lastfm_opt_out.value = "opt_out_managed"
        mock_opt_outs.append(lastfm_opt_out)
        
        return mock_opt_outs

    @pytest.fixture
    def mock_account(self, mock_account_opt_outs: list[Mock]) -> Mock:
        """Create mock MyPlexAccount for testing."""
        mock_account = Mock()
        mock_account.onlineMediaSources.return_value = mock_account_opt_outs
        return mock_account


class TestMediaSourcesRetrieval(TestPlexMediaSourceService):
    """Test media sources retrieval functionality."""

    @patch("app.services.plex_service.MyPlexAccount")
    def test_retrieve_online_media_sources_success(
        self, 
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser,
        mock_account: Mock,
        mock_account_opt_outs: list[Mock]
    ) -> None:
        """Test successful retrieval of online media sources using MyPlexAccount."""
        # Arrange
        mock_my_plex_account.return_value = mock_account
        
        # Act
        result = service.get_media_sources(mock_user.authentication_token)
        
        # Assert
        assert isinstance(result, list)
        assert len(result) == 3
        
        # Verify MyPlexAccount was created with correct token
        mock_my_plex_account.assert_called_once_with(token=mock_user.authentication_token)
        
        # Verify onlineMediaSources was called
        mock_account.onlineMediaSources.assert_called_once()
        
        # Verify first source is properly transformed
        first_source = result[0]
        assert isinstance(first_source, OnlineMediaSource)
        assert first_source.identifier == "spotify"
        assert first_source.enabled is False  # opt_out means disabled

    def test_parse_and_transform_source_data_opt_out(
        self,
        service: PlexMediaSourceService,
        mock_account_opt_out: Mock
    ) -> None:
        """Test parsing and transformation of AccountOptOut data for opted out source."""
        # Arrange
        mock_account_opt_out.key = "spotify"
        mock_account_opt_out.value = "opt_out"
        
        # Act
        result = service._transform_account_opt_out(mock_account_opt_out)
        
        # Assert
        assert isinstance(result, OnlineMediaSource)
        assert result.identifier == "spotify"
        assert result.title == "Spotify"  # Transformed from identifier
        assert result.enabled is False
        assert result.scrobble_types == ["track"]  # Default for music services

    def test_parse_and_transform_source_data_opt_in(
        self,
        service: PlexMediaSourceService
    ) -> None:
        """Test parsing and transformation of AccountOptOut data for opted in source."""
        # Arrange
        mock_opt_out = Mock()
        mock_opt_out.key = "tidal"
        mock_opt_out.value = "opt_in"
        
        # Act
        result = service._transform_account_opt_out(mock_opt_out)
        
        # Assert
        assert isinstance(result, OnlineMediaSource)
        assert result.identifier == "tidal"
        assert result.title == "TIDAL"
        assert result.enabled is True
        assert result.scrobble_types == ["track"]

    def test_parse_and_transform_source_data_opt_out_managed(
        self,
        service: PlexMediaSourceService
    ) -> None:
        """Test parsing and transformation of AccountOptOut data for managed opt out."""
        # Arrange
        mock_opt_out = Mock()
        mock_opt_out.key = "lastfm"
        mock_opt_out.value = "opt_out_managed"
        
        # Act
        result = service._transform_account_opt_out(mock_opt_out)
        
        # Assert
        assert isinstance(result, OnlineMediaSource)
        assert result.identifier == "lastfm"
        assert result.title == "Last.fm"
        assert result.enabled is False  # Managed opt out means disabled
        assert result.scrobble_types == ["track"]

    @patch("app.services.plex_service.MyPlexAccount")
    def test_handle_empty_sources_list(
        self,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser
    ) -> None:
        """Test handling of empty online media sources list."""
        # Arrange
        mock_account = Mock()
        mock_account.onlineMediaSources.return_value = []
        mock_my_plex_account.return_value = mock_account
        
        # Act
        result = service.get_media_sources(mock_user.authentication_token)
        
        # Assert
        assert isinstance(result, list)
        assert len(result) == 0
        
        # Verify the service still works correctly with empty list
        mock_my_plex_account.assert_called_once_with(token=mock_user.authentication_token)
        mock_account.onlineMediaSources.assert_called_once()

    @patch("app.services.plex_service.MyPlexAccount")
    def test_handle_plexapi_connection_errors(
        self,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser
    ) -> None:
        """Test handling of PlexAPI connection errors."""
        # Arrange
        mock_my_plex_account.side_effect = BadRequest("Connection failed")
        
        # Act & Assert
        with pytest.raises(PlexAPIException) as exc_info:
            service.get_media_sources(mock_user.authentication_token)
        
        assert "Failed to connect to Plex API" in str(exc_info.value)
        mock_my_plex_account.assert_called_once_with(token=mock_user.authentication_token)

    @patch("app.services.plex_service.MyPlexAccount")
    def test_handle_plexapi_unauthorized_errors(
        self,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser
    ) -> None:
        """Test handling of PlexAPI unauthorized errors."""
        # Arrange
        mock_my_plex_account.side_effect = Unauthorized("Invalid token")
        
        # Act & Assert
        with pytest.raises(AuthenticationException) as exc_info:
            service.get_media_sources(mock_user.authentication_token)
        
        assert "Authentication failed" in str(exc_info.value)
        mock_my_plex_account.assert_called_once_with(token=mock_user.authentication_token)

    def test_apply_proper_data_filtering_for_privacy(
        self,
        service: PlexMediaSourceService
    ) -> None:
        """Test that data filtering maintains privacy-first principles."""
        # Arrange
        mock_opt_out = Mock()
        mock_opt_out.key = "spotify"
        mock_opt_out.value = "opt_in"
        
        # Mock additional attributes that might contain sensitive data
        mock_opt_out.user_data = "sensitive_user_info"
        mock_opt_out.personal_info = {"email": "user@example.com"}
        
        # Act
        result = service._transform_account_opt_out(mock_opt_out)
        
        # Assert - Only essential data should be included
        assert result.identifier == "spotify"
        assert result.title == "Spotify"
        assert result.enabled is True
        assert result.scrobble_types == ["track"]
        
        # Ensure no sensitive data is included
        result_dict = result.model_dump()
        assert "user_data" not in result_dict
        assert "personal_info" not in result_dict
        assert "email" not in str(result_dict)

    def test_source_title_transformation_mapping(
        self,
        service: PlexMediaSourceService
    ) -> None:
        """Test the identifier to title transformation mapping."""
        # Test known mappings
        test_cases = [
            ("spotify", "Spotify"),
            ("tidal", "TIDAL"),
            ("lastfm", "Last.fm"),
            ("youtube", "YouTube"),
            ("unknown_service", "Unknown Service")  # Default case
        ]
        
        for identifier, expected_title in test_cases:
            # Arrange
            mock_opt_out = Mock()
            mock_opt_out.key = identifier
            mock_opt_out.value = "opt_in"
            
            # Act
            result = service._transform_account_opt_out(mock_opt_out)
            
            # Assert
            assert result.title == expected_title

    def test_invalid_authentication_token_handling(
        self,
        service: PlexMediaSourceService
    ) -> None:
        """Test handling of invalid authentication tokens."""
        # Test with None token
        with pytest.raises(AuthenticationException) as exc_info:
            service.get_media_sources(None)  # pyright: ignore[reportArgumentType]
        
        assert "Invalid authentication token" in str(exc_info.value)
        
        # Test with empty string token
        with pytest.raises(AuthenticationException) as exc_info:
            service.get_media_sources("")
        
        assert "Invalid authentication token" in str(exc_info.value)
        
        # Test with whitespace-only token
        with pytest.raises(AuthenticationException) as exc_info:
            service.get_media_sources("   ")
        
        assert "Invalid authentication token" in str(exc_info.value)

    @patch("app.services.plex_service.MyPlexAccount")
    def test_general_exception_handling(
        self,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser
    ) -> None:
        """Test handling of general exceptions during API calls."""
        # Arrange
        mock_my_plex_account.side_effect = Exception("Unexpected error")
        
        # Act & Assert
        with pytest.raises(PlexAPIException) as exc_info:
            service.get_media_sources(mock_user.authentication_token)
        
        assert "Unexpected error during Plex API operation" in str(exc_info.value)

    @patch("app.services.plex_service.get_settings")
    def test_service_initialization_with_default_settings(self, mock_get_settings: Mock) -> None:
        """Test service initialization with default settings."""
        # Arrange
        mock_settings = Mock()
        mock_get_settings.return_value = mock_settings
        
        # Act
        service = PlexMediaSourceService()
        
        # Assert
        assert service._settings is mock_settings
        mock_get_settings.assert_called_once()

    def test_source_scrobble_types_assignment(
        self,
        service: PlexMediaSourceService
    ) -> None:
        """Test proper assignment of scrobble types for different services."""
        test_cases = [
            ("spotify", ["track"]),
            ("tidal", ["track"]),
            ("lastfm", ["track"]),
            ("youtube", ["track"]),
            ("unknown", ["track"])  # Default fallback
        ]
        
        for identifier, expected_types in test_cases:
            # Arrange
            mock_opt_out = Mock()
            mock_opt_out.key = identifier
            mock_opt_out.value = "opt_in"
            
            # Act
            result = service._transform_account_opt_out(mock_opt_out)
            
            # Assert
            assert result.scrobble_types == expected_types 