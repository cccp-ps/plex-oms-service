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

from unittest.mock import Mock, patch

import pytest
from plexapi.exceptions import BadRequest, Unauthorized  # pyright: ignore[reportMissingTypeStubs]

from app.config import Settings
from app.models.plex_models import OnlineMediaSource, PlexUser
from app.services.plex_service import PlexMediaSourceService
from app.utils.exceptions import (
    AuthenticationException,
    PlexAPIException,
    ConnectionException
)




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
    def mock_account_opt_outs(self) -> list[object]:
        """Create list of mock AccountOptOut objects."""
        mock_opt_outs: list[object] = []
        
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
    def mock_account(self, mock_account_opt_outs: list[object]) -> Mock:
        """Create mock MyPlexAccount for testing."""
        mock_account = Mock()
        mock_account.onlineMediaSources.return_value = mock_account_opt_outs  # pyright: ignore[reportAny]
        return mock_account


class TestMediaSourcesRetrieval(TestPlexMediaSourceService):
    """Test media sources retrieval functionality."""

    @patch("app.services.plex_service.MyPlexAccount")
    def test_retrieve_online_media_sources_success(
        self, 
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser,
        mock_account: Mock
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
        mock_account.onlineMediaSources.assert_called_once()  # pyright: ignore[reportAny]
        
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
        result = service.transform_account_opt_out(mock_account_opt_out)
        
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
        result = service.transform_account_opt_out(mock_opt_out)
        
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
        result = service.transform_account_opt_out(mock_opt_out)
        
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
        mock_account.onlineMediaSources.return_value = []  # pyright: ignore[reportAny]
        mock_my_plex_account.return_value = mock_account
        
        # Act
        result = service.get_media_sources(mock_user.authentication_token)
        
        # Assert
        assert isinstance(result, list)
        assert len(result) == 0
        
        # Verify the service still works correctly with empty list
        mock_my_plex_account.assert_called_once_with(token=mock_user.authentication_token)
        mock_account.onlineMediaSources.assert_called_once()  # pyright: ignore[reportAny]

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
            _ = service.get_media_sources(mock_user.authentication_token)
        
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
            _ = service.get_media_sources(mock_user.authentication_token)
        
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
        result = service.transform_account_opt_out(mock_opt_out)
        
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
            result = service.transform_account_opt_out(mock_opt_out)
            
            # Assert
            assert result.title == expected_title

    def test_invalid_authentication_token_handling(
        self,
        service: PlexMediaSourceService
    ) -> None:
        """Test handling of invalid authentication tokens."""
        # Test with None token
        with pytest.raises(AuthenticationException) as exc_info:
            _ = service.get_media_sources(None)
        
        assert "Invalid authentication token" in str(exc_info.value)
        
        # Test with empty string token
        with pytest.raises(AuthenticationException) as exc_info:
            _ = service.get_media_sources("")
        
        assert "Invalid authentication token" in str(exc_info.value)
        
        # Test with whitespace-only token
        with pytest.raises(AuthenticationException) as exc_info:
            _ = service.get_media_sources("   ")
        
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
            _ = service.get_media_sources(mock_user.authentication_token)
        
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
        assert service.settings is mock_settings
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
            result = service.transform_account_opt_out(mock_opt_out)
            
            # Assert
            assert result.scrobble_types == expected_types 


class TestIndividualSourceManagement(TestPlexMediaSourceService):
    """Test individual source management functionality."""

    @pytest.fixture
    def mock_account_with_enable_disable(self) -> Mock:
        """Create mock MyPlexAccount with enableOnlineMediaSource and disableOnlineMediaSource methods."""
        mock_account = Mock()
        mock_account.enableOnlineMediaSource = Mock()
        mock_account.disableOnlineMediaSource = Mock()
        return mock_account

    @patch("app.services.plex_service.MyPlexAccount")
    def test_toggle_individual_source_enable_success(
        self,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser,
        mock_account_with_enable_disable: Mock
    ) -> None:
        """Test successful enabling of individual media source."""
        # Arrange
        source_identifier = "spotify"
        mock_my_plex_account.return_value = mock_account_with_enable_disable
        
        # Act
        result = service.toggle_individual_source(
            authentication_token=mock_user.authentication_token,
            source_identifier=source_identifier,
            enable=True
        )
        
        # Assert
        assert result is True
        mock_my_plex_account.assert_called_once_with(token=mock_user.authentication_token)
        mock_account_with_enable_disable.enableOnlineMediaSource.assert_called_once_with(source_identifier)  # pyright: ignore[reportAny]
        mock_account_with_enable_disable.disableOnlineMediaSource.assert_not_called()  # pyright: ignore[reportAny]

    @patch("app.services.plex_service.MyPlexAccount")
    def test_toggle_individual_source_disable_success(
        self,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser,
        mock_account_with_enable_disable: Mock
    ) -> None:
        """Test successful disabling of individual media source."""
        # Arrange
        source_identifier = "tidal"
        mock_my_plex_account.return_value = mock_account_with_enable_disable
        
        # Act
        result = service.toggle_individual_source(
            authentication_token=mock_user.authentication_token,
            source_identifier=source_identifier,
            enable=False
        )
        
        # Assert
        assert result is True
        mock_my_plex_account.assert_called_once_with(token=mock_user.authentication_token)
        mock_account_with_enable_disable.disableOnlineMediaSource.assert_called_once_with(source_identifier)  # pyright: ignore[reportAny]
        mock_account_with_enable_disable.enableOnlineMediaSource.assert_not_called()  # pyright: ignore[reportAny]

    def test_toggle_individual_source_invalid_token(
        self,
        service: PlexMediaSourceService
    ) -> None:
        """Test error handling for invalid authentication token."""
        # Arrange
        invalid_tokens = [None, "", "   ", "  \t\n  "]
        
        for invalid_token in invalid_tokens:
            # Act & Assert
            with pytest.raises(AuthenticationException, match="Invalid authentication token provided"):
                _ = service.toggle_individual_source(
                    authentication_token=invalid_token,
                    source_identifier="spotify",
                    enable=True
                )

    def test_toggle_individual_source_invalid_identifier(
        self,
        service: PlexMediaSourceService,
        mock_user: PlexUser
    ) -> None:
        """Test error handling for invalid source identifier."""
        # Arrange
        invalid_identifiers = [None, "", "   ", "  \t\n  "]
        
        for invalid_identifier in invalid_identifiers:
            # Act & Assert
            with pytest.raises(ValueError, match="Invalid source identifier provided"):
                _ = service.toggle_individual_source(
                    authentication_token=mock_user.authentication_token,
                    source_identifier=invalid_identifier,
                    enable=True
                )

    @patch("app.services.plex_service.MyPlexAccount")
    def test_toggle_individual_source_plexapi_unauthorized_error(
        self,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser
    ) -> None:
        """Test handling of PlexAPI unauthorized errors during source toggle."""
        # Arrange
        mock_my_plex_account.side_effect = Unauthorized("Invalid token")
        
        # Act & Assert
        with pytest.raises(AuthenticationException, match="Authentication failed with provided token"):
            _ = service.toggle_individual_source(
                authentication_token=mock_user.authentication_token,
                source_identifier="spotify",
                enable=True
            )

    @patch("app.services.plex_service.MyPlexAccount")
    def test_toggle_individual_source_plexapi_bad_request_error(
        self,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser
    ) -> None:
        """Test handling of PlexAPI bad request errors during source toggle."""
        # Arrange
        mock_account = Mock()
        mock_account.enableOnlineMediaSource.side_effect = BadRequest("Invalid source")  # pyright: ignore[reportAny]
        mock_my_plex_account.return_value = mock_account
        
        # Act & Assert
        with pytest.raises(PlexAPIException, match="Failed to toggle media source"):
            _ = service.toggle_individual_source(
                authentication_token=mock_user.authentication_token,
                source_identifier="invalid_source",
                enable=True
            )

    @patch("app.services.plex_service.MyPlexAccount")
    def test_toggle_individual_source_general_exception(
        self,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser
    ) -> None:
        """Test handling of general exceptions during source toggle."""
        # Arrange
        mock_account = Mock()
        mock_account.disableOnlineMediaSource.side_effect = Exception("Unexpected error")  # pyright: ignore[reportAny]
        mock_my_plex_account.return_value = mock_account
        
        # Act & Assert
        with pytest.raises(PlexAPIException, match="Unexpected error during source toggle operation"):
            _ = service.toggle_individual_source(
                authentication_token=mock_user.authentication_token,
                source_identifier="spotify",
                enable=False
            )

    @patch("app.services.plex_service.MyPlexAccount")
    def test_get_individual_source_status_success(
        self,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser,
        mock_account_opt_outs: list[object]
    ) -> None:
        """Test successful retrieval of individual source status."""
        # Arrange
        mock_account = Mock()
        mock_account.onlineMediaSources.return_value = mock_account_opt_outs  # pyright: ignore[reportAny]
        mock_my_plex_account.return_value = mock_account
        
        # Act
        result = service.get_individual_source_status(
            authentication_token=mock_user.authentication_token,
            source_identifier="spotify"
        )
        
        # Assert
        assert isinstance(result, OnlineMediaSource)
        assert result.identifier == "spotify"
        assert result.title == "Spotify"
        assert result.enabled is False  # From mock opt_out
        
        mock_my_plex_account.assert_called_once_with(token=mock_user.authentication_token)
        mock_account.onlineMediaSources.assert_called_once()  # pyright: ignore[reportAny]

    @patch("app.services.plex_service.MyPlexAccount")
    def test_get_individual_source_status_not_found(
        self,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser,
        mock_account_opt_outs: list[object]
    ) -> None:
        """Test error handling when source identifier is not found."""
        # Arrange
        mock_account = Mock()
        mock_account.onlineMediaSources.return_value = mock_account_opt_outs  # pyright: ignore[reportAny]
        mock_my_plex_account.return_value = mock_account
        
        # Act & Assert
        with pytest.raises(ValueError, match="Media source with identifier 'nonexistent' not found"):
            _ = service.get_individual_source_status(
                authentication_token=mock_user.authentication_token,
                source_identifier="nonexistent"
            )

    def test_get_individual_source_status_invalid_token(
        self,
        service: PlexMediaSourceService
    ) -> None:
        """Test error handling for invalid authentication token when getting source status."""
        # Arrange
        invalid_tokens = [None, "", "   ", "  \t\n  "]
        
        for invalid_token in invalid_tokens:
            # Act & Assert
            with pytest.raises(AuthenticationException, match="Invalid authentication token provided"):
                _ = service.get_individual_source_status(
                    authentication_token=invalid_token,
                    source_identifier="spotify"
                )

    def test_get_individual_source_status_invalid_identifier(
        self,
        service: PlexMediaSourceService,
        mock_user: PlexUser
    ) -> None:
        """Test error handling for invalid source identifier when getting source status."""
        # Arrange
        invalid_identifiers = [None, "", "   ", "  \t\n  "]
        
        for invalid_identifier in invalid_identifiers:
            # Act & Assert
            with pytest.raises(ValueError, match="Invalid source identifier provided"):
                _ = service.get_individual_source_status(
                    authentication_token=mock_user.authentication_token,
                    source_identifier=invalid_identifier
                ) 


class TestBulkOperations(TestPlexMediaSourceService):
    """Test bulk operations functionality."""

    @pytest.fixture
    def mock_account_with_bulk_operations(self, mock_account_opt_outs: list[object]) -> Mock:
        """Create mock MyPlexAccount with bulk operations methods."""
        mock_account = Mock()
        mock_account.onlineMediaSources.return_value = mock_account_opt_outs  # pyright: ignore[reportAny]
        
        # Mock individual opt-out objects with optOut methods
        mock_opt_outs_with_methods: list[Mock] = []
        for opt_out in mock_account_opt_outs:
            mock_opt_out_with_method = Mock()
            mock_opt_out_with_method.key = getattr(opt_out, 'key', 'unknown')
            mock_opt_out_with_method.value = getattr(opt_out, 'value', 'opt_out')
            mock_opt_out_with_method.optOut = Mock()  # Mock the optOut method
            mock_opt_outs_with_methods.append(mock_opt_out_with_method)
        
        mock_account.onlineMediaSources.return_value = mock_opt_outs_with_methods  # pyright: ignore[reportAny]
        return mock_account

    @pytest.fixture
    def mock_account_with_partial_failures(self, mock_account_opt_outs: list[object]) -> Mock:
        """Create mock MyPlexAccount where some bulk operations fail."""
        mock_account = Mock()
        
        # Create opt-out objects where some operations will fail
        mock_opt_outs_with_failures: list[Mock] = []
        for i, opt_out in enumerate(mock_account_opt_outs):
            mock_opt_out_with_method = Mock()
            mock_opt_out_with_method.key = getattr(opt_out, 'key', f'source_{i}')
            mock_opt_out_with_method.value = getattr(opt_out, 'value', 'opt_in')
            
            # Make first source fail, others succeed
            if i == 0:
                mock_opt_out_with_method.optOut = Mock(side_effect=BadRequest("Failed to opt out"))
            else:
                mock_opt_out_with_method.optOut = Mock()
            
            mock_opt_outs_with_failures.append(mock_opt_out_with_method)
        
        mock_account.onlineMediaSources.return_value = mock_opt_outs_with_failures  # pyright: ignore[reportAny]
        return mock_account

    @patch("app.services.plex_service.MyPlexAccount")
    def test_bulk_disable_all_sources_success(
        self,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser,
        mock_account_with_bulk_operations: Mock
    ) -> None:
        """Test successful bulk disable of all sources using AccountOptOut."""
        # Arrange
        mock_my_plex_account.return_value = mock_account_with_bulk_operations
        
        # Act
        result = service.bulk_disable_all_sources(mock_user.authentication_token)
        
        # Assert
        assert isinstance(result, dict)
        assert result["success"] is True
        assert result["total_requested"] == 3
        assert result["successful_count"] == 3
        assert result["failed_count"] == 0
        assert len(result["disabled_sources"]) == 3
        assert len(result["failed_sources"]) == 0
        assert "Successfully disabled 3 media sources" in result["message"]
        
        # Verify MyPlexAccount was created with correct token
        mock_my_plex_account.assert_called_once_with(token=mock_user.authentication_token)
        
        # Verify onlineMediaSources was called
        mock_account_with_bulk_operations.onlineMediaSources.assert_called_once()  # pyright: ignore[reportAny]
        
        # Verify optOut was called on each source
        opt_outs = mock_account_with_bulk_operations.onlineMediaSources.return_value  # pyright: ignore[reportAny]
        for opt_out in opt_outs:  # pyright: ignore[reportAny]
            opt_out.optOut.assert_called_once()  # pyright: ignore[reportAny]

    @patch("app.services.plex_service.MyPlexAccount")
    def test_bulk_disable_partial_failures(
        self,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser,
        mock_account_with_partial_failures: Mock
    ) -> None:
        """Test bulk disable with partial failures handling."""
        # Arrange
        mock_my_plex_account.return_value = mock_account_with_partial_failures
        
        # Act
        result = service.bulk_disable_all_sources(mock_user.authentication_token)
        
        # Assert
        assert isinstance(result, dict)
        assert result["success"] is False  # Overall operation failed due to partial failures
        assert result["total_requested"] == 3
        assert result["successful_count"] == 2
        assert result["failed_count"] == 1
        assert len(result["disabled_sources"]) == 2
        assert len(result["failed_sources"]) == 1
        assert "Disabled 2 out of 3 media sources" in result["message"]
        
        # Verify the failed source is the first one (spotify)
        assert "spotify" in result["failed_sources"]

    @patch("app.services.plex_service.MyPlexAccount")
    def test_bulk_disable_return_operation_summary(
        self,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser,
        mock_account_with_bulk_operations: Mock
    ) -> None:
        """Test bulk disable returns proper operation summary with success/failure counts."""
        # Arrange
        mock_my_plex_account.return_value = mock_account_with_bulk_operations
        
        # Act
        result = service.bulk_disable_all_sources(mock_user.authentication_token)
        
        # Assert - Verify all required fields are present
        required_fields = [
            "success", "total_requested", "successful_count", "failed_count",
            "disabled_sources", "failed_sources", "message"
        ]
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"
        
        # Verify data types
        assert isinstance(result["success"], bool)
        assert isinstance(result["total_requested"], int)
        assert isinstance(result["successful_count"], int)
        assert isinstance(result["failed_count"], int)
        assert isinstance(result["disabled_sources"], list)
        assert isinstance(result["failed_sources"], list)
        assert isinstance(result["message"], str)
        
        # Verify counts add up correctly
        assert result["successful_count"] + result["failed_count"] == result["total_requested"]

    @patch("app.services.plex_service.MyPlexAccount")
    @patch("app.services.plex_service.time.sleep")  # Mock sleep for testing
    def test_bulk_disable_with_retry_logic(
        self,
        mock_sleep: Mock,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser
    ) -> None:
        """Test bulk disable implements proper retry logic with exponential backoff."""
        # Arrange
        mock_account = Mock()
        mock_opt_out = Mock()
        mock_opt_out.key = "spotify"
        mock_opt_out.value = "opt_in"
        
        # First call fails with BadRequest, second call succeeds
        mock_opt_out.optOut = Mock(side_effect=[BadRequest("Temporary failure"), None])
        mock_account.onlineMediaSources.return_value = [mock_opt_out]  # pyright: ignore[reportAny]
        mock_my_plex_account.return_value = mock_account
        
        # Act
        result = service.bulk_disable_all_sources(mock_user.authentication_token)
        
        # Assert
        assert result["success"] is True
        assert result["successful_count"] == 1
        assert result["failed_count"] == 0
        
        # Verify retry logic was executed
        assert mock_opt_out.optOut.call_count == 2  # pyright: ignore[reportAny]
        mock_sleep.assert_called_once()  # Verify sleep was called for backoff

    def test_bulk_disable_invalid_authentication_token(
        self,
        service: PlexMediaSourceService
    ) -> None:
        """Test bulk disable with invalid authentication token."""
        # Arrange
        invalid_tokens = [None, "", "   ", "  \t\n  "]
        
        for invalid_token in invalid_tokens:
            # Act & Assert
            with pytest.raises(AuthenticationException, match="Invalid authentication token provided"):
                _ = service.bulk_disable_all_sources(invalid_token)

    @patch("app.services.plex_service.MyPlexAccount")
    def test_bulk_disable_plexapi_unauthorized_error(
        self,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser
    ) -> None:
        """Test bulk disable handles PlexAPI unauthorized errors."""
        # Arrange
        mock_my_plex_account.side_effect = Unauthorized("Invalid token")
        
        # Act & Assert
        with pytest.raises(AuthenticationException, match="Authentication failed with provided token"):
            _ = service.bulk_disable_all_sources(mock_user.authentication_token)

    @patch("app.services.plex_service.MyPlexAccount")
    def test_bulk_disable_plexapi_connection_error(
        self,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser
    ) -> None:
        """Test bulk disable handles PlexAPI connection errors."""
        # Arrange
        mock_my_plex_account.side_effect = BadRequest("Connection failed")
        
        # Act & Assert
        with pytest.raises(PlexAPIException, match="Failed to connect to Plex API"):
            _ = service.bulk_disable_all_sources(mock_user.authentication_token)

    @patch("app.services.plex_service.MyPlexAccount")
    def test_bulk_disable_empty_sources_list(
        self,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser
    ) -> None:
        """Test bulk disable with empty media sources list."""
        # Arrange
        mock_account = Mock()
        mock_account.onlineMediaSources.return_value = []  # pyright: ignore[reportAny]
        mock_my_plex_account.return_value = mock_account
        
        # Act
        result = service.bulk_disable_all_sources(mock_user.authentication_token)
        
        # Assert
        assert result["success"] is True
        assert result["total_requested"] == 0
        assert result["successful_count"] == 0
        assert result["failed_count"] == 0
        assert len(result["disabled_sources"]) == 0
        assert len(result["failed_sources"]) == 0
        assert "No media sources found to disable" in result["message"]

    @patch("app.services.plex_service.MyPlexAccount")
    def test_bulk_disable_general_exception_handling(
        self,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser
    ) -> None:
        """Test bulk disable handles general exceptions properly."""
        # Arrange
        mock_my_plex_account.side_effect = Exception("Unexpected error")
        
        # Act & Assert
        with pytest.raises(PlexAPIException, match="Unexpected error during bulk operation"):
            _ = service.bulk_disable_all_sources(mock_user.authentication_token) 


class TestRateLimitingAndErrorHandling(TestPlexMediaSourceService):
    """Test rate limiting and enhanced error handling functionality."""

    @patch("app.services.plex_service.MyPlexAccount")
    def test_handle_plexapi_rate_limits_with_proper_backoff(
        self,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser
    ) -> None:
        """Test handling of PlexAPI rate limits with exponential backoff."""
        from plexapi.exceptions import BadRequest  # pyright: ignore[reportMissingTypeStubs]
        
        # Arrange - Simulate rate limit error (HTTP 429-like behavior)
        rate_limit_error = BadRequest("Rate limit exceeded. Please try again later.")
        mock_my_plex_account.side_effect = rate_limit_error
        
        # Act & Assert
        with pytest.raises(PlexAPIException) as exc_info:
            service.get_media_sources_with_rate_limiting(mock_user.authentication_token)
        
        # Verify the exception was properly wrapped
        assert "Rate limit" in str(exc_info.value)
        assert exc_info.value.original_error == rate_limit_error

    @patch("app.services.plex_service.MyPlexAccount")
    @patch("app.services.plex_service.time.sleep")
    def test_retry_failed_requests_with_exponential_backoff(
        self,
        mock_sleep: Mock,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser
    ) -> None:
        """Test retry logic with exponential backoff for failed requests."""
        from plexapi.exceptions import BadRequest  # pyright: ignore[reportMissingTypeStubs]
        
        # Arrange - Fail first two attempts, succeed on third
        mock_account = Mock()
        mock_account.onlineMediaSources.return_value = []  # pyright: ignore[reportAny]
        
        connection_error = BadRequest("Connection timeout")
        mock_my_plex_account.side_effect = [
            connection_error,  # First attempt fails
            connection_error,  # Second attempt fails  
            mock_account       # Third attempt succeeds
        ]
        
        # Act
        result = service.get_media_sources_with_retry(mock_user.authentication_token)
        
        # Assert
        assert isinstance(result, list)
        assert len(result) == 0  # Empty list from successful call
        
        # Verify exponential backoff was used
        assert mock_sleep.call_count == 2  # Two retries
        # Check exponential backoff delays: 1s, 2s
        expected_delays = [1.0, 2.0]
        actual_delays = [call.args[0] for call in mock_sleep.call_args_list]
        assert actual_delays == expected_delays

    @patch("app.services.plex_service.MyPlexAccount")
    def test_handle_network_timeout_errors(
        self,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser
    ) -> None:
        """Test handling of network timeout errors."""
        import socket
        
        # Arrange - Simulate network timeout
        timeout_error = socket.timeout("Connection timed out")
        mock_my_plex_account.side_effect = timeout_error
        
        # Act & Assert
        with pytest.raises(PlexAPIException) as exc_info:
            service.get_media_sources_with_timeout_handling(mock_user.authentication_token)
        
        # Verify timeout error was properly handled
        assert "timeout" in str(exc_info.value).lower()
        assert exc_info.value.original_error == timeout_error

    @patch("app.services.plex_service.MyPlexAccount")
    @patch("app.services.plex_service.logger")
    def test_log_errors_appropriately_without_exposing_sensitive_data(
        self,
        mock_logger: Mock,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser
    ) -> None:
        """Test that errors are logged securely without exposing sensitive data."""
        from plexapi.exceptions import Unauthorized  # pyright: ignore[reportMissingTypeStubs]
        
        # Arrange - Simulate authentication error with sensitive token in message
        sensitive_token = "secret_token_12345"
        auth_error = Unauthorized(f"Invalid token: {sensitive_token}")
        mock_my_plex_account.side_effect = auth_error
        
        # Act
        with pytest.raises(AuthenticationException):
            service.get_media_sources_with_secure_logging(sensitive_token)
        
        # Assert - Verify logging occurred without sensitive data
        assert mock_logger.error.called
        
        # Check that the logged message doesn't contain the sensitive token
        logged_args = [str(arg) for call in mock_logger.error.call_args_list for arg in call[0]]
        for logged_message in logged_args:
            assert sensitive_token not in logged_message
            assert "***" in logged_message or "[REDACTED]" in logged_message

    @patch("app.services.plex_service.MyPlexAccount")
    @patch("app.services.plex_service.time.sleep")
    def test_rate_limit_backoff_with_jitter(
        self,
        mock_sleep: Mock,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser
    ) -> None:
        """Test rate limit handling with jitter to avoid thundering herd."""
        from plexapi.exceptions import BadRequest  # pyright: ignore[reportMissingTypeStubs]
        
        # Arrange
        rate_limit_error = BadRequest("429 Too Many Requests")
        mock_my_plex_account.side_effect = [
            rate_limit_error,
            rate_limit_error, 
            Mock(onlineMediaSources=Mock(return_value=[]))
        ]
        
        # Act
        result = service.get_media_sources_with_jitter(mock_user.authentication_token)
        
        # Assert
        assert isinstance(result, list)
        assert mock_sleep.call_count == 2
        
        # Verify jitter was applied (delays should vary slightly from base exponential)
        delays = [call.args[0] for call in mock_sleep.call_args_list]
        # Delays should be in reasonable range with jitter
        assert 0.5 <= delays[0] <= 2.5  # Base 1s ± 50% jitter
        assert 1.0 <= delays[1] <= 4.0  # Base 2s ± 50% jitter

    @patch("app.services.plex_service.MyPlexAccount")
    def test_max_retry_limit_enforcement(
        self,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser
    ) -> None:
        """Test that retry attempts respect maximum retry limits."""
        from plexapi.exceptions import BadRequest  # pyright: ignore[reportMissingTypeStubs]
        
        # Arrange - Always fail to test max retries
        connection_error = BadRequest("Connection failed")
        mock_my_plex_account.side_effect = connection_error
        
        # Act & Assert
        with pytest.raises(PlexAPIException):
            service.get_media_sources_with_max_retries(
                mock_user.authentication_token, 
                max_retries=2
            )
        
        # Verify exactly max_retries + 1 attempts were made (initial + retries)
        assert mock_my_plex_account.call_count == 3  # 1 initial + 2 retries

    @patch("app.services.plex_service.MyPlexAccount")
    def test_circuit_breaker_pattern_for_repeated_failures(
        self,
        mock_my_plex_account: Mock,
        service: PlexMediaSourceService,
        mock_user: PlexUser
    ) -> None:
        """Test circuit breaker pattern to prevent cascade failures."""
        from plexapi.exceptions import BadRequest  # pyright: ignore[reportMissingTypeStubs]
        
        # Arrange - Simulate repeated failures to trigger circuit breaker
        connection_error = BadRequest("Service unavailable")
        mock_my_plex_account.side_effect = connection_error
        
        # Act - Make multiple calls to trigger circuit breaker
        for _ in range(5):  # Exceed circuit breaker threshold
            with pytest.raises((PlexAPIException, ConnectionException)):
                service.get_media_sources_with_circuit_breaker(mock_user.authentication_token)
        
        # Next call should fail fast due to circuit breaker
        with pytest.raises(ConnectionException) as exc_info:
            service.get_media_sources_with_circuit_breaker(mock_user.authentication_token)
        
        assert "circuit breaker" in str(exc_info.value).lower() or "service unavailable" in str(exc_info.value).lower() 