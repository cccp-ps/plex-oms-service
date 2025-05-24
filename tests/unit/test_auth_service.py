"""
Unit tests for PlexAuthService OAuth flow functionality.

This module tests the authentication service with a focus on:
- OAuth flow initiation using MyPlexPinLogin(oauth=True)
- Secure state parameter generation 
- PlexAPI connection error handling
- OAuth URL generation for direct Plex account login
- Ensuring oauth=True is always used for better UX

Following TDD principles with comprehensive test coverage.
"""

import pytest
from unittest.mock import MagicMock, patch
from plexapi.exceptions import BadRequest, Unauthorized  # pyright: ignore[reportMissingTypeStubs]

from app.services.auth_service import PlexAuthService


@pytest.fixture
def mock_settings() -> MagicMock:
    """Create mock settings for testing."""
    settings = MagicMock()
    settings.plex_client_id = "test-client-id"
    settings.plex_client_secret.get_secret_value.return_value = "test-secret"
    settings.oauth_redirect_uri = "http://localhost:8000/auth/callback"
    return settings


class TestPlexAuthServiceOAuthInitiation:
    """Test OAuth flow initiation functionality."""

    def test_initiate_oauth_flow_success(self, mock_plex_pin_login: MagicMock, mock_settings: MagicMock) -> None:
        """Test successful OAuth flow initiation using MyPlexPinLogin(oauth=True)."""
        # Arrange
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin_login_class:
            mock_instance = MagicMock()
            mock_instance.oauthUrl.return_value = "https://app.plex.tv/auth/#!?clientID=test&code=test-code-12345"
            mock_instance.code = "test-code-12345"
            mock_pin_login_class.return_value = mock_instance
            
            auth_service = PlexAuthService(settings=mock_settings)
            
            # Act
            result = auth_service.initiate_oauth_flow()
            
            # Assert
            assert result is not None
            assert "oauth_url" in result
            assert "state" in result
            assert "code" in result
            assert result["oauth_url"] == "https://app.plex.tv/auth/#!?clientID=test&code=test-code-12345"
            assert isinstance(result["state"], str)
            assert len(result["state"]) >= 32  # Secure state parameter
            assert result["code"] == "test-code-12345"
            
            # Verify MyPlexPinLogin was called with oauth=True
            mock_pin_login_class.assert_called_once_with(oauth=True)
            mock_instance.oauthUrl.assert_called_once()

    def test_generate_secure_state_parameter(self, mock_settings: MagicMock) -> None:
        """Test that secure state parameters are generated for CSRF protection."""
        # Arrange
        auth_service = PlexAuthService(settings=mock_settings)
        
        # Act
        state1 = auth_service._generate_state_parameter()
        state2 = auth_service._generate_state_parameter()
        
        # Assert
        assert isinstance(state1, str)
        assert isinstance(state2, str)
        assert len(state1) >= 32
        assert len(state2) >= 32
        assert state1 != state2  # Each state should be unique

    def test_oauth_flow_with_forward_url(self, mock_plex_pin_login: MagicMock, mock_settings: MagicMock) -> None:
        """Test OAuth flow initiation with custom forward URL."""
        # Arrange
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin_login_class:
            mock_instance = MagicMock()
            forward_url = "https://example.com/callback"
            expected_oauth_url = f"https://app.plex.tv/auth/#!?clientID=test&code=test-code-12345&forwardUrl={forward_url}"
            mock_instance.oauthUrl.return_value = expected_oauth_url
            mock_instance.code = "test-code-12345"
            mock_pin_login_class.return_value = mock_instance
            
            auth_service = PlexAuthService(settings=mock_settings)
            
            # Act
            result = auth_service.initiate_oauth_flow(forward_url=forward_url)
            
            # Assert
            assert result["oauth_url"] == expected_oauth_url
            mock_pin_login_class.assert_called_once_with(oauth=True)
            mock_instance.oauthUrl.assert_called_once_with(forwardUrl=forward_url)

    def test_handle_plexapi_connection_errors(self, mock_plex_pin_login: MagicMock, mock_settings: MagicMock) -> None:
        """Test handling of PlexAPI connection errors during OAuth initiation."""
        # Arrange
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin_login_class:
            mock_instance = MagicMock()
            mock_instance.oauthUrl.side_effect = BadRequest("Connection failed")
            mock_pin_login_class.return_value = mock_instance
            
            auth_service = PlexAuthService(settings=mock_settings)
            
            # Act & Assert
            with pytest.raises(BadRequest, match="Connection failed"):
                auth_service.initiate_oauth_flow()

    def test_handle_unauthorized_errors(self, mock_plex_pin_login: MagicMock, mock_settings: MagicMock) -> None:
        """Test handling of unauthorized errors during OAuth initiation."""
        # Arrange
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin_login_class:
            mock_instance = MagicMock()
            mock_instance.oauthUrl.side_effect = Unauthorized("Invalid credentials")
            mock_pin_login_class.return_value = mock_instance
            
            auth_service = PlexAuthService(settings=mock_settings)
            
            # Act & Assert
            with pytest.raises(Unauthorized, match="Invalid credentials"):
                auth_service.initiate_oauth_flow()

    def test_return_oauth_url_for_direct_plex_login(self, mock_plex_pin_login: MagicMock, mock_settings: MagicMock) -> None:
        """Test that OAuth URL is returned for direct Plex account login."""
        # Arrange
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin_login_class:
            mock_instance = MagicMock()
            expected_oauth_url = "https://app.plex.tv/auth/#!?clientID=test&code=test-code-12345"
            mock_instance.oauthUrl.return_value = expected_oauth_url
            mock_instance.code = "test-code-12345"
            mock_pin_login_class.return_value = mock_instance
            
            auth_service = PlexAuthService(settings=mock_settings)
            
            # Act
            result = auth_service.initiate_oauth_flow()
            
            # Assert
            assert result["oauth_url"].startswith("https://app.plex.tv/auth/")
            assert "clientID" in result["oauth_url"]
            assert "code" in result["oauth_url"]

    def test_ensure_oauth_true_always_used(self, mock_settings: MagicMock) -> None:
        """Test that oauth=True is always used for better user experience."""
        # Arrange & Act
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin_login_class:
            mock_instance = MagicMock()
            mock_instance.oauthUrl.return_value = "https://app.plex.tv/auth/#!?test"
            mock_instance.code = "test-code"
            mock_pin_login_class.return_value = mock_instance
            
            auth_service = PlexAuthService(settings=mock_settings)
            auth_service.initiate_oauth_flow()
            
            # Assert
            mock_pin_login_class.assert_called_once_with(oauth=True)

    def test_oauth_initiation_includes_client_configuration(self, mock_settings: MagicMock) -> None:
        """Test that OAuth initiation includes proper client configuration from settings."""
        # Arrange
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin_login_class:
            mock_instance = MagicMock()
            mock_instance.oauthUrl.return_value = "https://app.plex.tv/auth/#!?clientID=test&code=test-code-12345"
            mock_instance.code = "test-code-12345"
            mock_pin_login_class.return_value = mock_instance
            
            auth_service = PlexAuthService(settings=mock_settings)
            
            # Act
            result = auth_service.initiate_oauth_flow()
            
            # Assert - Verify the OAuth URL contains configuration from settings
            oauth_url = result["oauth_url"]
            assert "clientID" in oauth_url
            # Note: The actual client ID will be injected by PlexAPI based on headers

    def test_state_parameter_validation_helper(self, mock_settings: MagicMock) -> None:
        """Test helper method for validating state parameters."""
        # Arrange
        auth_service = PlexAuthService(settings=mock_settings)
        valid_state = auth_service._generate_state_parameter()
        invalid_state = "short"
        
        # Act & Assert
        assert auth_service._validate_state_parameter(valid_state) is True
        assert auth_service._validate_state_parameter(invalid_state) is False
        assert auth_service._validate_state_parameter("") is False
        assert auth_service._validate_state_parameter(None) is False  # pyright: ignore[reportArgumentType]

    def test_oauth_flow_stores_state_securely(self, mock_settings: MagicMock) -> None:
        """Test that OAuth flow stores state parameter securely for later validation."""
        # Arrange
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin_login_class:
            mock_instance = MagicMock()
            mock_instance.oauthUrl.return_value = "https://app.plex.tv/auth/#!?clientID=test&code=test-code-12345"
            mock_instance.code = "test-code-12345"
            mock_pin_login_class.return_value = mock_instance
            
            auth_service = PlexAuthService(settings=mock_settings)
            
            # Act
            result = auth_service.initiate_oauth_flow()
            
            # Assert
            state = result["state"]
            assert auth_service._validate_state_parameter(state) is True
            # Verify state is stored for later CSRF validation
            assert hasattr(auth_service, '_pending_states')
            assert state in auth_service._pending_states

    def test_multiple_concurrent_oauth_flows(self, mock_settings: MagicMock) -> None:
        """Test handling of multiple concurrent OAuth flows with different state parameters."""
        # Arrange
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin_login_class:
            # Create different mock instances for each call
            mock_instance1 = MagicMock()
            mock_instance1.oauthUrl.return_value = "https://app.plex.tv/auth/#!?clientID=test&code=test-code-1"
            mock_instance1.code = "test-code-1"
            
            mock_instance2 = MagicMock()
            mock_instance2.oauthUrl.return_value = "https://app.plex.tv/auth/#!?clientID=test&code=test-code-2"
            mock_instance2.code = "test-code-2"
            
            # Configure side_effect to return different instances on each call
            mock_pin_login_class.side_effect = [mock_instance1, mock_instance2]
            
            auth_service = PlexAuthService(settings=mock_settings)
            
            # Act
            result1 = auth_service.initiate_oauth_flow()
            result2 = auth_service.initiate_oauth_flow()
            
            # Assert
            assert result1["state"] != result2["state"]
            assert result1["code"] != result2["code"]  # Different PIN login instances
            assert auth_service._validate_state_parameter(result1["state"]) is True
            assert auth_service._validate_state_parameter(result2["state"]) is True 