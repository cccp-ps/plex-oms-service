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
import time
from typing import cast

from app.services.auth_service import PlexAuthService


@pytest.fixture
def mock_settings() -> MagicMock:
    """Create mock settings for testing."""
    settings = MagicMock()
    settings.plex_client_id = "test-client-id"
    # Create properly structured mock for plex_client_secret
    mock_secret = MagicMock()
    mock_secret.get_secret_value.return_value = "test-secret"  # pyright: ignore[reportAny]
    settings.plex_client_secret = mock_secret
    settings.oauth_redirect_uri = "http://localhost:8000/auth/callback"
    return settings


class TestPlexAuthServiceOAuthInitiation:
    """Test OAuth flow initiation functionality."""

    def test_initiate_oauth_flow_success(self, mock_settings: MagicMock) -> None:
        """Test successful OAuth flow initiation using MyPlexPinLogin(oauth=True)."""
        # Arrange
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin_login_class:
            mock_instance = MagicMock()
            # Create properly typed mock function
            oauth_url_mock = MagicMock(return_value="https://app.plex.tv/auth/#!?clientID=test&code=test-code-12345")
            mock_instance.oauthUrl = oauth_url_mock
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
            oauth_url_mock.assert_called_once()

    def test_generate_secure_state_parameter(self, mock_settings: MagicMock) -> None:
        """Test that secure state parameters are generated for CSRF protection."""
        # Arrange
        auth_service = PlexAuthService(settings=mock_settings)
        
        # Act - Test private methods for completeness
        state1 = auth_service._generate_state_parameter()  # pyright: ignore[reportPrivateUsage]
        state2 = auth_service._generate_state_parameter()  # pyright: ignore[reportPrivateUsage]
        
        # Assert
        assert isinstance(state1, str)
        assert isinstance(state2, str)
        assert len(state1) >= 32
        assert len(state2) >= 32
        assert state1 != state2  # Each state should be unique

    def test_oauth_flow_with_forward_url(self, mock_settings: MagicMock) -> None:
        """Test OAuth flow initiation with custom forward URL."""
        # Arrange
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin_login_class:
            mock_instance = MagicMock()
            forward_url = "https://example.com/callback"
            expected_oauth_url = f"https://app.plex.tv/auth/#!?clientID=test&code=test-code-12345&forwardUrl={forward_url}"
            # Create properly typed mock function
            oauth_url_mock = MagicMock(return_value=expected_oauth_url)
            mock_instance.oauthUrl = oauth_url_mock
            mock_instance.code = "test-code-12345"
            mock_pin_login_class.return_value = mock_instance
            
            auth_service = PlexAuthService(settings=mock_settings)
            
            # Act
            result = auth_service.initiate_oauth_flow(forward_url=forward_url)
            
            # Assert
            assert result["oauth_url"] == expected_oauth_url
            mock_pin_login_class.assert_called_once_with(oauth=True)
            oauth_url_mock.assert_called_once_with(forwardUrl=forward_url)

    def test_handle_plexapi_connection_errors(self, mock_settings: MagicMock) -> None:
        """Test handling of PlexAPI connection errors during OAuth initiation."""
        # Arrange
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin_login_class:
            mock_instance = MagicMock()
            # Create properly typed mock function with side effect
            oauth_url_mock = MagicMock(side_effect=BadRequest("Connection failed"))
            mock_instance.oauthUrl = oauth_url_mock
            mock_pin_login_class.return_value = mock_instance
            
            auth_service = PlexAuthService(settings=mock_settings)
            
            # Act & Assert
            with pytest.raises(BadRequest, match="Connection failed"):
                _ = auth_service.initiate_oauth_flow()  # Fix reportUnusedCallResult

    def test_handle_unauthorized_errors(self, mock_settings: MagicMock) -> None:
        """Test handling of unauthorized errors during OAuth initiation."""
        # Arrange
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin_login_class:
            mock_instance = MagicMock()
            # Create properly typed mock function with side effect
            oauth_url_mock = MagicMock(side_effect=Unauthorized("Invalid credentials"))
            mock_instance.oauthUrl = oauth_url_mock
            mock_pin_login_class.return_value = mock_instance
            
            auth_service = PlexAuthService(settings=mock_settings)
            
            # Act & Assert
            with pytest.raises(Unauthorized, match="Invalid credentials"):
                _ = auth_service.initiate_oauth_flow()  # Fix reportUnusedCallResult

    def test_return_oauth_url_for_direct_plex_login(self, mock_settings: MagicMock) -> None:
        """Test that OAuth URL is returned for direct Plex account login."""
        # Arrange
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin_login_class:
            mock_instance = MagicMock()
            expected_oauth_url = "https://app.plex.tv/auth/#!?clientID=test&code=test-code-12345"
            # Create properly typed mock function
            oauth_url_mock = MagicMock(return_value=expected_oauth_url)
            mock_instance.oauthUrl = oauth_url_mock
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
            # Create properly typed mock function
            oauth_url_mock = MagicMock(return_value="https://app.plex.tv/auth/#!?test")
            mock_instance.oauthUrl = oauth_url_mock
            mock_instance.code = "test-code"
            mock_pin_login_class.return_value = mock_instance
            
            auth_service = PlexAuthService(settings=mock_settings)
            _ = auth_service.initiate_oauth_flow()  # Fix reportUnusedCallResult
            
            # Assert
            mock_pin_login_class.assert_called_once_with(oauth=True)

    def test_oauth_initiation_includes_client_configuration(self, mock_settings: MagicMock) -> None:
        """Test that OAuth initiation includes proper client configuration from settings."""
        # Arrange
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin_login_class:
            mock_instance = MagicMock()
            # Create properly typed mock function
            oauth_url_mock = MagicMock(return_value="https://app.plex.tv/auth/#!?clientID=test&code=test-code-12345")
            mock_instance.oauthUrl = oauth_url_mock
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
        
        # Act - Test private method for completeness
        valid_state = "a" * 32  # 32 character string
        invalid_state_short = "short"
        invalid_state_empty = ""
        
        # Assert
        assert auth_service._validate_state_parameter(valid_state) is True  # pyright: ignore[reportPrivateUsage]
        assert auth_service._validate_state_parameter(invalid_state_short) is False  # pyright: ignore[reportPrivateUsage]
        assert auth_service._validate_state_parameter(invalid_state_empty) is False  # pyright: ignore[reportPrivateUsage]
        assert auth_service._validate_state_parameter(None) is False  # pyright: ignore[reportPrivateUsage]

    def test_oauth_flow_stores_state_securely(self, mock_settings: MagicMock) -> None:
        """Test that OAuth flow stores state parameters securely."""
        # Arrange
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin_login_class:
            mock_instance = MagicMock()
            # Create properly typed mock function
            oauth_url_mock = MagicMock(return_value="https://app.plex.tv/auth/#!?test")
            mock_instance.oauthUrl = oauth_url_mock
            mock_instance.code = "test-code"
            mock_pin_login_class.return_value = mock_instance
            
            auth_service = PlexAuthService(settings=mock_settings)
            
            # Act
            result = auth_service.initiate_oauth_flow()
            
            # Assert
            state = result["state"]
            assert state in auth_service._pending_states  # pyright: ignore[reportPrivateUsage]
            assert state in auth_service._state_timestamps  # pyright: ignore[reportPrivateUsage]
            assert isinstance(auth_service._state_timestamps[state], float)  # pyright: ignore[reportPrivateUsage]

    def test_multiple_concurrent_oauth_flows(self, mock_settings: MagicMock) -> None:
        """Test handling multiple concurrent OAuth flows with different states."""
        # Arrange
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin_login_class:
            mock_instance = MagicMock()
            # Create properly typed mock function
            oauth_url_mock = MagicMock(return_value="https://app.plex.tv/auth/#!?test")
            mock_instance.oauthUrl = oauth_url_mock
            mock_instance.code = "test-code"
            mock_pin_login_class.return_value = mock_instance
            
            auth_service = PlexAuthService(settings=mock_settings)
            
            # Act - Initiate multiple OAuth flows
            result1 = auth_service.initiate_oauth_flow()
            result2 = auth_service.initiate_oauth_flow()
            result3 = auth_service.initiate_oauth_flow()
            
            # Assert
            states = [result1["state"], result2["state"], result3["state"]]
            
            # All states should be unique
            assert len(set(states)) == 3
            
            # All states should be stored
            for state in states:
                assert state in auth_service._pending_states  # pyright: ignore[reportPrivateUsage]
                assert state in auth_service._state_timestamps  # pyright: ignore[reportPrivateUsage]


class TestPlexAuthServiceOAuthCompletion:
    """Test OAuth flow completion functionality."""

    def test_complete_oauth_flow_with_valid_authorization_code(self, mock_settings: MagicMock) -> None:
        """Test completing OAuth flow with valid authorization code."""
        # Arrange
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin_login_class, \
             patch('app.services.auth_service.MyPlexAccount') as mock_account_class:
            
            # Set up MyPlexPinLogin mock
            mock_pin_login = MagicMock()
            mock_pin_login.code = "test-code-12345"
            mock_pin_login.waitForLogin.return_value = True  # pyright: ignore[reportAny]
            mock_pin_login.finished = True
            mock_pin_login.username = "testuser"
            mock_pin_login.token = "test-token-success"
            mock_pin_login_class.return_value = mock_pin_login
            
            # Set up MyPlexAccount mock
            mock_account = MagicMock()
            mock_account.username = "testuser"
            mock_account.email = "test@example.com"
            mock_account.id = 12345
            mock_account.uuid = "test-uuid-12345"
            mock_account.authenticationToken = "test-token-success"
            mock_account_class.return_value = mock_account
            
            auth_service = PlexAuthService(settings=mock_settings)
            valid_state = auth_service._generate_state_parameter()  # pyright: ignore[reportPrivateUsage]
            auth_service._pending_states.add(valid_state)  # pyright: ignore[reportPrivateUsage]
            auth_service._state_timestamps[valid_state] = time.time()  # pyright: ignore[reportPrivateUsage]
            
            # Act
            result = auth_service.complete_oauth_flow(
                code="test-code-12345",
                state=valid_state
            )
            
            # Assert
            assert result is not None
            assert "access_token" in result
            assert "user" in result
            assert result["access_token"] == "test-token-success"
            user_data = result["user"]
            assert isinstance(user_data, dict)
            assert user_data["username"] == "testuser"
            assert user_data["email"] == "test@example.com"
            
            # Verify state was consumed (removed from pending states)
            assert valid_state not in auth_service._pending_states  # pyright: ignore[reportPrivateUsage]

    def test_validate_state_parameter_for_csrf_protection(self, mock_settings: MagicMock) -> None:
        """Test state parameter validation for CSRF protection."""
        # Arrange
        auth_service = PlexAuthService(settings=mock_settings)
        valid_state = auth_service._generate_state_parameter()  # pyright: ignore[reportPrivateUsage]
        auth_service._pending_states.add(valid_state)  # pyright: ignore[reportPrivateUsage]
        auth_service._state_timestamps[valid_state] = time.time()  # pyright: ignore[reportPrivateUsage]
        
        invalid_state = "invalid-state-not-generated"
        
        # Act & Assert - Valid state should pass validation
        assert auth_service._validate_state_parameter_for_completion(valid_state) is True  # pyright: ignore[reportPrivateUsage]
        
        # Invalid state should fail validation
        assert auth_service._validate_state_parameter_for_completion(invalid_state) is False  # pyright: ignore[reportPrivateUsage]
        
        # Empty state should fail validation
        assert auth_service._validate_state_parameter_for_completion("") is False  # pyright: ignore[reportPrivateUsage]
        
        # None state should fail validation
        assert auth_service._validate_state_parameter_for_completion(None) is False  # pyright: ignore[reportPrivateUsage]

    def test_retrieve_myplexaccount_with_oauth_token(self, mock_settings: MagicMock) -> None:
        """Test retrieving MyPlexAccount with OAuth token."""
        # Arrange
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin_login_class, \
             patch('app.services.auth_service.MyPlexAccount') as mock_account_class:
            
            mock_pin_login = MagicMock()
            mock_pin_login.code = "test-code-12345"
            mock_pin_login.waitForLogin.return_value = True  # pyright: ignore[reportAny]
            mock_pin_login.finished = True
            mock_pin_login.token = "oauth-token-12345"
            mock_pin_login_class.return_value = mock_pin_login
            
            mock_account = MagicMock()
            mock_account.username = "testuser"
            mock_account.authenticationToken = "oauth-token-12345"
            mock_account_class.return_value = mock_account
            
            auth_service = PlexAuthService(settings=mock_settings)
            valid_state = auth_service._generate_state_parameter()  # pyright: ignore[reportPrivateUsage]
            auth_service._pending_states.add(valid_state)  # pyright: ignore[reportPrivateUsage]
            auth_service._state_timestamps[valid_state] = time.time()  # pyright: ignore[reportPrivateUsage]
            
            # Act
            result = auth_service.complete_oauth_flow(
                code="test-code-12345",
                state=valid_state
            )
            
            # Assert
            assert result["access_token"] == "oauth-token-12345"
            mock_account_class.assert_called_once_with(token="oauth-token-12345")

    def test_handle_invalid_authorization_code_scenarios(self, mock_settings: MagicMock) -> None:
        """Test handling of invalid authorization code scenarios."""
        # Arrange
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin_login_class:
            mock_pin_login = MagicMock()
            mock_pin_login.code = "test-code-12345"
            mock_pin_login.waitForLogin.side_effect = Unauthorized("Invalid authorization code")  # pyright: ignore[reportAny]
            mock_pin_login.finished = False
            mock_pin_login.token = None
            mock_pin_login_class.return_value = mock_pin_login
            
            auth_service = PlexAuthService(settings=mock_settings)
            valid_state = auth_service._generate_state_parameter()  # pyright: ignore[reportPrivateUsage]
            auth_service._pending_states.add(valid_state)  # pyright: ignore[reportPrivateUsage]
            auth_service._state_timestamps[valid_state] = time.time()  # pyright: ignore[reportPrivateUsage]
            
            # Act & Assert
            with pytest.raises(Unauthorized, match="Invalid authorization code"):
                _ = auth_service.complete_oauth_flow(
                    code="invalid-code",
                    state=valid_state
                )

    def test_handle_expired_oauth_session_scenarios(self, mock_settings: MagicMock) -> None:
        """Test handling of expired OAuth session scenarios."""
        # Arrange
        auth_service = PlexAuthService(settings=mock_settings)
        
        # Create an expired state (older than TTL)
        expired_state = auth_service._generate_state_parameter()  # pyright: ignore[reportPrivateUsage]
        auth_service._pending_states.add(expired_state)  # pyright: ignore[reportPrivateUsage]
        
        # Simulate expired timestamp (more than 600 seconds ago)
        auth_service._state_timestamps[expired_state] = time.time() - 700  # pyright: ignore[reportPrivateUsage]
        
        # Act & Assert
        with pytest.raises(Unauthorized, match="OAuth session expired or invalid"):
            _ = auth_service.complete_oauth_flow(
                code="test-code-12345",
                state=expired_state
            )

    def test_complete_oauth_flow_with_invalid_state_parameter(self, mock_settings: MagicMock) -> None:
        """Test completing OAuth flow with invalid state parameter (CSRF protection)."""
        # Arrange
        auth_service = PlexAuthService(settings=mock_settings)
        invalid_state = "malicious-state-parameter"
        
        # Act & Assert
        with pytest.raises(Unauthorized, match="Invalid state parameter"):
            _ = auth_service.complete_oauth_flow(
                code="test-code-12345",
                state=invalid_state
            )

    def test_complete_oauth_flow_cleans_up_used_state(self, mock_settings: MagicMock) -> None:
        """Test that completing OAuth flow cleans up the used state parameter."""
        # Arrange
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin_login_class, \
             patch('app.services.auth_service.MyPlexAccount') as mock_account_class:
            
            mock_pin_login = MagicMock()
            mock_pin_login.code = "test-code-12345"
            mock_pin_login.waitForLogin.return_value = True  # pyright: ignore[reportAny]
            mock_pin_login.finished = True
            mock_pin_login.token = "test-token"
            mock_pin_login_class.return_value = mock_pin_login
            
            mock_account = MagicMock()
            mock_account.authenticationToken = "test-token"
            mock_account_class.return_value = mock_account
            
            auth_service = PlexAuthService(settings=mock_settings)
            valid_state = auth_service._generate_state_parameter()  # pyright: ignore[reportPrivateUsage]
            auth_service._pending_states.add(valid_state)  # pyright: ignore[reportPrivateUsage]
            auth_service._state_timestamps[valid_state] = time.time()  # pyright: ignore[reportPrivateUsage]
            
            # Verify state is present before completion
            assert valid_state in auth_service._pending_states  # pyright: ignore[reportPrivateUsage]
            assert valid_state in auth_service._state_timestamps  # pyright: ignore[reportPrivateUsage]
            
            # Act
            _ = auth_service.complete_oauth_flow(
                code="test-code-12345",
                state=valid_state
            )
            
            # Assert state is cleaned up after completion
            assert valid_state not in auth_service._pending_states  # pyright: ignore[reportPrivateUsage]
            assert valid_state not in auth_service._state_timestamps  # pyright: ignore[reportPrivateUsage]


class TestPlexAuthServiceTokenValidationAndRefresh:
    """Test token validation and refresh functionality."""

    def test_validate_existing_token_with_myplexaccount_success(self, mock_settings: MagicMock) -> None:
        """Test validating an existing token with MyPlexAccount successfully."""
        # Arrange
        with patch('app.services.auth_service.MyPlexAccount') as mock_account_class:
            mock_account = MagicMock()
            mock_account.username = "testuser"
            mock_account.email = "test@example.com"
            mock_account.id = 12345
            mock_account.uuid = "test-uuid-12345"
            mock_account.authenticationToken = "valid-token-12345"
            mock_account.confirmed = True
            mock_account.restricted = False
            mock_account.guest = False
            mock_account_class.return_value = mock_account
            
            auth_service = PlexAuthService(settings=mock_settings)
            
            # Act
            result = auth_service.validate_token("valid-token-12345")
            
            # Assert
            assert result is not None
            assert cast(bool, result["valid"]) is True
            assert "user" in result
            user_data = cast(dict[str, object], result["user"])
            assert user_data["username"] == "testuser"
            assert user_data["email"] == "test@example.com"
            assert user_data["authentication_token"] == "valid-token-12345"
            
            # Verify MyPlexAccount was called with the token
            mock_account_class.assert_called_once_with(token="valid-token-12345")

    def test_validate_existing_token_with_myplexaccount_invalid_token(self, mock_settings: MagicMock) -> None:
        """Test validating an invalid token with MyPlexAccount."""
        # Arrange
        with patch('app.services.auth_service.MyPlexAccount') as mock_account_class:
            mock_account_class.side_effect = Unauthorized("Invalid token")
            
            auth_service = PlexAuthService(settings=mock_settings)
            
            # Act
            result = auth_service.validate_token("invalid-token-12345")
            
            # Assert
            assert result is not None
            assert cast(bool, result["valid"]) is False
            assert "error" in result
            error_msg = cast(str, result["error"])
            assert "Invalid token" in error_msg
            
            # Verify MyPlexAccount was called with the token
            mock_account_class.assert_called_once_with(token="invalid-token-12345")

    def test_validate_existing_token_with_connection_error(self, mock_settings: MagicMock) -> None:
        """Test validating token when PlexAPI connection fails."""
        # Arrange
        with patch('app.services.auth_service.MyPlexAccount') as mock_account_class:
            mock_account_class.side_effect = BadRequest("Connection failed")
            
            auth_service = PlexAuthService(settings=mock_settings)
            
            # Act
            result = auth_service.validate_token("test-token-12345")
            
            # Assert
            assert result is not None
            assert cast(bool, result["valid"]) is False
            assert "error" in result
            error_msg = cast(str, result["error"])
            assert "Connection failed" in error_msg

    def test_handle_expired_tokens_gracefully(self, mock_settings: MagicMock) -> None:
        """Test handling expired tokens gracefully."""
        # Arrange
        with patch('app.services.auth_service.MyPlexAccount') as mock_account_class:
            # Simulate expired token scenario
            mock_account_class.side_effect = Unauthorized("Token expired")
            
            auth_service = PlexAuthService(settings=mock_settings)
            
            # Act
            result = auth_service.validate_token("expired-token-12345")
            
            # Assert
            assert result is not None
            assert cast(bool, result["valid"]) is False
            assert "error" in result
            error_msg = cast(str, result["error"])
            assert "Token expired" in error_msg
            assert cast(bool, result.get("expired")) is True

    def test_refresh_token_if_possible_success(self, mock_settings: MagicMock) -> None:
        """Test refreshing token if possible (MyPlexAccount provides new token)."""
        # Arrange
        with patch('app.services.auth_service.MyPlexAccount') as mock_account_class:
            # Mock a valid account that represents a successful "refresh"
            # (In PlexAPI, refresh means the token is still valid)
            refreshed_account = MagicMock()
            refreshed_account.username = "testuser"
            refreshed_account.email = "test@example.com"
            refreshed_account.id = 12345
            refreshed_account.uuid = "test-uuid-12345"
            refreshed_account.authenticationToken = "refreshed-token-12345"
            refreshed_account.confirmed = True
            refreshed_account.restricted = False
            refreshed_account.guest = False
            
            mock_account_class.return_value = refreshed_account
            
            auth_service = PlexAuthService(settings=mock_settings)
            
            # Act
            result = auth_service.refresh_token("valid-token")
            
            # Assert
            assert result is not None
            assert cast(bool, result["success"]) is True
            assert "access_token" in result
            assert cast(str, result["access_token"]) == "refreshed-token-12345"
            assert "user" in result
            user_data = cast(dict[str, object], result["user"])
            assert user_data["username"] == "testuser"
            assert user_data["authentication_token"] == "refreshed-token-12345"

    def test_refresh_token_if_possible_fails(self, mock_settings: MagicMock) -> None:
        """Test refresh token when refresh is not possible."""
        # Arrange
        with patch('app.services.auth_service.MyPlexAccount') as mock_account_class:
            mock_account_class.side_effect = Unauthorized("Cannot refresh token")
            
            auth_service = PlexAuthService(settings=mock_settings)
            
            # Act
            result = auth_service.refresh_token("unrefreshable-token")
            
            # Assert
            assert result is not None
            assert cast(bool, result["success"]) is False
            assert "error" in result
            error_msg = cast(str, result["error"])
            assert "Cannot refresh token" in error_msg

    def test_clear_invalid_sessions_after_validation_failure(self, mock_settings: MagicMock) -> None:
        """Test clearing invalid sessions after validation failure."""
        # Arrange
        auth_service = PlexAuthService(settings=mock_settings)
        
        # Simulate some session data that should be cleared
        session_data: dict[str, object] = {
            "user_id": "12345",
            "token": "invalid-token",
            "expires_at": float(time.time() + 3600)
        }
        
        # Act
        cleared_session = auth_service.clear_invalid_session(session_data)
        
        # Assert
        assert cleared_session is not None
        assert cast(bool, cleared_session["cleared"]) is True
        assert "session_id" in cleared_session
        assert cast(str, cleared_session["reason"]) == "invalid_token"

    def test_clear_invalid_sessions_with_expired_timestamp(self, mock_settings: MagicMock) -> None:
        """Test clearing sessions that have expired based on timestamp."""
        # Arrange
        auth_service = PlexAuthService(settings=mock_settings)
        
        # Simulate expired session data
        expired_session_data: dict[str, object] = {
            "user_id": "12345",
            "token": "expired-token",
            "expires_at": float(time.time() - 3600)  # Expired 1 hour ago
        }
        
        # Act
        cleared_session = auth_service.clear_invalid_session(expired_session_data)
        
        # Assert
        assert cleared_session is not None
        assert cast(bool, cleared_session["cleared"]) is True
        assert cast(str, cleared_session["reason"]) == "session_expired"

    def test_validate_token_with_empty_or_none_token(self, mock_settings: MagicMock) -> None:
        """Test validating token with empty or None token."""
        # Arrange
        auth_service = PlexAuthService(settings=mock_settings)
        
        # Act & Assert - None token
        result_none = auth_service.validate_token(None)
        assert cast(bool, result_none["valid"]) is False
        assert "error" in result_none
        error_msg_none = cast(str, result_none["error"])
        assert "Token is required" in error_msg_none
        
        # Act & Assert - Empty token
        result_empty = auth_service.validate_token("")
        assert cast(bool, result_empty["valid"]) is False
        assert "error" in result_empty
        error_msg_empty = cast(str, result_empty["error"])
        assert "Token is required" in error_msg_empty

    def test_validate_token_with_malformed_token(self, mock_settings: MagicMock) -> None:
        """Test validating token with malformed token format."""
        # Arrange
        auth_service = PlexAuthService(settings=mock_settings)
        
        # Act & Assert - Malformed token (too short)
        result_short = auth_service.validate_token("abc")
        assert cast(bool, result_short["valid"]) is False
        assert "error" in result_short
        error_msg_short = cast(str, result_short["error"])
        assert "Invalid token format" in error_msg_short
        
        # Act & Assert - Malformed token (invalid characters)
        result_invalid = auth_service.validate_token("invalid@token#format!")
        assert cast(bool, result_invalid["valid"]) is False
        assert "error" in result_invalid
        error_msg_invalid = cast(str, result_invalid["error"])
        assert "Invalid token format" in error_msg_invalid