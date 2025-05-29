"""
Test cases for authentication request/response schemas.

This module tests the Pydantic models for authentication endpoints,
including OAuth flow schemas, token refresh schemas, and error handling schemas.

Tests follow TDD principles with comprehensive validation testing.
"""

import pytest
from datetime import datetime, timezone
from pydantic import ValidationError

from app.schemas.auth_schemas import (
    OAuthInitiationRequest,
    OAuthInitiationResponse,
    OAuthCallbackRequest,
    OAuthCallbackResponse,
    TokenRefreshRequest,
    TokenRefreshResponse,
    AuthenticationErrorResponse,
    UserInfoResponse,
)


class TestOAuthInitiationRequest:
    """Test cases for OAuth initiation request schema."""

    def test_oauth_initiation_request_valid_data(self) -> None:
        """Test OAuth initiation request with valid data."""
        request_data = {
            "redirect_uri": "https://app.example.com/auth/callback",
            "scopes": ["read", "write"]
        }
        
        request = OAuthInitiationRequest(**request_data)  # pyright: ignore[reportArgumentType]
        
        assert str(request.redirect_uri) == "https://app.example.com/auth/callback"
        assert request.scopes == ["read", "write"]

    def test_oauth_initiation_request_optional_fields(self) -> None:
        """Test OAuth initiation request with optional fields."""
        request_data: dict[str, object] = {}
        
        request = OAuthInitiationRequest(**request_data)  # pyright: ignore[reportArgumentType]
        
        # Should have default values
        assert request.redirect_uri is not None
        assert request.scopes is not None
        assert len(request.scopes) > 0

    def test_oauth_initiation_request_invalid_redirect_uri(self) -> None:
        """Test OAuth initiation request with invalid redirect URI."""
        request_data: dict[str, object] = {
            "redirect_uri": "not-a-valid-url",
            "scopes": ["read"]
        }
        
        with pytest.raises(ValidationError) as exc_info:
            _ = OAuthInitiationRequest(**request_data)  # pyright: ignore[reportArgumentType]
        
        error_str = str(exc_info.value)
        assert "redirect_uri" in error_str

    def test_oauth_initiation_request_empty_scopes(self) -> None:
        """Test OAuth initiation request with empty scopes."""
        request_data: dict[str, object] = {
            "redirect_uri": "https://app.example.com/auth/callback",
            "scopes": []
        }
        
        with pytest.raises(ValidationError) as exc_info:
            _ = OAuthInitiationRequest(**request_data)  # pyright: ignore[reportArgumentType]
        
        error_str = str(exc_info.value)
        assert "scopes" in error_str

    def test_oauth_initiation_request_localhost_redirect_uri(self) -> None:
        """Test OAuth initiation request with localhost redirect URI (development)."""
        request_data = {
            "redirect_uri": "http://localhost:3000/auth/callback",
            "scopes": ["read"]
        }
        
        request = OAuthInitiationRequest(**request_data)  # pyright: ignore[reportArgumentType]
        
        assert str(request.redirect_uri) == "http://localhost:3000/auth/callback"


class TestOAuthInitiationResponse:
    """Test cases for OAuth initiation response schema."""

    def test_oauth_initiation_response_valid_data(self) -> None:
        """Test OAuth initiation response with valid data."""
        response_data = {
            "oauth_url": "https://app.plex.tv/auth/#!?clientID=test&code=abc123",
            "state": "secure-state-parameter-xyz789-that-is-at-least-32-characters",
            "code": "auth-code-12345",
            "expires_at": datetime.now(timezone.utc)
        }
        
        response = OAuthInitiationResponse(**response_data)  # pyright: ignore[reportArgumentType]
        
        assert str(response.oauth_url) == "https://app.plex.tv/auth/#!?clientID=test&code=abc123"
        assert response.state == "secure-state-parameter-xyz789-that-is-at-least-32-characters"
        assert response.expires_at is not None

    def test_oauth_initiation_response_missing_oauth_url(self) -> None:
        """Test OAuth initiation response with missing OAuth URL."""
        response_data: dict[str, object] = {
            "state": "secure-state-parameter",
            "expires_at": datetime.now(timezone.utc)
        }
        
        with pytest.raises(ValidationError) as exc_info:
            _ = OAuthInitiationResponse(**response_data)  # pyright: ignore[reportArgumentType]
        
        error_str = str(exc_info.value)
        assert "oauth_url" in error_str

    def test_oauth_initiation_response_missing_state(self) -> None:
        """Test OAuth initiation response with missing state parameter."""
        response_data: dict[str, object] = {
            "oauth_url": "https://app.plex.tv/auth/#!?clientID=test&code=abc123",
            "expires_at": datetime.now(timezone.utc)
        }
        
        with pytest.raises(ValidationError) as exc_info:
            _ = OAuthInitiationResponse(**response_data)  # pyright: ignore[reportArgumentType]
        
        error_str = str(exc_info.value)
        assert "state" in error_str

    def test_oauth_initiation_response_invalid_oauth_url(self) -> None:
        """Test OAuth initiation response with invalid OAuth URL."""
        response_data: dict[str, object] = {
            "oauth_url": "not-a-valid-url",
            "state": "secure-state-parameter",
            "expires_at": datetime.now(timezone.utc)
        }
        
        with pytest.raises(ValidationError) as exc_info:
            _ = OAuthInitiationResponse(**response_data)  # pyright: ignore[reportArgumentType]
        
        error_str = str(exc_info.value)
        assert "oauth_url" in error_str


class TestOAuthCallbackRequest:
    """Test cases for OAuth callback request schema."""

    def test_oauth_callback_request_valid_data(self) -> None:
        """Test OAuth callback request with valid data."""
        request_data = {
            "code": "auth-code-12345",
            "state": "secure-state-parameter-xyz789-that-is-at-least-32-characters"
        }
        
        request = OAuthCallbackRequest(**request_data)
        
        assert request.code == "auth-code-12345"
        assert request.state == "secure-state-parameter-xyz789-that-is-at-least-32-characters"

    def test_oauth_callback_request_missing_code(self) -> None:
        """Test OAuth callback request with missing authorization code."""
        request_data: dict[str, object] = {
            "state": "secure-state-parameter"
        }
        
        with pytest.raises(ValidationError) as exc_info:
            _ = OAuthCallbackRequest(**request_data)  # pyright: ignore[reportArgumentType]
        
        error_str = str(exc_info.value)
        assert "code" in error_str

    def test_oauth_callback_request_missing_state(self) -> None:
        """Test OAuth callback request with missing state parameter."""
        request_data: dict[str, object] = {
            "code": "auth-code-12345"
        }
        
        with pytest.raises(ValidationError) as exc_info:
            _ = OAuthCallbackRequest(**request_data)  # pyright: ignore[reportArgumentType]
        
        error_str = str(exc_info.value)
        assert "state" in error_str

    def test_oauth_callback_request_empty_code(self) -> None:
        """Test OAuth callback request with empty authorization code."""
        request_data = {
            "code": "",
            "state": "secure-state-parameter"
        }
        
        with pytest.raises(ValidationError) as exc_info:
            _ = OAuthCallbackRequest(**request_data)
        
        error_str = str(exc_info.value)
        assert "code" in error_str

    def test_oauth_callback_request_empty_state(self) -> None:
        """Test OAuth callback request with empty state parameter."""
        request_data = {
            "code": "auth-code-12345",
            "state": ""
        }
        
        with pytest.raises(ValidationError) as exc_info:
            _ = OAuthCallbackRequest(**request_data)
        
        error_str = str(exc_info.value)
        assert "state" in error_str

    def test_oauth_callback_request_whitespace_values(self) -> None:
        """Test OAuth callback request with whitespace-only values."""
        request_data = {
            "code": "   ",
            "state": "   "
        }
        
        with pytest.raises(ValidationError) as exc_info:
            _ = OAuthCallbackRequest(**request_data)
        
        error_str = str(exc_info.value)
        assert "code" in error_str or "state" in error_str


class TestOAuthCallbackResponse:
    """Test cases for OAuth callback response schema."""

    def test_oauth_callback_response_valid_data(self) -> None:
        """Test OAuth callback response with valid data."""
        response_data = {
            "access_token": "plex-access-token-12345",
            "token_type": "Bearer",
            "expires_in": 3600,
            "user": {
                "id": 12345,
                "uuid": "user-uuid-abcd1234",
                "username": "testuser",
                "email": "test@example.com",
                "authentication_token": "plex-auth-token-67890"
            }
        }
        
        response = OAuthCallbackResponse(**response_data)  # pyright: ignore[reportArgumentType]
        
        assert response.access_token == "plex-access-token-12345"
        assert response.token_type == "Bearer"
        assert response.expires_in == 3600
        assert response.user.username == "testuser"

    def test_oauth_callback_response_missing_access_token(self) -> None:
        """Test OAuth callback response with missing access token."""
        response_data: dict[str, object] = {
            "token_type": "Bearer",
            "expires_in": 3600,
            "user": {
                "id": 12345,
                "uuid": "user-uuid-abcd1234",
                "username": "testuser",
                "email": "test@example.com",
                "authentication_token": "plex-auth-token-67890"
            }
        }
        
        with pytest.raises(ValidationError) as exc_info:
            _ = OAuthCallbackResponse(**response_data)  # pyright: ignore[reportArgumentType]
        
        error_str = str(exc_info.value)
        assert "access_token" in error_str

    def test_oauth_callback_response_invalid_token_type(self) -> None:
        """Test OAuth callback response with invalid token type."""
        response_data: dict[str, object] = {
            "access_token": "plex-access-token-12345",
            "token_type": "InvalidType",
            "expires_in": 3600,
            "user": {
                "id": 12345,
                "uuid": "user-uuid-abcd1234",
                "username": "testuser",
                "email": "test@example.com",
                "authentication_token": "plex-auth-token-67890"
            }
        }
        
        with pytest.raises(ValidationError) as exc_info:
            _ = OAuthCallbackResponse(**response_data)  # pyright: ignore[reportArgumentType]
        
        error_str = str(exc_info.value)
        assert "token_type" in error_str

    def test_oauth_callback_response_negative_expires_in(self) -> None:
        """Test OAuth callback response with negative expires_in value."""
        response_data: dict[str, object] = {
            "access_token": "plex-access-token-12345",
            "token_type": "Bearer",
            "expires_in": -100,
            "user": {
                "id": 12345,
                "uuid": "user-uuid-abcd1234",
                "username": "testuser",
                "email": "test@example.com",
                "authentication_token": "plex-auth-token-67890"
            }
        }
        
        with pytest.raises(ValidationError) as exc_info:
            _ = OAuthCallbackResponse(**response_data)  # pyright: ignore[reportArgumentType]
        
        error_str = str(exc_info.value)
        assert "expires_in" in error_str


class TestTokenRefreshRequest:
    """Test cases for token refresh request schema."""

    def test_token_refresh_request_valid_data(self) -> None:
        """Test token refresh request with valid data."""
        request_data = {
            "refresh_token": "refresh-token-abcdef123456"
        }
        
        request = TokenRefreshRequest(**request_data)
        
        assert request.refresh_token == "refresh-token-abcdef123456"

    def test_token_refresh_request_missing_refresh_token(self) -> None:
        """Test token refresh request with missing refresh token."""
        request_data: dict[str, object] = {}
        
        with pytest.raises(ValidationError) as exc_info:
            _ = TokenRefreshRequest(**request_data)  # pyright: ignore[reportArgumentType]
        
        error_str = str(exc_info.value)
        assert "refresh_token" in error_str

    def test_token_refresh_request_empty_refresh_token(self) -> None:
        """Test token refresh request with empty refresh token."""
        request_data = {
            "refresh_token": ""
        }
        
        with pytest.raises(ValidationError) as exc_info:
            _ = TokenRefreshRequest(**request_data)
        
        error_str = str(exc_info.value)
        assert "refresh_token" in error_str

    def test_token_refresh_request_whitespace_refresh_token(self) -> None:
        """Test token refresh request with whitespace-only refresh token."""
        request_data = {
            "refresh_token": "   "
        }
        
        with pytest.raises(ValidationError) as exc_info:
            _ = TokenRefreshRequest(**request_data)
        
        error_str = str(exc_info.value)
        assert "refresh_token" in error_str


class TestTokenRefreshResponse:
    """Test cases for token refresh response schema."""

    def test_token_refresh_response_valid_data(self) -> None:
        """Test token refresh response with valid data."""
        response_data = {
            "access_token": "new-access-token-12345",
            "token_type": "Bearer",
            "expires_in": 7200
        }
        
        response = TokenRefreshResponse(**response_data)  # pyright: ignore[reportArgumentType]
        
        assert response.access_token == "new-access-token-12345"
        assert response.token_type == "Bearer"
        assert response.expires_in == 7200

    def test_token_refresh_response_optional_refresh_token(self) -> None:
        """Test token refresh response with optional refresh token."""
        response_data = {
            "access_token": "new-access-token-12345",
            "token_type": "Bearer",
            "expires_in": 7200,
            "refresh_token": "new-refresh-token-67890"
        }
        
        response = TokenRefreshResponse(**response_data)  # pyright: ignore[reportArgumentType]
        
        assert response.access_token == "new-access-token-12345"
        assert response.refresh_token == "new-refresh-token-67890"

    def test_token_refresh_response_missing_access_token(self) -> None:
        """Test token refresh response with missing access token."""
        response_data: dict[str, object] = {
            "token_type": "Bearer",
            "expires_in": 7200
        }
        
        with pytest.raises(ValidationError) as exc_info:
            _ = TokenRefreshResponse(**response_data)  # pyright: ignore[reportArgumentType]
        
        error_str = str(exc_info.value)
        assert "access_token" in error_str


class TestAuthenticationErrorResponse:
    """Test cases for authentication error response schema."""

    def test_authentication_error_response_valid_data(self) -> None:
        """Test authentication error response with valid data."""
        response_data = {
            "error": "invalid_request",
            "error_description": "The request is missing a required parameter",
            "error_code": "AUTH_001"
        }
        
        response = AuthenticationErrorResponse(**response_data)
        
        assert response.error == "invalid_request"
        assert response.error_description == "The request is missing a required parameter"
        assert response.error_code == "AUTH_001"

    def test_authentication_error_response_minimal_data(self) -> None:
        """Test authentication error response with minimal required data."""
        response_data = {
            "error": "invalid_grant"
        }
        
        response = AuthenticationErrorResponse(**response_data)
        
        assert response.error == "invalid_grant"
        assert response.error_description is None
        assert response.error_code is None

    def test_authentication_error_response_missing_error(self) -> None:
        """Test authentication error response with missing error field."""
        response_data: dict[str, object] = {
            "error_description": "Something went wrong"
        }
        
        with pytest.raises(ValidationError) as exc_info:
            _ = AuthenticationErrorResponse(**response_data)  # pyright: ignore[reportArgumentType]
        
        error_str = str(exc_info.value)
        assert "error" in error_str

    def test_authentication_error_response_empty_error(self) -> None:
        """Test authentication error response with empty error field."""
        response_data = {
            "error": ""
        }
        
        with pytest.raises(ValidationError) as exc_info:
            _ = AuthenticationErrorResponse(**response_data)
        
        error_str = str(exc_info.value)
        assert "error" in error_str

    def test_authentication_error_response_standard_oauth_errors(self) -> None:
        """Test authentication error response with standard OAuth error codes."""
        standard_errors = [
            "invalid_request",
            "unauthorized_client", 
            "access_denied",
            "unsupported_response_type",
            "invalid_scope",
            "server_error",
            "temporarily_unavailable",
            "invalid_grant",
            "invalid_client"
        ]
        
        for error_code in standard_errors:
            response_data = {
                "error": error_code,
                "error_description": f"Description for {error_code}"
            }
            
            response = AuthenticationErrorResponse(**response_data)
            assert response.error == error_code


class TestUserInfoResponse:
    """Test cases for user info response schema."""

    def test_user_info_response_valid_data(self) -> None:
        """Test user info response with valid data."""
        response_data = {
            "user": {
                "id": 12345,
                "uuid": "user-uuid-abcd1234",
                "username": "testuser",
                "email": "test@example.com",
                "authentication_token": "plex-auth-token-67890"
            },
            "authenticated": True,
            "session_expires_at": datetime.now(timezone.utc)
        }
        
        response = UserInfoResponse(**response_data)  # pyright: ignore[reportArgumentType]
        
        assert response.user is not None
        assert response.user.username == "testuser"
        assert response.authenticated is True
        assert response.session_expires_at is not None

    def test_user_info_response_unauthenticated(self) -> None:
        """Test user info response for unauthenticated user."""
        response_data = {
            "user": None,
            "authenticated": False,
            "session_expires_at": None
        }
        
        response = UserInfoResponse(**response_data)  # pyright: ignore[reportArgumentType]
        
        assert response.user is None
        assert response.authenticated is False
        assert response.session_expires_at is None

    def test_user_info_response_missing_authenticated_field(self) -> None:
        """Test user info response with missing authenticated field."""
        response_data: dict[str, object] = {
            "user": {
                "id": 12345,
                "uuid": "user-uuid-abcd1234",
                "username": "testuser",
                "email": "test@example.com",
                "authentication_token": "plex-auth-token-67890"
            }
        }
        
        with pytest.raises(ValidationError) as exc_info:
            _ = UserInfoResponse(**response_data)  # pyright: ignore[reportArgumentType]
        
        error_str = str(exc_info.value)
        assert "authenticated" in error_str


class TestAuthSchemasImmutability:
    """Test cases for ensuring authentication schemas are immutable."""

    def test_oauth_initiation_request_immutable(self) -> None:
        """Test OAuth initiation request is immutable after creation."""
        request = OAuthInitiationRequest(
            redirect_uri="https://app.example.com/auth/callback",  # pyright: ignore[reportArgumentType]
            scopes=["read"]
        )
        
        with pytest.raises(ValidationError):
            request.redirect_uri = "https://different.example.com/callback"  # pyright: ignore[reportAttributeAccessIssue]

    def test_oauth_callback_response_immutable(self) -> None:
        """Test OAuth callback response is immutable after creation."""
        response = OAuthCallbackResponse(
            access_token="token-12345",
            token_type="Bearer",
            expires_in=3600,
            user={  # pyright: ignore[reportArgumentType]
                "id": 12345,
                "uuid": "user-uuid",
                "username": "testuser",
                "email": "test@example.com",
                "authentication_token": "auth-token"
            }
        )
        
        with pytest.raises(ValidationError):
            response.access_token = "different-token"

    def test_authentication_error_response_immutable(self) -> None:
        """Test authentication error response is immutable after creation."""
        response = AuthenticationErrorResponse(
            error="invalid_request",
            error_description="Test error"
        )
        
        with pytest.raises(ValidationError):
            response.error = "different_error"


class TestAuthSchemasPrivacyCompliance:
    """Test cases for ensuring authentication schemas are privacy-compliant."""

    def test_no_extra_fields_allowed(self) -> None:
        """Test that extra fields are not allowed to maintain data minimization."""
        request_data: dict[str, object] = {
            "redirect_uri": "https://app.example.com/auth/callback",
            "scopes": ["read"],
            "extra_field": "should_not_be_allowed"
        }
        
        with pytest.raises(ValidationError) as exc_info:
            _ = OAuthInitiationRequest(**request_data)  # pyright: ignore[reportArgumentType]
        
        error_str = str(exc_info.value)
        assert "extra_field" in error_str or "forbidden" in error_str.lower()

    def test_user_data_minimal_in_responses(self) -> None:
        """Test that user data in responses contains only essential information."""
        response_data = {
            "access_token": "token-12345",
            "token_type": "Bearer", 
            "expires_in": 3600,
            "user": {
                "id": 12345,
                "uuid": "user-uuid",
                "username": "testuser",
                "email": "test@example.com",
                "authentication_token": "auth-token"
            }
        }
        
        response = OAuthCallbackResponse(**response_data)  # pyright: ignore[reportArgumentType]
        
        # Verify only essential user fields are present
        user_dict = response.user.model_dump()
        essential_fields = {"id", "uuid", "username", "email", "authentication_token"}
        
        # Check that all required fields are present
        for field in essential_fields:
            assert field in user_dict 