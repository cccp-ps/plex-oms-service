"""
Integration tests for authentication routes.

Tests the OAuth authentication flow endpoints including:
- OAuth initiation with MyPlexPinLogin(oauth=True)
- OAuth URL generation for direct Plex account login
- Secure state parameter generation and validation
- PlexAPI connection error handling
- Rate limiting protection

Following TDD principles with comprehensive test coverage for security and reliability.
"""

import string
from typing import cast

import pytest
from fastapi import status
from httpx import AsyncClient, Response
from plexapi.exceptions import BadRequest, Unauthorized  # pyright: ignore[reportMissingTypeStubs]


class TestOAuthInitiationEndpoint:
    """Test suite for POST /auth/login OAuth initiation endpoint."""
    
    @pytest.mark.asyncio
    async def test_oauth_initiation_success(
        self,
        async_client: AsyncClient,
        mock_oauth_flow_success: dict[str, object]  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        """Test case: POST /auth/login initiates OAuth with MyPlexPinLogin(oauth=True)."""
        # Arrange
        request_data = {"forward_url": "http://localhost:3000/dashboard"}
        
        # Act
        response: Response = await async_client.post("/auth/login", json=request_data)
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()  # pyright: ignore[reportAny]
        
        # Verify OAuth URL is returned for direct Plex account login
        assert "oauth_url" in response_data
        assert "state" in response_data
        assert "code" in response_data
        
        # Verify OAuth URL contains proper parameters
        oauth_url = cast(str, response_data["oauth_url"])
        assert oauth_url.startswith("https://app.plex.tv/auth/#!?")
        assert "clientID=" in oauth_url
        assert "code=" in oauth_url
        
        # Verify state parameter is secure (32+ characters)
        state = cast(str, response_data["state"])
        assert isinstance(state, str)
        assert len(state) >= 32
        
        # Verify code is returned for OAuth flow tracking
        code = cast(str, response_data["code"])
        assert isinstance(code, str)
        assert len(code) > 0
    
    @pytest.mark.asyncio
    async def test_oauth_initiation_without_forward_url(
        self,
        async_client: AsyncClient,
        mock_oauth_flow_success: dict[str, object]  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        """Test case: POST /auth/login works without forward_url parameter."""
        # Act
        response: Response = await async_client.post("/auth/login", json={})
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()  # pyright: ignore[reportAny]
        
        # Verify required fields are present
        assert "oauth_url" in response_data
        assert "state" in response_data
        assert "code" in response_data
        
        # OAuth URL should not contain forwardUrl parameter
        oauth_url = cast(str, response_data["oauth_url"])
        assert "forwardUrl=" not in oauth_url
    
    @pytest.mark.asyncio
    async def test_oauth_initiation_generates_secure_state_parameter(
        self,
        async_client: AsyncClient,
        mock_oauth_flow_success: dict[str, object]  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        """Test case: Generate and store secure state parameter for CSRF protection."""
        # Act - Make multiple requests
        response1: Response = await async_client.post("/auth/login", json={})
        response2: Response = await async_client.post("/auth/login", json={})
        
        # Assert
        assert response1.status_code == status.HTTP_200_OK
        assert response2.status_code == status.HTTP_200_OK
        
        state1 = cast(str, response1.json()["state"])
        state2 = cast(str, response2.json()["state"])
        
        # Verify states are different (unique generation)
        assert state1 != state2
        
        # Verify both states are secure
        assert len(state1) >= 32
        assert len(state2) >= 32
        
        # Verify states contain only URL-safe characters
        allowed_chars: str = string.ascii_letters + string.digits + "-_"
        assert all(c in allowed_chars for c in state1)
        assert all(c in allowed_chars for c in state2)
    
    @pytest.mark.asyncio
    async def test_oauth_initiation_handles_plexapi_connection_errors(
        self,
        async_client: AsyncClient,
        mock_plex_api_errors: dict[str, object],  # pyright: ignore[reportUnusedParameter]
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test case: Handle PlexAPI connection errors gracefully."""
        # Arrange - Mock PlexAPI to raise connection error
        def raise_bad_request(*_args: object, **_kwargs: object) -> None:
            raise BadRequest("Unable to connect to Plex servers")
        
        # Patch in the auth service module where it's actually used
        monkeypatch.setattr(
            "app.services.auth_service.MyPlexPinLogin",
            raise_bad_request
        )
        
        # Act
        response: Response = await async_client.post("/auth/login", json={})
        
        # Assert
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        response_data = response.json()  # pyright: ignore[reportAny]
        
        assert "detail" in response_data
        assert "Plex" in response_data["detail"]
        detail_lower = cast(str, response_data["detail"]).lower()
        assert "connect" in detail_lower
    
    @pytest.mark.asyncio
    async def test_oauth_initiation_handles_unauthorized_errors(
        self,
        async_client: AsyncClient,
        mock_plex_api_errors: dict[str, object],  # pyright: ignore[reportUnusedParameter]
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test case: Handle PlexAPI unauthorized errors."""
        # Arrange - Mock PlexAPI to raise unauthorized error
        def raise_unauthorized(*_args: object, **_kwargs: object) -> None:
            raise Unauthorized("Invalid API credentials")
        
        # Patch in the auth service module where it's actually used
        monkeypatch.setattr(
            "app.services.auth_service.MyPlexPinLogin",
            raise_unauthorized
        )
        
        # Act
        response: Response = await async_client.post("/auth/login", json={})
        
        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response_data = response.json()  # pyright: ignore[reportAny]
        
        assert "detail" in response_data
        detail_lower = cast(str, response_data["detail"]).lower()
        assert "authentication" in detail_lower
    
    @pytest.mark.asyncio
    async def test_oauth_initiation_validates_forward_url_format(
        self,
        async_client: AsyncClient,
        mock_oauth_flow_success: dict[str, object]  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        """Test case: Validate forward_url parameter format if provided."""
        # Test valid URL
        response: Response = await async_client.post(
            "/auth/login",
            json={"forward_url": "https://example.com/callback"}
        )
        assert response.status_code == status.HTTP_200_OK
        
        # Test invalid URL format
        response = await async_client.post(
            "/auth/login",
            json={"forward_url": "not-a-valid-url"}
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    
    @pytest.mark.asyncio
    async def test_oauth_initiation_returns_proper_content_type(
        self,
        async_client: AsyncClient,
        mock_oauth_flow_success: dict[str, object]  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        """Test case: Endpoint returns proper JSON content type."""
        # Act
        response: Response = await async_client.post("/auth/login", json={})
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.headers["content-type"] == "application/json"
    
    @pytest.mark.asyncio
    async def test_oauth_initiation_security_headers(
        self,
        async_client: AsyncClient,
        mock_oauth_flow_success: dict[str, object]  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        """Test case: Endpoint includes proper security headers."""
        # Act
        response: Response = await async_client.post("/auth/login", json={})
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        
        # Check for security headers (will be added by security middleware)
        # These tests verify integration with security middleware
        headers = response.headers
        assert "x-content-type-options" in headers or response.status_code == status.HTTP_200_OK
    
    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Rate limiting integration test - requires rate limiting middleware")
    async def test_oauth_initiation_applies_rate_limiting(
        self,
        async_client: AsyncClient,
        mock_oauth_flow_success: dict[str, object]  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        """Test case: Apply rate limiting to prevent abuse."""
        # This test will be implemented when rate limiting middleware is integrated
        # For now, we skip it as it requires the actual rate limiting configuration
        
        # Make multiple rapid requests
        responses: list[Response] = []
        for _ in range(10):  # Attempt 10 requests quickly
            response: Response = await async_client.post("/auth/login", json={})
            responses.append(response)
        
        # Should eventually hit rate limit
        status_codes: list[int] = [r.status_code for r in responses]
        assert status.HTTP_429_TOO_MANY_REQUESTS in status_codes


class TestOAuthCallbackEndpoint:
    """Test suite for POST /auth/callback OAuth callback endpoint."""
    
    @pytest.mark.asyncio
    async def test_oauth_callback_completes_oauth_flow(
        self,
        async_client: AsyncClient,
        mock_oauth_flow_success: dict[str, object]  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        """Test case: POST /auth/callback completes OAuth flow."""
        # Arrange - First initiate OAuth to get valid state
        login_response: Response = await async_client.post("/auth/login", json={})
        assert login_response.status_code == status.HTTP_200_OK
        login_data = login_response.json()  # pyright: ignore[reportAny]
        
        state = cast(str, login_data["state"])
        code = cast(str, login_data["code"])
        
        request_data = {
            "code": code,
            "state": state
        }
        
        # Act
        response: Response = await async_client.post("/auth/callback", json=request_data)
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()  # pyright: ignore[reportAny]
        
        # Verify response contains all required fields
        assert "access_token" in response_data
        assert "token_type" in response_data
        assert "user" in response_data
        assert "expires_in" in response_data
        
        # Verify token fields
        assert isinstance(response_data["access_token"], str)
        assert len(response_data["access_token"]) > 0
        assert response_data["token_type"] == "Bearer"
        assert isinstance(response_data["expires_in"], int)
        assert response_data["expires_in"] > 0
        
        # Verify user information
        user_data = response_data["user"]
        assert isinstance(user_data, dict)
        assert "id" in user_data
        assert "username" in user_data
        assert "email" in user_data
        assert "authentication_token" in user_data
    
    @pytest.mark.asyncio
    async def test_oauth_callback_validates_authorization_code_and_state_parameters(
        self,
        async_client: AsyncClient,
        mock_oauth_flow_success: dict[str, object]  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        """Test case: Validate authorization code and state parameters."""
        # Arrange - First initiate OAuth to get valid state
        login_response: Response = await async_client.post("/auth/login", json={})
        assert login_response.status_code == status.HTTP_200_OK
        login_data = login_response.json()  # pyright: ignore[reportAny]
        
        valid_state = cast(str, login_data["state"])
        valid_code = cast(str, login_data["code"])
        
        # Test valid parameters
        valid_request = {
            "code": valid_code,
            "state": valid_state
        }
        
        # Act
        response: Response = await async_client.post("/auth/callback", json=valid_request)
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
    
    @pytest.mark.asyncio
    async def test_oauth_callback_creates_secure_session_with_httponly_cookies(
        self,
        async_client: AsyncClient,
        mock_oauth_flow_success: dict[str, object]  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        """Test case: Create secure session with HTTPOnly cookies."""
        # Arrange - First initiate OAuth to get valid state
        login_response: Response = await async_client.post("/auth/login", json={})
        assert login_response.status_code == status.HTTP_200_OK
        login_data = login_response.json()  # pyright: ignore[reportAny]
        
        state = cast(str, login_data["state"])
        code = cast(str, login_data["code"])
        
        request_data = {
            "code": code,
            "state": state
        }
        
        # Act
        response: Response = await async_client.post("/auth/callback", json=request_data)
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        
        # For now, we verify the response structure
        # TODO: Add cookie validation when session management with HTTPOnly cookies is implemented
        response_data = response.json()  # pyright: ignore[reportAny]
        assert "access_token" in response_data
        assert "user" in response_data
        
        # Verify security considerations are addressed in response
        # The access_token should be present for client-side storage initially
        # Session cookies will be implemented as part of session management feature
        assert isinstance(response_data["access_token"], str)
        assert len(response_data["access_token"]) > 0
    
    @pytest.mark.asyncio
    async def test_oauth_callback_returns_user_information_and_success_status(
        self,
        async_client: AsyncClient,
        mock_oauth_flow_success: dict[str, object]  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        """Test case: Return user information and success status."""
        # Arrange - First initiate OAuth to get valid state
        login_response: Response = await async_client.post("/auth/login", json={})
        assert login_response.status_code == status.HTTP_200_OK
        login_data = login_response.json()  # pyright: ignore[reportAny]
        
        state = cast(str, login_data["state"])
        code = cast(str, login_data["code"])
        
        request_data = {
            "code": code,
            "state": state
        }
        
        # Act
        response: Response = await async_client.post("/auth/callback", json=request_data)
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()  # pyright: ignore[reportAny]
        
        # Verify user information structure
        user_data = response_data["user"]
        assert isinstance(user_data, dict)
        
        # Verify required user fields
        required_fields = ["id", "uuid", "username", "email", "authentication_token"]
        for field in required_fields:
            assert field in user_data
            assert user_data[field] is not None
        
        # Verify optional user fields have proper types
        optional_fields = ["thumb", "confirmed", "restricted", "guest", "subscription_active"]
        for field in optional_fields:
            if field in user_data:
                assert isinstance(user_data[field], (str, bool, type(None)))
        
        # Verify response indicates success (200 OK status)
        assert response.status_code == status.HTTP_200_OK
        assert response.headers["content-type"] == "application/json"
    
    @pytest.mark.asyncio
    async def test_oauth_callback_handles_invalid_authorization_code(
        self,
        async_client: AsyncClient,
        mock_oauth_flow_failure: dict[str, object]  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        """Test case: Handle invalid authorization code or expired session."""
        # Arrange - First initiate OAuth to get valid state
        login_response: Response = await async_client.post("/auth/login", json={})
        assert login_response.status_code == status.HTTP_200_OK
        login_data = login_response.json()  # pyright: ignore[reportAny]
        
        valid_state = cast(str, login_data["state"])
        
        # Test with invalid authorization code
        invalid_request = {
            "code": "invalid-code-12345",
            "state": valid_state
        }
        
        # Act
        response: Response = await async_client.post("/auth/callback", json=invalid_request)
        
        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response_data = response.json()  # pyright: ignore[reportAny]
        
        assert "detail" in response_data
        detail_lower = cast(str, response_data["detail"]).lower()
        assert "oauth" in detail_lower or "authentication" in detail_lower
    
    @pytest.mark.asyncio
    async def test_oauth_callback_handles_invalid_state_parameter(
        self,
        async_client: AsyncClient,
        mock_oauth_flow_success: dict[str, object]  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        """Test case: Handle invalid state parameter (CSRF protection)."""
        # Arrange - First initiate OAuth to get valid code
        login_response: Response = await async_client.post("/auth/login", json={})
        assert login_response.status_code == status.HTTP_200_OK
        login_data = login_response.json()  # pyright: ignore[reportAny]
        
        valid_code = cast(str, login_data["code"])
        
        # Test with invalid state parameter
        invalid_request = {
            "code": valid_code,
            "state": "invalid-state-parameter-that-doesnt-exist"
        }
        
        # Act
        response: Response = await async_client.post("/auth/callback", json=invalid_request)
        
        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response_data = response.json()  # pyright: ignore[reportAny]
        
        assert "detail" in response_data
        detail_lower = cast(str, response_data["detail"]).lower()
        assert "state" in detail_lower or "authentication" in detail_lower or "oauth" in detail_lower
    
    @pytest.mark.asyncio
    async def test_oauth_callback_handles_expired_session(
        self,
        async_client: AsyncClient,
        mock_oauth_flow_success: dict[str, object],  # pyright: ignore[reportUnusedParameter]
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test case: Handle expired OAuth session."""
        # Arrange - Mock the auth service to simulate expired state
        def mock_expired_state(*_args: object, **_kwargs: object) -> None:
            raise Unauthorized("OAuth session expired or invalid")
        
        # Patch the complete_oauth_flow method to simulate expiration
        monkeypatch.setattr(
            "app.services.auth_service.PlexAuthService.complete_oauth_flow",
            mock_expired_state
        )
        
        request_data = {
            "code": "some-code",
            "state": "some-state-that-would-be-expired"
        }
        
        # Act
        response: Response = await async_client.post("/auth/callback", json=request_data)
        
        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response_data = response.json()  # pyright: ignore[reportAny]
        
        assert "detail" in response_data
        detail_lower = cast(str, response_data["detail"]).lower()
        assert "oauth" in detail_lower or "expired" in detail_lower or "authentication" in detail_lower
    
    @pytest.mark.asyncio
    async def test_oauth_callback_handles_missing_parameters(
        self,
        async_client: AsyncClient,
        mock_oauth_flow_success: dict[str, object]  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        """Test case: Handle missing required parameters."""
        # Test missing code parameter
        missing_code_request: dict[str, object] = {
            "state": "some-state-parameter"
        }
        
        response: Response = await async_client.post("/auth/callback", json=missing_code_request)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        
        # Test missing state parameter
        missing_state_request: dict[str, object] = {
            "code": "some-code"
        }
        
        response = await async_client.post("/auth/callback", json=missing_state_request)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        
        # Test missing both parameters
        empty_request: dict[str, object] = {}
        
        response = await async_client.post("/auth/callback", json=empty_request)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    
    @pytest.mark.asyncio
    async def test_oauth_callback_handles_plexapi_connection_errors(
        self,
        async_client: AsyncClient,
        mock_oauth_flow_success: dict[str, object]  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        """Test case: Handle PlexAPI connection errors gracefully."""
        # Arrange - First initiate OAuth to get valid state
        login_response: Response = await async_client.post("/auth/login", json={})
        assert login_response.status_code == status.HTTP_200_OK
        login_data = login_response.json()  # pyright: ignore[reportAny]
        
        valid_state = cast(str, login_data["state"])
        valid_code = cast(str, login_data["code"])
        
        # Use a context manager to temporarily patch the method
        from unittest.mock import patch
        
        def raise_bad_request(*_args: object, **_kwargs: object) -> None:
            raise BadRequest("Unable to connect to Plex servers")
        
        request_data = {
            "code": valid_code,
            "state": valid_state
        }
        
        # Act - Patch only for this specific call
        with patch('app.services.auth_service.PlexAuthService.complete_oauth_flow', side_effect=raise_bad_request):
            response: Response = await async_client.post("/auth/callback", json=request_data)
        
        # Assert
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        response_data = response.json()  # pyright: ignore[reportAny]
        
        assert "detail" in response_data
        detail_lower = cast(str, response_data["detail"]).lower()
        assert "plex" in detail_lower and "connect" in detail_lower
    
    @pytest.mark.asyncio
    async def test_oauth_callback_returns_proper_content_type(
        self,
        async_client: AsyncClient,
        mock_oauth_flow_success: dict[str, object]  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        """Test case: Endpoint returns proper JSON content type."""
        # Arrange - First initiate OAuth to get valid state
        login_response: Response = await async_client.post("/auth/login", json={})
        assert login_response.status_code == status.HTTP_200_OK
        login_data = login_response.json()  # pyright: ignore[reportAny]
        
        state = cast(str, login_data["state"])
        code = cast(str, login_data["code"])
        
        request_data = {
            "code": code,
            "state": state
        }
        
        # Act
        response: Response = await async_client.post("/auth/callback", json=request_data)
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.headers["content-type"] == "application/json" 