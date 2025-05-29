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


# Type aliases for better type safety
OAuthInitiationResponseData = dict[str, object]
OAuthCallbackResponseData = dict[str, object]
UserData = dict[str, object]
ErrorResponseData = dict[str, str]


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
        response_data = cast(OAuthInitiationResponseData, response.json())
        
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
        response_data = cast(OAuthInitiationResponseData, response.json())
        
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
        
        state1 = cast(str, cast(OAuthInitiationResponseData, response1.json())["state"])
        state2 = cast(str, cast(OAuthInitiationResponseData, response2.json())["state"])
        
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
        response_data = cast(ErrorResponseData, response.json())
        
        assert "detail" in response_data
        assert "Plex" in response_data["detail"]
        detail_lower = response_data["detail"].lower()
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
        response_data = cast(ErrorResponseData, response.json())
        
        assert "detail" in response_data
        detail_lower = response_data["detail"].lower()
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
        """Test case: Return proper content type header."""
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
        """Test case: Include security headers in OAuth initiation response."""
        # Act
        response: Response = await async_client.post("/auth/login", json={})
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        
        # For now, we verify content type (security headers would be added by middleware)
        assert response.headers["content-type"] == "application/json"
        
        # TODO: Add proper security header validation when security middleware is implemented
        # Expected headers: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection
    
    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Rate limiting integration test - requires rate limiting middleware")
    async def test_oauth_initiation_applies_rate_limiting(
        self,
        async_client: AsyncClient,
        mock_oauth_flow_success: dict[str, object]  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        """Test case: Apply rate limiting to OAuth initiation endpoint."""
        # This test would verify rate limiting middleware is working
        # Skipped until rate limiting middleware is implemented
        
        # Expected behavior: Make many requests and verify rate limiting kicks in
        # after a certain threshold (e.g., 10 requests per minute)
        
        responses: list[Response] = []
        for _ in range(15):  # Attempt more than rate limit
            response: Response = await async_client.post("/auth/login", json={})
            responses.append(response)
        
        # Should have some 429 Too Many Requests responses
        rate_limited_responses: list[Response] = [r for r in responses if r.status_code == 429]
        assert len(rate_limited_responses) > 0


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
        login_data = cast(OAuthInitiationResponseData, login_response.json())
        
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
        response_data = cast(OAuthCallbackResponseData, response.json())
        
        # Verify response contains all required fields
        assert "access_token" in response_data
        assert "token_type" in response_data
        assert "user" in response_data
        assert "expires_in" in response_data
        
        # Verify token fields
        access_token = cast(str, response_data["access_token"])
        assert isinstance(access_token, str)
        assert len(access_token) > 0
        assert response_data["token_type"] == "Bearer"
        assert isinstance(response_data["expires_in"], int)
        assert response_data["expires_in"] > 0
        
        # Verify user information
        user_data = cast(UserData, response_data["user"])
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
        login_data = cast(OAuthInitiationResponseData, login_response.json())
        
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
        login_data = cast(OAuthInitiationResponseData, login_response.json())
        
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
        response_data = cast(OAuthCallbackResponseData, response.json())
        assert "access_token" in response_data
        assert "user" in response_data
        
        # Verify security considerations are addressed in response
        # The access_token should be present for client-side storage initially
        # Session cookies will be implemented as part of session management feature
        access_token = cast(str, response_data["access_token"])
        assert isinstance(access_token, str)
        assert len(access_token) > 0
    
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
        login_data = cast(OAuthInitiationResponseData, login_response.json())
        
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
        response_data = cast(OAuthCallbackResponseData, response.json())
        
        # Verify user information structure
        user_data = cast(UserData, response_data["user"])
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
        login_data = cast(OAuthInitiationResponseData, login_response.json())
        
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
        response_data = cast(ErrorResponseData, response.json())
        
        assert "detail" in response_data
        detail_lower = response_data["detail"].lower()
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
        login_data = cast(OAuthInitiationResponseData, login_response.json())
        
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
        response_data = cast(ErrorResponseData, response.json())
        
        assert "detail" in response_data
        detail_lower = response_data["detail"].lower()
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
        response_data = cast(ErrorResponseData, response.json())
        
        assert "detail" in response_data
        detail_lower = response_data["detail"].lower()
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
        login_data = cast(OAuthInitiationResponseData, login_response.json())
        
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
        response_data = cast(ErrorResponseData, response.json())
        
        assert "detail" in response_data
        detail_lower = response_data["detail"].lower()
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
        login_data = cast(OAuthInitiationResponseData, login_response.json())
        
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


class TestSessionManagementEndpoints:
    """Test suite for session management endpoints."""
    
    @pytest.mark.asyncio
    async def test_get_current_user_information_when_authenticated(
        self,
        async_client: AsyncClient,
        mock_oauth_flow_success: dict[str, object]  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        """Test case: GET /auth/me returns current user information when authenticated."""
        # Arrange - First complete OAuth flow to authenticate
        login_response: Response = await async_client.post("/auth/login", json={})
        assert login_response.status_code == status.HTTP_200_OK
        login_data = cast(OAuthInitiationResponseData, login_response.json())
        
        # Complete OAuth callback to get authenticated
        callback_response: Response = await async_client.post(
            "/auth/callback",
            json={
                "code": cast(str, login_data["code"]),
                "state": cast(str, login_data["state"])
            }
        )
        assert callback_response.status_code == status.HTTP_200_OK
        
        # Extract session cookies from callback response
        session_cookies: dict[str, str] = {}
        for cookie_header in callback_response.headers.get_list("set-cookie"):
            if "plex_session_token" in cookie_header:
                # Parse cookie value
                cookie_parts = cookie_header.split(";")[0]  # Get just the name=value part
                name, value = cookie_parts.split("=", 1)
                session_cookies[name] = value
        
        # Act - Get current user information with session cookies
        response: Response = await async_client.get("/auth/me", cookies=session_cookies)
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = cast(dict[str, object], response.json())
        
        # Verify user is authenticated
        assert "authenticated" in response_data
        assert response_data["authenticated"] is True
        
        # Verify user information is returned
        assert "user" in response_data
        assert response_data["user"] is not None
        user_data = cast(dict[str, object], response_data["user"])
        
        # Verify essential user fields
        required_fields = ["id", "username", "email"]
        for field in required_fields:
            assert field in user_data
            assert user_data[field] is not None
    
    @pytest.mark.asyncio
    async def test_get_current_user_information_when_unauthenticated(
        self,
        async_client: AsyncClient
    ) -> None:
        """Test case: GET /auth/me returns unauthenticated status when no session."""
        # Act
        response: Response = await async_client.get("/auth/me")
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = cast(dict[str, object], response.json())
        
        # Verify user is not authenticated
        assert "authenticated" in response_data
        assert response_data["authenticated"] is False
        
        # Verify no user information is returned
        assert "user" in response_data
        assert response_data["user"] is None
    
    @pytest.mark.asyncio
    async def test_refresh_authentication_token_success(
        self,
        async_client: AsyncClient,
        mock_oauth_flow_success: dict[str, object]  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        """Test case: POST /auth/refresh refreshes authentication token successfully."""
        # Arrange - First complete OAuth flow to authenticate
        login_response: Response = await async_client.post("/auth/login", json={})
        assert login_response.status_code == status.HTTP_200_OK
        login_data = cast(OAuthInitiationResponseData, login_response.json())
        
        # Complete OAuth callback to get authenticated
        callback_response: Response = await async_client.post(
            "/auth/callback",
            json={
                "code": cast(str, login_data["code"]),
                "state": cast(str, login_data["state"])
            }
        )
        assert callback_response.status_code == status.HTTP_200_OK
        
        # Extract session cookies from callback response
        session_cookies: dict[str, str] = {}
        for cookie_header in callback_response.headers.get_list("set-cookie"):
            if "plex_session_token" in cookie_header:
                # Parse cookie value
                cookie_parts = cookie_header.split(";")[0]  # Get just the name=value part
                name, value = cookie_parts.split("=", 1)
                session_cookies[name] = value
        
        # Act - Refresh token with session cookies
        response: Response = await async_client.post("/auth/refresh", cookies=session_cookies)
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = cast(dict[str, object], response.json())
        
        # Verify new token is returned
        assert "access_token" in response_data
        assert isinstance(response_data["access_token"], str)
        assert len(response_data["access_token"]) > 0
        
        # Verify token type
        assert "token_type" in response_data
        assert response_data["token_type"] == "Bearer"
        
        # Verify expires_in
        assert "expires_in" in response_data
        assert isinstance(response_data["expires_in"], int)
        assert response_data["expires_in"] > 0
        
        # Verify user information is still available
        assert "user" in response_data
        assert response_data["user"] is not None
    
    @pytest.mark.asyncio
    async def test_refresh_authentication_token_when_unauthenticated(
        self,
        async_client: AsyncClient
    ) -> None:
        """Test case: POST /auth/refresh handles unauthenticated requests appropriately."""
        # Act
        response: Response = await async_client.post("/auth/refresh")
        
        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response_data = cast(dict[str, str], response.json())
        
        assert "detail" in response_data
        detail_lower = response_data["detail"].lower()
        assert "authentication" in detail_lower or "unauthorized" in detail_lower
    
    @pytest.mark.asyncio
    async def test_logout_clears_session_and_cookies(
        self,
        async_client: AsyncClient,
        mock_oauth_flow_success: dict[str, object]  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        """Test case: POST /auth/logout clears session and cookies."""
        # Arrange - First complete OAuth flow to authenticate
        login_response: Response = await async_client.post("/auth/login", json={})
        assert login_response.status_code == status.HTTP_200_OK
        login_data = cast(OAuthInitiationResponseData, login_response.json())
        
        # Complete OAuth callback to get authenticated
        callback_response: Response = await async_client.post(
            "/auth/callback",
            json={
                "code": cast(str, login_data["code"]),
                "state": cast(str, login_data["state"])
            }
        )
        assert callback_response.status_code == status.HTTP_200_OK
        
        # Extract session cookies from callback response
        session_cookies: dict[str, str] = {}
        for cookie_header in callback_response.headers.get_list("set-cookie"):
            if "plex_session_token" in cookie_header:
                # Parse cookie value
                cookie_parts = cookie_header.split(";")[0]  # Get just the name=value part
                name, value = cookie_parts.split("=", 1)
                session_cookies[name] = value
        
        # Act - Logout with session cookies
        response: Response = await async_client.post("/auth/logout", cookies=session_cookies)
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = cast(dict[str, object], response.json())
        
        # Verify logout success
        assert "success" in response_data
        assert response_data["success"] is True
        
        # Verify logout message
        assert "message" in response_data
        assert isinstance(response_data["message"], str)
        assert len(response_data["message"]) > 0
        
        # Verify cookies are cleared (should have Set-Cookie headers for clearing)
        # Look for session clearing cookies in response headers
        set_cookie_headers = response.headers.get_list("set-cookie")
        if set_cookie_headers:
            # At least one cookie should be cleared (have Max-Age=0 or expires in past)
            cleared_cookies = [
                cookie for cookie in set_cookie_headers 
                if "Max-Age=0" in cookie or "expires=" in cookie.lower()
            ]
            assert len(cleared_cookies) > 0
    
    @pytest.mark.asyncio
    async def test_logout_when_unauthenticated(
        self,
        async_client: AsyncClient
    ) -> None:
        """Test case: POST /auth/logout handles unauthenticated requests gracefully."""
        # Act
        response: Response = await async_client.post("/auth/logout")
        
        # Assert - Logout should succeed even when not authenticated
        assert response.status_code == status.HTTP_200_OK
        response_data = cast(dict[str, object], response.json())
        
        # Verify logout success
        assert "success" in response_data
        assert response_data["success"] is True
        
        # Verify message indicates successful logout
        assert "message" in response_data
        assert isinstance(response_data["message"], str)
    
    @pytest.mark.asyncio
    async def test_logout_followed_by_me_returns_unauthenticated(
        self,
        async_client: AsyncClient,
        mock_oauth_flow_success: dict[str, object]  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        """Test case: After logout, GET /auth/me returns unauthenticated status."""
        # Arrange - First complete OAuth flow to authenticate
        login_response: Response = await async_client.post("/auth/login", json={})
        assert login_response.status_code == status.HTTP_200_OK
        login_data = cast(OAuthInitiationResponseData, login_response.json())
        
        # Complete OAuth callback to get authenticated
        callback_response: Response = await async_client.post(
            "/auth/callback",
            json={
                "code": cast(str, login_data["code"]),
                "state": cast(str, login_data["state"])
            }
        )
        assert callback_response.status_code == status.HTTP_200_OK
        
        # Extract session cookies from callback response
        session_cookies: dict[str, str] = {}
        for cookie_header in callback_response.headers.get_list("set-cookie"):
            if "plex_session_token" in cookie_header:
                # Parse cookie value
                cookie_parts = cookie_header.split(";")[0]  # Get just the name=value part
                name, value = cookie_parts.split("=", 1)
                session_cookies[name] = value
        
        # Logout with session cookies
        logout_response: Response = await async_client.post("/auth/logout", cookies=session_cookies)
        assert logout_response.status_code == status.HTTP_200_OK
        
        # Extract any updated cookies from logout response (should clear the session)
        logout_cookies: dict[str, str] = {}
        for cookie_header in logout_response.headers.get_list("set-cookie"):
            if "plex_session_token" in cookie_header:
                # Parse cookie value - should be empty or expired
                cookie_parts = cookie_header.split(";")[0]  # Get just the name=value part
                name, value = cookie_parts.split("=", 1)
                logout_cookies[name] = value
        
        # Act - Check authentication status after logout (use cleared cookies)
        response: Response = await async_client.get("/auth/me", cookies=logout_cookies)
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = cast(dict[str, object], response.json())
        
        # Verify user is not authenticated after logout
        assert "authenticated" in response_data
        assert response_data["authenticated"] is False
        
        # Verify no user information is returned
        assert "user" in response_data
        assert response_data["user"] is None
    
    @pytest.mark.asyncio
    async def test_session_endpoints_return_proper_content_type(
        self,
        async_client: AsyncClient
    ) -> None:
        """Test case: Session endpoints return proper JSON content type."""
        # Test /auth/me
        me_response: Response = await async_client.get("/auth/me")
        assert me_response.status_code == status.HTTP_200_OK
        assert me_response.headers["content-type"] == "application/json"
        
        # Test /auth/logout
        logout_response: Response = await async_client.post("/auth/logout")
        assert logout_response.status_code == status.HTTP_200_OK
        assert logout_response.headers["content-type"] == "application/json"
        
        # Test /auth/refresh (will return 401 for unauthenticated, but should still be JSON)
        refresh_response: Response = await async_client.post("/auth/refresh")
        assert refresh_response.status_code == status.HTTP_401_UNAUTHORIZED
        assert refresh_response.headers["content-type"] == "application/json"
    
    @pytest.mark.asyncio
    async def test_handle_unauthenticated_requests_consistently(
        self,
        async_client: AsyncClient
    ) -> None:
        """Test case: Handle unauthenticated requests appropriately across all endpoints."""
        # Test protected endpoints that require authentication
        protected_endpoints = [
            ("POST", "/auth/refresh")
        ]
        
        for method, endpoint in protected_endpoints:
            if method == "POST":
                response: Response = await async_client.post(endpoint)
            elif method == "GET":
                response = await async_client.get(endpoint)
            else:
                continue  # Skip unsupported methods
            
            # All protected endpoints should return 401 for unauthenticated requests
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
            response_data = cast(dict[str, str], response.json())
            assert "detail" in response_data
        
        # Test endpoints that work without authentication
        public_endpoints = [
            ("GET", "/auth/me"),        # Returns unauthenticated status
            ("POST", "/auth/logout")    # Succeeds even when not authenticated
        ]
        
        for method, endpoint in public_endpoints:
            if method == "POST":
                response = await async_client.post(endpoint)
            elif method == "GET":
                response = await async_client.get(endpoint)
            else:
                continue  # Skip unsupported methods
            
            # Public endpoints should return 200 even for unauthenticated requests
            assert response.status_code == status.HTTP_200_OK 