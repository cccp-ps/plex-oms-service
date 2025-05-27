"""
Test cases for security middleware module.

Tests CSRF protection, rate limiting, and security headers middleware
for the Plex Online Media Sources Manager.
"""

import pytest
from unittest.mock import Mock, patch
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app.middleware.security import CSRFProtectionMiddleware, CSRFTokenValidator


class TestCSRFProtectionMiddleware:
    """Test cases for CSRF protection middleware."""

    @pytest.fixture
    def csrf_validator(self) -> CSRFTokenValidator:
        """Create CSRF token validator for testing."""
        return CSRFTokenValidator(secret_key="test-secret-key-minimum-32-chars-req")

    @pytest.fixture
    def app_with_csrf_middleware(self) -> Starlette:
        """Create test application with CSRF middleware."""
        async def test_endpoint(_request: Request) -> JSONResponse:
            return JSONResponse({"message": "success"})
        
        async def health_endpoint(_request: Request) -> JSONResponse:
            return JSONResponse({"status": "ok"})
        
        routes = [
            Route("/api/test", test_endpoint, methods=["POST"]),
            Route("/health", health_endpoint, methods=["GET"]),
        ]
        
        middleware = [
            Middleware(
                CSRFProtectionMiddleware,
                secret_key="test-secret-key-minimum-32-chars-req",
                excluded_paths=["/health", "/auth/login"]
            )
        ]
        
        app = Starlette(routes=routes, middleware=middleware)
        return app

    def test_generate_and_validate_csrf_tokens(self, csrf_validator: CSRFTokenValidator) -> None:
        """Test case: Generate and validate CSRF tokens."""
        # Generate a CSRF token
        csrf_token = csrf_validator.generate_token()
        
        # Verify token format
        assert isinstance(csrf_token, str)
        assert len(csrf_token) >= 32
        assert csrf_token.count('.') == 2  # Should have timestamp.token.signature format
        
        # Validate the generated token
        assert csrf_validator.validate_token(csrf_token) is True
        
        # Test invalid token validation
        invalid_token = "invalid.token.format"
        assert csrf_validator.validate_token(invalid_token) is False
        
        # Test empty token validation
        assert csrf_validator.validate_token("") is False
        assert csrf_validator.validate_token(None) is False

    def test_reject_requests_with_invalid_csrf_tokens(self, app_with_csrf_middleware: Starlette) -> None:
        """Test case: Reject requests with invalid CSRF tokens."""
        client = TestClient(app_with_csrf_middleware)
        
        # Test POST request without CSRF token
        response = client.post("/api/test", json={"data": "test"})
        assert response.status_code == 403
        assert "CSRF token required" in response.json()["detail"]
        
        # Test POST request with invalid CSRF token
        headers = {"X-CSRF-Token": "invalid-token"}
        response = client.post("/api/test", json={"data": "test"}, headers=headers)
        assert response.status_code == 403
        assert "Invalid CSRF token" in response.json()["detail"]
        
        # Test POST request with malformed CSRF token
        headers = {"X-CSRF-Token": "malformed"}
        response = client.post("/api/test", json={"data": "test"}, headers=headers)
        assert response.status_code == 403
        assert "Invalid CSRF token" in response.json()["detail"]

    def test_handle_csrf_token_expiration(self, csrf_validator: CSRFTokenValidator) -> None:
        """Test case: Handle CSRF token expiration."""
        # Mock time to simulate expired token
        with patch('time.time') as mock_time:
            # Generate token at time 0
            mock_time.return_value = 0
            csrf_token = csrf_validator.generate_token()
            
            # Verify token is valid immediately
            assert csrf_validator.validate_token(csrf_token) is True
            
            # Simulate time passing beyond expiration (default 1 hour = 3600 seconds)
            mock_time.return_value = 3601
            
            # Token should now be expired
            assert csrf_validator.validate_token(csrf_token) is False

    def test_integrate_with_oauth_state_parameter(self, csrf_validator: CSRFTokenValidator) -> None:
        """Test case: Integrate with OAuth state parameter."""
        # Generate CSRF token that can be used as OAuth state
        csrf_token = csrf_validator.generate_token()
        
        # Verify token can be used for OAuth state validation
        assert csrf_validator.validate_oauth_state(csrf_token) is True
        
        # Test with invalid OAuth state
        invalid_state = "invalid-oauth-state"
        assert csrf_validator.validate_oauth_state(invalid_state) is False
        
        # Test with expired OAuth state
        with patch('time.time') as mock_time:
            mock_time.return_value = 0
            oauth_state = csrf_validator.generate_token()
            
            # Advance time beyond expiration
            mock_time.return_value = 3601
            assert csrf_validator.validate_oauth_state(oauth_state) is False

    def test_csrf_middleware_allows_excluded_paths(self, app_with_csrf_middleware: Starlette) -> None:
        """Test that CSRF middleware allows excluded paths without token validation."""
        client = TestClient(app_with_csrf_middleware)
        
        # Health endpoint should be excluded from CSRF protection
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_csrf_middleware_allows_safe_methods(self) -> None:
        """Test that CSRF middleware allows safe HTTP methods without token validation."""
        async def get_test_endpoint(_request: Request) -> JSONResponse:
            return JSONResponse({"message": "success"})
        
        async def post_test_endpoint(_request: Request) -> JSONResponse:
            return JSONResponse({"message": "success"})
        
        routes = [
            Route("/api/test", get_test_endpoint, methods=["GET"]),
            Route("/api/test", post_test_endpoint, methods=["POST"]),
        ]
        
        middleware = [
            Middleware(
                CSRFProtectionMiddleware,
                secret_key="test-secret-key-minimum-32-chars-req",
                excluded_paths=["/health", "/auth/login"]
            )
        ]
        
        app = Starlette(routes=routes, middleware=middleware)
        client = TestClient(app)
        
        # GET requests should not require CSRF token
        response = client.get("/api/test")
        assert response.status_code == 200
        assert response.json() == {"message": "success"}

    @pytest.mark.asyncio
    async def test_csrf_middleware_async_validation(self) -> None:
        """Test CSRF middleware with async request processing."""
        csrf_validator = CSRFTokenValidator(secret_key="test-secret-key-minimum-32-chars-req")
        
        # Create mock request with valid CSRF token
        valid_token = csrf_validator.generate_token()
        mock_request = Mock(spec=Request)
        mock_request.method = "POST"
        mock_request.url.path = "/api/test"  # pyright: ignore[reportAny]
        mock_request.headers = {"X-CSRF-Token": valid_token}
        
        # Test validation
        is_valid = await csrf_validator.async_validate_token(valid_token)
        assert is_valid is True
        
        # Test with invalid token
        is_valid = await csrf_validator.async_validate_token("invalid")
        assert is_valid is False

    def test_csrf_token_integration_with_oauth_service(self, csrf_validator: CSRFTokenValidator) -> None:
        """Test integration between CSRF tokens and OAuth service state parameters."""
        # This test verifies that CSRF tokens can be used as OAuth state parameters
        # which provides unified security across authentication flows
        
        # Generate a CSRF token
        csrf_token = csrf_validator.generate_token()
        
        # Verify it can be used as OAuth state (same validation logic)
        assert csrf_validator.validate_oauth_state(csrf_token) is True
        
        # Verify the token format is compatible with OAuth requirements
        # OAuth state should be URL-safe and sufficiently random
        assert len(csrf_token) >= 32  # Sufficient entropy
        assert '.' in csrf_token  # Contains structured data
        
        # Test that expired tokens are rejected for OAuth as well
        with patch('time.time') as mock_time:
            mock_time.return_value = 0
            oauth_state = csrf_validator.generate_token()
            
            # Token should be valid initially
            assert csrf_validator.validate_oauth_state(oauth_state) is True
            
            # Advance time beyond expiration
            mock_time.return_value = 3601
            
            # Expired token should be rejected for OAuth
            assert csrf_validator.validate_oauth_state(oauth_state) is False

    def test_csrf_middleware_with_valid_token_allows_request(self, app_with_csrf_middleware: Starlette) -> None:
        """Test that CSRF middleware allows requests with valid tokens."""
        client = TestClient(app_with_csrf_middleware)
        
        # Generate a valid CSRF token
        csrf_validator = CSRFTokenValidator(secret_key="test-secret-key-minimum-32-chars-req")
        valid_token = csrf_validator.generate_token()
        
        # Test POST request with valid CSRF token
        headers = {"X-CSRF-Token": valid_token}
        response = client.post("/api/test", json={"data": "test"}, headers=headers)
        assert response.status_code == 200
        assert response.json() == {"message": "success"} 