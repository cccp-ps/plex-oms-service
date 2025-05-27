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
        """Test that CSRF middleware allows requests with valid CSRF tokens."""
        client = TestClient(app_with_csrf_middleware)
        csrf_validator = CSRFTokenValidator(secret_key="test-secret-key-minimum-32-chars-req")
        
        # Generate valid CSRF token
        valid_token = csrf_validator.generate_token()
        headers = {"X-CSRF-Token": valid_token}
        
        # POST request with valid CSRF token should succeed
        response = client.post("/api/test", json={"data": "test"}, headers=headers)
        assert response.status_code == 200
        assert response.json() == {"message": "success"}


class TestRateLimitingMiddleware:
    """Test cases for rate limiting middleware using slowapi."""

    @pytest.fixture
    def app_with_rate_limiting(self) -> Starlette:
        """Create test application with rate limiting middleware."""
        # This fixture will be implemented after creating the RateLimitingMiddleware
        async def test_endpoint(_request: Request) -> JSONResponse:
            return JSONResponse({"message": "success"})
        
        async def auth_endpoint(_request: Request) -> JSONResponse:
            return JSONResponse({"message": "auth"})
        
        routes = [
            Route("/api/test", test_endpoint, methods=["GET", "POST"]),
            Route("/auth/login", auth_endpoint, methods=["POST"]),
        ]
        
        # Import will be added after implementation
        from app.middleware.security import RateLimitingMiddleware  # pyright: ignore[reportMissingImports]
        
        # Mock the settings to avoid validation errors
        with patch('app.middleware.security.get_settings') as mock_get_settings:
            mock_settings = Mock()
            mock_settings.rate_limit_enabled = True
            mock_get_settings.return_value = mock_settings
            
            middleware = [
                Middleware(
                    RateLimitingMiddleware,
                    default_rate_limit="10/minute",
                    endpoint_limits={
                        "/auth/login": "5/minute",
                        "/api/bulk-disable": "2/minute"
                    }
                )
            ]
            
            app = Starlette(routes=routes, middleware=middleware)
        return app

    def test_implement_per_ip_rate_limiting_using_slowapi(self, app_with_rate_limiting: Starlette) -> None:
        """Test case: Implement per-IP rate limiting using slowapi."""
        client = TestClient(app_with_rate_limiting)
        
        # Make requests within rate limit
        for _ in range(5):  # Should be within 10/minute limit
            response = client.get("/api/test")
            assert response.status_code == 200
        
        # Simulate requests from different IP addresses
        with patch('starlette.requests.Request.client') as mock_client:
            # Different IP should have its own rate limit
            mock_client.host = "192.168.1.2"  # pyright: ignore[reportAny]
            response = client.get("/api/test")
            assert response.status_code == 200

    def test_different_limits_for_different_endpoints(self, app_with_rate_limiting: Starlette) -> None:
        """Test case: Different limits for different endpoints."""
        client = TestClient(app_with_rate_limiting)
        
        # Auth endpoint should have stricter limit (5/minute)
        for _ in range(3):  # Should be within 5/minute limit
            response = client.post("/auth/login", json={"username": "test"})
            assert response.status_code == 200
        
        # Regular endpoint should have more relaxed limit (10/minute)
        for _ in range(7):  # Should be within 10/minute limit
            response = client.get("/api/test")
            assert response.status_code == 200

    def test_handle_rate_limit_exceeded_responses(self, app_with_rate_limiting: Starlette) -> None:
        """Test case: Handle rate limit exceeded responses."""
        client = TestClient(app_with_rate_limiting)
        
        # Exhaust the rate limit for auth endpoint (5/minute)
        for _ in range(5):
            response = client.post("/auth/login", json={"username": "test"})
            assert response.status_code == 200
        
        # Next request should be rate limited
        response = client.post("/auth/login", json={"username": "test"})
        assert response.status_code == 429  # Too Many Requests
        assert "rate limit exceeded" in response.json()["detail"].lower()
        
        # Should include Retry-After header
        assert "Retry-After" in response.headers

    def test_reset_rate_limits_after_time_window(self, app_with_rate_limiting: Starlette) -> None:
        """Test case: Reset rate limits after time window."""
        client = TestClient(app_with_rate_limiting)
        
        # Exhaust the rate limit
        for _ in range(5):
            response = client.post("/auth/login", json={"username": "test"})
            assert response.status_code == 200
        
        # Should be rate limited
        response = client.post("/auth/login", json={"username": "test"})
        assert response.status_code == 429
        
        # Mock time advancement to simulate window reset
        with patch('time.time') as mock_time:
            # Advance time by 61 seconds (beyond 1 minute window)
            mock_time.return_value = mock_time.return_value + 61
            
            # Should be able to make requests again
            response = client.post("/auth/login", json={"username": "test"})
            assert response.status_code == 200

    def test_rate_limiting_respects_client_ip(self) -> None:
        """Test that rate limiting is properly applied per client IP."""
        # This test will verify that different IPs get separate rate limit counters
        
        # Import will be added after implementation
        from app.middleware.security import RateLimitingMiddleware  # pyright: ignore[reportMissingImports]
        
        async def test_endpoint(_request: Request) -> JSONResponse:
            return JSONResponse({"message": "success"})
        
        routes = [Route("/api/test", test_endpoint, methods=["GET"])]
        
        # Mock the settings to avoid validation errors
        with patch('app.middleware.security.get_settings') as mock_get_settings:
            mock_settings = Mock()
            mock_settings.rate_limit_enabled = True
            mock_get_settings.return_value = mock_settings
            
            middleware = [Middleware(RateLimitingMiddleware, default_rate_limit="2/minute")]
            
            app = Starlette(routes=routes, middleware=middleware)
            client = TestClient(app)
            
            # IP 1 makes requests
            with patch('starlette.requests.Request.client') as mock_client:
                mock_client.host = "192.168.1.1"  # pyright: ignore[reportAny]
                
                # Exhaust limit for IP 1
                response1 = client.get("/api/test")
                assert response1.status_code == 200
                response2 = client.get("/api/test")  
                assert response2.status_code == 200
                response3 = client.get("/api/test")
                assert response3.status_code == 429  # Rate limited
            
            # IP 2 should have its own counter
            with patch('starlette.requests.Request.client') as mock_client:
                mock_client.host = "192.168.1.2"  # pyright: ignore[reportAny]
                
                response = client.get("/api/test")
                assert response.status_code == 200  # Should not be rate limited

    def test_rate_limiting_with_configuration_disabled(self) -> None:
        """Test that rate limiting can be disabled via configuration."""
        # Import will be added after implementation
        from app.middleware.security import RateLimitingMiddleware  # pyright: ignore[reportMissingImports]
        
        async def test_endpoint(_request: Request) -> JSONResponse:
            return JSONResponse({"message": "success"})
        
        routes = [Route("/api/test", test_endpoint, methods=["GET"])]
        
        # Mock the settings with rate limiting disabled
        with patch('app.middleware.security.get_settings') as mock_get_settings:
            mock_settings = Mock()
            mock_settings.rate_limit_enabled = False
            mock_get_settings.return_value = mock_settings
            
            middleware = [Middleware(RateLimitingMiddleware, default_rate_limit="1/minute")]
            
            app = Starlette(routes=routes, middleware=middleware)
            client = TestClient(app)
            
            # Should be able to make many requests when disabled
            for _ in range(10):
                response = client.get("/api/test")
                assert response.status_code == 200

    def test_rate_limiting_error_responses_format(self, app_with_rate_limiting: Starlette) -> None:
        """Test that rate limit error responses follow the expected format."""
        client = TestClient(app_with_rate_limiting)
        
        # Exhaust rate limit
        for _ in range(5):
            client.post("/auth/login", json={"username": "test"})
        
        # Get rate limited response
        response = client.post("/auth/login", json={"username": "test"})
        
        assert response.status_code == 429
        response_data = response.json()
        
        # Verify error response structure
        assert "error" in response_data
        assert "detail" in response_data
        assert response_data["error"] == "Too Many Requests"
        assert "rate limit" in response_data["detail"].lower()
        
        # Verify headers
        assert "Retry-After" in response.headers
        assert int(response.headers["Retry-After"]) > 0 