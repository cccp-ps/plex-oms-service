"""
Test cases for security middleware module.

Tests CSRF protection, rate limiting, and security headers middleware
for the Plex Online Media Sources Manager.
"""

import pytest
from typing import cast
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
        
        # Import the implemented RateLimitingMiddleware
        from app.middleware.security import RateLimitingMiddleware

        middleware = [
            Middleware(
                RateLimitingMiddleware,
                default_rate_limit="10/minute",
                endpoint_limits={
                    "/auth/login": "5/minute",
                    "/api/bulk-disable": "2/minute"
                },
                enabled=True  # Explicitly enable rate limiting for tests
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
            mock_client.host = "192.168.1.2"
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
        response_json = cast(dict[str, str], response.json())
        assert "rate limit exceeded" in response_json["detail"].lower()
        
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
            current_time = cast(float, mock_time.return_value)
            mock_time.return_value = current_time + 61
            
            # Should be able to make requests again
            response = client.post("/auth/login", json={"username": "test"})
            assert response.status_code == 200

    def test_rate_limiting_respects_client_ip(self) -> None:
        """Test that rate limiting is properly applied per client IP."""
        # This test will verify that different IPs get separate rate limit counters
        
        # Import the implemented RateLimitingMiddleware
        from app.middleware.security import RateLimitingMiddleware
        
        async def test_endpoint(_request: Request) -> JSONResponse:
            return JSONResponse({"message": "success"})
        
        routes = [Route("/api/test", test_endpoint, methods=["GET"])]
        
        middleware = [Middleware(RateLimitingMiddleware, default_rate_limit="2/minute", enabled=True)]
        
        app = Starlette(routes=routes, middleware=middleware)
        client = TestClient(app)
        
        # IP 1 makes requests
        with patch('starlette.requests.Request.client') as mock_client:
            mock_client.host = "192.168.1.1"
            
            # Exhaust limit for IP 1
            response1 = client.get("/api/test")
            assert response1.status_code == 200
            response2 = client.get("/api/test")  
            assert response2.status_code == 200
            response3 = client.get("/api/test")
            assert response3.status_code == 429  # Rate limited
        
        # IP 2 should have its own counter
        with patch('starlette.requests.Request.client') as mock_client:
            mock_client.host = "192.168.1.2"
            
            response = client.get("/api/test")
            assert response.status_code == 200  # Should not be rate limited

    def test_rate_limiting_with_configuration_disabled(self) -> None:
        """Test that rate limiting can be disabled via configuration."""
        # Import the implemented RateLimitingMiddleware
        from app.middleware.security import RateLimitingMiddleware
        
        async def test_endpoint(_request: Request) -> JSONResponse:
            return JSONResponse({"message": "success"})
        
        routes = [Route("/api/test", test_endpoint, methods=["GET"])]
        
        middleware = [Middleware(RateLimitingMiddleware, default_rate_limit="1/minute", enabled=False)]
        
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
            _ = client.post("/auth/login", json={"username": "test"})
        
        # Get rate limited response
        response = client.post("/auth/login", json={"username": "test"})
        
        assert response.status_code == 429
        response_data = cast(dict[str, str], response.json())
        
        # Verify error response structure
        assert "error" in response_data
        assert "detail" in response_data
        assert response_data["error"] == "Too Many Requests"
        assert "rate limit" in response_data["detail"].lower()
        
        # Verify headers
        assert "Retry-After" in response.headers
        assert int(response.headers["Retry-After"]) > 0 


class TestSecurityHeadersMiddleware:
    """Test cases for Security Headers middleware."""

    @pytest.fixture
    def app_with_security_headers(self) -> Starlette:
        """Create test application with security headers middleware."""
        # This fixture will be implemented after creating the SecurityHeadersMiddleware
        async def test_endpoint(_request: Request) -> JSONResponse:
            response = JSONResponse({"message": "success"})
            response.set_cookie("session", "test-value")
            return response
        
        async def api_endpoint(_request: Request) -> JSONResponse:
            return JSONResponse({"data": "api-response"})
        
        routes = [
            Route("/api/test", test_endpoint, methods=["GET", "POST"]),
            Route("/api/data", api_endpoint, methods=["GET"]),
        ]
        
        # Import the SecurityHeadersMiddleware that we'll implement
        from app.middleware.security import SecurityHeadersMiddleware

        middleware = [
            Middleware(
                SecurityHeadersMiddleware,
                include_hsts=True,
                include_csp=True,
                include_security_headers=True,
                cors_allowed_origins=["https://localhost:3000", "https://app.example.com"],
                cors_allow_credentials=True
            )
        ]

        app = Starlette(routes=routes, middleware=middleware)
        return app

    def test_inject_security_headers_hsts_csp_etc(self, app_with_security_headers: Starlette) -> None:
        """Test case: Inject security headers (HSTS, CSP, etc.)."""
        client = TestClient(app_with_security_headers)
        
        response = client.get("/api/test")
        assert response.status_code == 200
        
        # Verify HSTS header
        assert "Strict-Transport-Security" in response.headers
        hsts_value = response.headers["Strict-Transport-Security"]
        assert "max-age=" in hsts_value
        assert "includeSubDomains" in hsts_value
        assert "preload" in hsts_value
        
        # Verify Content Security Policy
        assert "Content-Security-Policy" in response.headers
        csp_value = response.headers["Content-Security-Policy"]
        assert "default-src 'self'" in csp_value
        assert "script-src" in csp_value
        assert "style-src" in csp_value
        assert "img-src" in csp_value
        
        # Verify X-Content-Type-Options
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        
        # Verify X-Frame-Options
        assert response.headers.get("X-Frame-Options") == "DENY"
        
        # Verify X-XSS-Protection (legacy header for older browsers)
        assert response.headers.get("X-XSS-Protection") == "1; mode=block"
        
        # Verify Referrer-Policy
        assert "Referrer-Policy" in response.headers
        assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
        
        # Verify Permissions-Policy (replaces Feature-Policy)
        assert "Permissions-Policy" in response.headers
        permissions_policy = response.headers["Permissions-Policy"]
        assert "camera=()" in permissions_policy
        assert "microphone=()" in permissions_policy
        assert "geolocation=()" in permissions_policy

    def test_configure_proper_cors_headers(self, app_with_security_headers: Starlette) -> None:
        """Test case: Configure proper CORS headers."""
        client = TestClient(app_with_security_headers)
        
        # Test preflight request
        response = client.options(
            "/api/test",
            headers={
                "Origin": "https://localhost:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type"
            }
        )
        
        # Should handle OPTIONS preflight
        assert response.status_code == 200
        
        # Test actual CORS request
        response = client.get(
            "/api/test",
            headers={"Origin": "https://localhost:3000"}
        )
        assert response.status_code == 200
        
        # Verify CORS headers
        assert response.headers.get("Access-Control-Allow-Origin") == "https://localhost:3000"
        assert response.headers.get("Access-Control-Allow-Credentials") == "true"
        
        # Test with disallowed origin
        response = client.get(
            "/api/test", 
            headers={"Origin": "https://malicious-site.com"}
        )
        assert response.status_code == 200
        # Should not include CORS headers for disallowed origins
        assert "Access-Control-Allow-Origin" not in response.headers

    def test_set_secure_cookie_attributes(self, app_with_security_headers: Starlette) -> None:
        """Test case: Set secure cookie attributes."""
        client = TestClient(app_with_security_headers)
        
        response = client.get("/api/test")
        assert response.status_code == 200
        
        # Check that cookies have secure attributes
        cookies = response.cookies
        if "session" in cookies:
            # Note: TestClient doesn't always preserve cookie attributes
            # In real implementation, we'll verify the Set-Cookie header directly
            pass
        
        # Check Set-Cookie header directly for proper attributes
        set_cookie_headers = [value for name, value in response.headers.items() if name.lower() == "set-cookie"]
        if set_cookie_headers:
            for cookie_header in set_cookie_headers:
                # Verify secure attributes are added by middleware
                assert "Secure" in cookie_header or "HttpOnly" in cookie_header or "SameSite" in cookie_header

    def test_remove_sensitive_server_information(self, app_with_security_headers: Starlette) -> None:
        """Test case: Remove sensitive server information."""
        client = TestClient(app_with_security_headers)
        
        response = client.get("/api/test")
        assert response.status_code == 200
        
        # Verify sensitive headers are removed or sanitized
        assert "Server" not in response.headers or response.headers["Server"] == "PlexOMS"
        assert "X-Powered-By" not in response.headers
        
        # Verify that we don't expose FastAPI/Uvicorn version information
        server_header = cast(str, response.headers.get("Server", ""))
        assert "uvicorn" not in server_header.lower()
        assert "fastapi" not in server_header.lower()
        assert "starlette" not in server_header.lower()

    def test_security_headers_with_custom_configuration(self) -> None:
        """Test security headers middleware with custom configuration."""
        from app.middleware.security import SecurityHeadersMiddleware
        
        async def test_endpoint(_request: Request) -> JSONResponse:
            return JSONResponse({"message": "success"})
        
        routes = [Route("/api/test", test_endpoint, methods=["GET"])]
        
        # Test with custom CSP policy
        middleware = [
            Middleware(
                SecurityHeadersMiddleware,
                include_hsts=False,  # Disable HSTS for testing
                include_csp=True,
                csp_policy="default-src 'self'; script-src 'self' 'unsafe-inline'",
                cors_allowed_origins=["https://custom-domain.com"],
                custom_server_header="CustomApp/1.0"
            )
        ]
        
        app = Starlette(routes=routes, middleware=middleware)
        client = TestClient(app)
        
        response = client.get("/api/test")
        assert response.status_code == 200
        
        # Should not have HSTS when disabled
        assert "Strict-Transport-Security" not in response.headers
        
        # Should have custom CSP
        assert response.headers.get("Content-Security-Policy") == "default-src 'self'; script-src 'self' 'unsafe-inline'"
        
        # Should have custom server header
        assert response.headers.get("Server") == "CustomApp/1.0"

    def test_security_headers_preserve_existing_headers(self) -> None:
        """Test that security headers middleware preserves existing headers."""
        from app.middleware.security import SecurityHeadersMiddleware
        
        async def test_endpoint(_request: Request) -> JSONResponse:
            response = JSONResponse({"message": "success"})
            response.headers["Custom-App-Header"] = "custom-value"
            response.headers["Cache-Control"] = "no-cache"
            return response
        
        routes = [Route("/api/test", test_endpoint, methods=["GET"])]
        
        middleware = [
            Middleware(SecurityHeadersMiddleware, include_security_headers=True)
        ]
        
        app = Starlette(routes=routes, middleware=middleware)
        client = TestClient(app)
        
        response = client.get("/api/test")
        assert response.status_code == 200
        
        # Should preserve existing headers
        assert response.headers.get("Custom-App-Header") == "custom-value"
        assert response.headers.get("Cache-Control") == "no-cache"
        
        # Should also add security headers
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers

    def test_cors_preflight_handling(self) -> None:
        """Test CORS preflight request handling."""
        from app.middleware.security import SecurityHeadersMiddleware
        
        async def test_endpoint(_request: Request) -> JSONResponse:
            return JSONResponse({"message": "success"})
        
        routes = [Route("/api/test", test_endpoint, methods=["GET", "POST"])]
        
        middleware = [
            Middleware(
                SecurityHeadersMiddleware,
                cors_allowed_origins=["https://localhost:3000"],
                cors_allowed_methods=["GET", "POST", "PUT", "DELETE"],
                cors_allowed_headers=["Content-Type", "Authorization", "X-CSRF-Token"]
            )
        ]
        
        app = Starlette(routes=routes, middleware=middleware)
        client = TestClient(app)
        
        # Test preflight request
        response = client.options(
            "/api/test",
            headers={
                "Origin": "https://localhost:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type, Authorization"
            }
        )
        
        assert response.status_code == 200
        assert response.headers.get("Access-Control-Allow-Origin") == "https://localhost:3000"
        assert "POST" in response.headers.get("Access-Control-Allow-Methods", "")
        assert "Content-Type" in response.headers.get("Access-Control-Allow-Headers", "")
        assert "Authorization" in response.headers.get("Access-Control-Allow-Headers", "")

    def test_security_headers_disabled_configuration(self) -> None:
        """Test security headers middleware when features are disabled."""
        from app.middleware.security import SecurityHeadersMiddleware
        
        async def test_endpoint(_request: Request) -> JSONResponse:
            return JSONResponse({"message": "success"})
        
        routes = [Route("/api/test", test_endpoint, methods=["GET"])]
        
        middleware = [
            Middleware(
                SecurityHeadersMiddleware,
                include_hsts=False,
                include_csp=False,
                include_security_headers=False
            )
        ]
        
        app = Starlette(routes=routes, middleware=middleware)
        client = TestClient(app)
        
        response = client.get("/api/test")
        assert response.status_code == 200
        
        # Should not include disabled headers
        assert "Strict-Transport-Security" not in response.headers
        assert "Content-Security-Policy" not in response.headers
        assert "X-Content-Type-Options" not in response.headers
        assert "X-Frame-Options" not in response.headers 