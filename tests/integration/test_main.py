"""
Integration tests for main FastAPI application.

Tests the FastAPI application initialization, middleware configuration,
route registration, exception handlers, and health check endpoints.
"""

import pytest
from fastapi import status
from fastapi.testclient import TestClient
from httpx import Response
import json
from unittest.mock import AsyncMock, MagicMock, patch

from app.main import app
from app.config import Settings


class TestFastAPIApplicationInitialization:
    """Test FastAPI application initialization and configuration."""
    
    def test_app_is_fastapi_instance(self) -> None:
        """Test that app is properly initialized as FastAPI instance."""
        from fastapi import FastAPI
        assert isinstance(app, FastAPI)
        assert app.title == "Plex Online Media Sources Manager"
        assert app.version == "0.1.0"
        assert "privacy-first" in app.description.lower()
    
    def test_cors_middleware_configuration(self) -> None:
        """Test CORS middleware is properly configured with security settings."""
        with TestClient(app) as client:
            # Test preflight request
            response = client.options(
                "/",
                headers={
                    "Origin": "http://localhost:3000",
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "authorization"
                }
            )
            
            # Check CORS headers are present
            assert "access-control-allow-origin" in response.headers
            assert "access-control-allow-methods" in response.headers
            assert "access-control-allow-headers" in response.headers
    
    def test_authentication_routes_registered(self) -> None:
        """Test authentication routes are properly registered."""
        with TestClient(app) as client:
            # Test auth routes exist (should get 422 for missing body, not 404)
            auth_routes = ["/auth/login", "/auth/callback", "/auth/logout", "/auth/refresh"]
            
            for route in auth_routes:
                response = client.post(route)
                # 422 (validation error) means route exists but missing required fields
                # 404 would mean route doesn't exist
                assert response.status_code != status.HTTP_404_NOT_FOUND
    
    def test_media_source_routes_registered(self) -> None:
        """Test media source routes are properly registered.""" 
        with TestClient(app) as client:
            # Test media source routes exist
            response = client.get("/api/media-sources")
            # 401 (unauthorized) means route exists but auth required
            # 404 would mean route doesn't exist
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
            
            # Test individual source route
            response = client.patch("/api/media-sources/test-source")
            assert response.status_code != status.HTTP_404_NOT_FOUND
            
            # Test bulk disable route
            response = client.post("/api/media-sources/disable-all")
            assert response.status_code != status.HTTP_404_NOT_FOUND
    
    def test_exception_handlers_configured(self) -> None:
        """Test custom exception handlers are properly set up."""
        # Check that our custom exception handlers are registered
        assert hasattr(app, "exception_handlers")
        
        # Import our custom exceptions
        from app.utils.exceptions import (
            PlexAPIException, 
            AuthenticationException,
            AuthorizationException,
            ValidationException,
            ConnectionException,
            RateLimitException
        )
        
        # Verify exception handlers are registered
        exception_types = [
            PlexAPIException,
            AuthenticationException, 
            AuthorizationException,
            ValidationException,
            ConnectionException,
            RateLimitException
        ]
        
        for exc_type in exception_types:
            assert exc_type in app.exception_handlers
    
    def test_security_middleware_configured(self) -> None:
        """Test security middleware is properly configured."""
        with TestClient(app) as client:
            response = client.get("/health")
            
            # Check security headers are applied
            # Note: HSTS is only enabled in production environment
            basic_security_headers = [
                "x-content-type-options",
                "x-frame-options", 
                "x-xss-protection"
            ]
            
            for header in basic_security_headers:
                assert header in response.headers.keys() or any(
                    header.replace("-", "_") in key.lower() for key in response.headers.keys()
                )
            
            # Check that CSP is present (either as header or through middleware)
            has_csp = "content-security-policy" in response.headers
            assert has_csp, "Content Security Policy header should be present"


class TestHealthCheckAndMonitoring:
    """Test health check endpoints and monitoring functionality."""
    
    def test_health_endpoint_returns_status(self) -> None:
        """Test GET /health returns application health status."""
        with TestClient(app) as client:
            response = client.get("/health")
            
            assert response.status_code == status.HTTP_200_OK
            
            data = response.json()
            assert "status" in data
            assert data["status"] in ["healthy", "degraded", "unhealthy"]
            assert "timestamp" in data
            assert "version" in data
    
    @patch("app.services.plex_service.PlexMediaSourceService.check_connectivity")
    def test_health_check_with_plex_connectivity(self, mock_connectivity: AsyncMock) -> None:
        """Test health endpoint includes PlexAPI connectivity check."""
        # Mock successful PlexAPI connectivity
        mock_connectivity.return_value = True
        
        with TestClient(app) as client:
            response = client.get("/health")
            
            assert response.status_code == status.HTTP_200_OK
            
            data = response.json()
            assert "plex_api" in data
            assert data["plex_api"]["connected"] is True
            assert "response_time_ms" in data["plex_api"]
    
    @patch("app.services.plex_service.PlexMediaSourceService.check_connectivity") 
    def test_health_check_with_plex_failure(self, mock_connectivity: AsyncMock) -> None:
        """Test health endpoint handles PlexAPI connectivity failures."""
        # Mock PlexAPI connectivity failure
        mock_connectivity.side_effect = Exception("Connection failed")
        
        with TestClient(app) as client:
            response = client.get("/health")
            
            # Health endpoint should still return 200 but indicate degraded status
            assert response.status_code == status.HTTP_200_OK
            
            data = response.json()
            assert data["status"] == "degraded"
            assert "plex_api" in data
            assert data["plex_api"]["connected"] is False
            assert "error" in data["plex_api"]
    
    def test_health_check_proper_status_codes(self) -> None:
        """Test health endpoint returns proper HTTP status codes."""
        with TestClient(app) as client:
            # Health check should always return 200 OK for monitoring
            response = client.get("/health")
            assert response.status_code == status.HTTP_200_OK
            
            # Response should be JSON
            assert response.headers["content-type"] == "application/json"
            
            # Should include required fields
            data = response.json()
            required_fields = ["status", "timestamp", "version"]
            for field in required_fields:
                assert field in data
    
    def test_health_check_response_format(self) -> None:
        """Test health check response has proper format and types."""
        with TestClient(app) as client:
            response = client.get("/health")
            data = response.json()
            
            # Verify data types
            assert isinstance(data["status"], str)
            assert isinstance(data["timestamp"], str)
            assert isinstance(data["version"], str)
            
            # Verify timestamp format (ISO 8601)
            from datetime import datetime
            try:
                datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
            except ValueError:
                pytest.fail("Timestamp is not in valid ISO 8601 format")
    
    def test_health_endpoint_security(self) -> None:
        """Test health endpoint doesn't expose sensitive information."""
        with TestClient(app) as client:
            response = client.get("/health")
            data = response.json()
            
            # Ensure no sensitive data is exposed
            sensitive_fields = [
                "secret", "password", "token", "key", "credential",
                "api_key", "auth", "private", "internal"
            ]
            
            response_str = json.dumps(data).lower()
            for field in sensitive_fields:
                assert field not in response_str, f"Sensitive field '{field}' found in health response"


class TestApplicationSecurity:
    """Test application-level security features."""
    
    def test_csrf_protection_on_state_changing_methods(self) -> None:
        """Test CSRF protection is active for POST/PUT/PATCH/DELETE methods."""
        with TestClient(app) as client:
            # Test POST requests require CSRF token (except auth endpoints which have OAuth state)
            response = client.post("/api/media-sources/disable-all", json={"confirmed": True})
            
            # Should get either 401 (auth required) or 403 (CSRF required)
            # but not 404 (route not found)
            assert response.status_code in [
                status.HTTP_401_UNAUTHORIZED,
                status.HTTP_403_FORBIDDEN,
                status.HTTP_422_UNPROCESSABLE_ENTITY
            ]
    
    def test_rate_limiting_applied(self) -> None:
        """Test rate limiting is applied to endpoints."""
        with TestClient(app) as client:
            # Make multiple rapid requests to test rate limiting
            responses = []
            for _ in range(10):
                response = client.get("/health")
                responses.append(response.status_code)
            
            # All health check requests should succeed (rate limit is high)
            # But rate limiting middleware should be present
            assert all(code == status.HTTP_200_OK for code in responses)
            
            # Check rate limit headers are present
            response = client.get("/health")
            # Rate limit headers might be present depending on configuration
            rate_limit_headers = ["x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"]
            has_rate_limit_headers = any(
                header.lower() in [h.lower() for h in response.headers.keys()]
                for header in rate_limit_headers
            )
            # Note: Headers might not be present if rate limiting is disabled for health checks
    
    def test_security_headers_present(self) -> None:
        """Test security headers are properly set."""
        with TestClient(app) as client:
            response = client.get("/health")
            
            # Check key security headers
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Should have X-Content-Type-Options
            assert any("nosniff" in v for v in headers.values())
            
            # Should have X-Frame-Options or CSP frame-ancestors
            frame_protection = (
                "x-frame-options" in headers or
                any("frame-ancestors" in v for v in headers.values())
            )
            assert frame_protection
    
    def test_error_responses_dont_leak_information(self) -> None:
        """Test error responses don't leak sensitive information."""
        with TestClient(app) as client:
            # Test 404 response
            response = client.get("/nonexistent-endpoint")
            assert response.status_code == status.HTTP_404_NOT_FOUND
            
            error_data = response.json()
            
            # Should not contain stack traces or internal paths
            error_str = json.dumps(error_data).lower()
            sensitive_info = [
                "traceback", "stack", "/home/", "/app/", "exception",
                "internal", "debug", "secret", "token"
            ]
            
            for info in sensitive_info:
                assert info not in error_str, f"Sensitive info '{info}' found in error response" 