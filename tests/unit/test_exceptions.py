"""
Unit tests for custom exception classes.

Tests all custom exception functionality including:
- Exception initialization and messaging
- PlexAPI error mapping and transformation 
- Privacy-focused error handling
- Exception hierarchy correctness
- Global FastAPI exception handlers
"""

from unittest.mock import patch, MagicMock
import json
import pytest

from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.utils.exceptions import (
    PlexAPIException,
    AuthenticationException,
    AuthorizationException,
    ConnectionException,
    RateLimitException,
    ValidationException,
    handle_plexapi_error,
)


def _parse_json_response(response: JSONResponse) -> dict[str, object]:
    """Helper function to parse JSONResponse content and return typed dict."""
    response_content = response.body
    return json.loads(bytes(response_content).decode('utf-8'))  # pyright: ignore[reportAny]


class TestPlexAPIException:
    """Test base PlexAPI exception class."""

    def test_exception_initialization_with_message_only(self) -> None:
        """Test PlexAPIException initialization with message only."""
        message = "Test error message"
        exception = PlexAPIException(message)
        
        assert str(exception) == message
        assert exception.message == message
        assert exception.original_error is None

    def test_exception_initialization_with_original_error(self) -> None:
        """Test PlexAPIException initialization with original error."""
        message = "Test error message"
        original_error = ValueError("Original error")
        exception = PlexAPIException(message, original_error)
        
        assert str(exception) == message
        assert exception.message == message
        assert exception.original_error is original_error

    def test_exception_is_subclass_of_exception(self) -> None:
        """Test that PlexAPIException is a proper Exception subclass."""
        exception = PlexAPIException("test")
        assert isinstance(exception, Exception)

    def test_exception_str_method(self) -> None:
        """Test __str__ method returns user-friendly message."""
        message = "User-friendly error message"
        exception = PlexAPIException(message)
        assert str(exception) == message


class TestAuthenticationException:
    """Test authentication exception class."""

    def test_authentication_exception_default_message(self) -> None:
        """Test AuthenticationException with default message."""
        exception = AuthenticationException()
        
        assert str(exception) == "Authentication failed"
        assert exception.message == "Authentication failed"
        assert exception.original_error is None

    def test_authentication_exception_custom_message(self) -> None:
        """Test AuthenticationException with custom message."""
        message = "Token expired"
        exception = AuthenticationException(message)
        
        assert str(exception) == message
        assert exception.message == message

    def test_authentication_exception_with_original_error(self) -> None:
        """Test AuthenticationException preserves original error."""
        original_error = ValueError("Invalid token format")
        exception = AuthenticationException("Authentication failed", original_error)
        
        assert exception.original_error is original_error

    def test_authentication_exception_is_plexapi_exception(self) -> None:
        """Test that AuthenticationException inherits from PlexAPIException."""
        exception = AuthenticationException()
        assert isinstance(exception, PlexAPIException)
        assert isinstance(exception, Exception)


class TestAuthorizationException:
    """Test authorization exception class."""

    def test_authorization_exception_default_message(self) -> None:
        """Test AuthorizationException with default message."""
        exception = AuthorizationException()
        
        assert str(exception) == "Access denied"
        assert exception.message == "Access denied"
        assert exception.original_error is None

    def test_authorization_exception_custom_message(self) -> None:
        """Test AuthorizationException with custom message."""
        message = "Insufficient permissions"
        exception = AuthorizationException(message)
        
        assert str(exception) == message
        assert exception.message == message

    def test_authorization_exception_with_original_error(self) -> None:
        """Test AuthorizationException preserves original error."""
        original_error = PermissionError("Access denied by server")
        exception = AuthorizationException("Access denied", original_error)
        
        assert exception.original_error is original_error

    def test_authorization_exception_is_plexapi_exception(self) -> None:
        """Test that AuthorizationException inherits from PlexAPIException."""
        exception = AuthorizationException()
        assert isinstance(exception, PlexAPIException)
        assert isinstance(exception, Exception)


class TestConnectionException:
    """Test connection exception class."""

    def test_connection_exception_default_message(self) -> None:
        """Test ConnectionException with default message."""
        exception = ConnectionException()
        
        assert str(exception) == "Connection failed"
        assert exception.message == "Connection failed"
        assert exception.original_error is None

    def test_connection_exception_custom_message(self) -> None:
        """Test ConnectionException with custom message."""
        message = "Network timeout"
        exception = ConnectionException(message)
        
        assert str(exception) == message
        assert exception.message == message

    def test_connection_exception_with_original_error(self) -> None:
        """Test ConnectionException preserves original error."""
        original_error = ConnectionError("Network unreachable")
        exception = ConnectionException("Connection failed", original_error)
        
        assert exception.original_error is original_error

    def test_connection_exception_is_plexapi_exception(self) -> None:
        """Test that ConnectionException inherits from PlexAPIException."""
        exception = ConnectionException()
        assert isinstance(exception, PlexAPIException)
        assert isinstance(exception, Exception)


class TestRateLimitException:
    """Test rate limit exception class."""

    def test_rate_limit_exception_default_message(self) -> None:
        """Test RateLimitException with default message."""
        exception = RateLimitException()
        
        assert str(exception) == "Rate limit exceeded"
        assert exception.message == "Rate limit exceeded"
        assert exception.original_error is None

    def test_rate_limit_exception_custom_message(self) -> None:
        """Test RateLimitException with custom message."""
        message = "Too many requests"
        exception = RateLimitException(message)
        
        assert str(exception) == message
        assert exception.message == message

    def test_rate_limit_exception_with_original_error(self) -> None:
        """Test RateLimitException preserves original error."""
        original_error = Exception("429 Too Many Requests")
        exception = RateLimitException("Rate limit exceeded", original_error)
        
        assert exception.original_error is original_error

    def test_rate_limit_exception_is_plexapi_exception(self) -> None:
        """Test that RateLimitException inherits from PlexAPIException."""
        exception = RateLimitException()
        assert isinstance(exception, PlexAPIException)
        assert isinstance(exception, Exception)


class TestValidationException:
    """Test validation exception class."""

    def test_validation_exception_default_message(self) -> None:
        """Test ValidationException with default message."""
        exception = ValidationException()
        
        assert str(exception) == "Validation failed"
        assert exception.message == "Validation failed"
        assert exception.original_error is None

    def test_validation_exception_custom_message(self) -> None:
        """Test ValidationException with custom message."""
        message = "Invalid input format"
        exception = ValidationException(message)
        
        assert str(exception) == message
        assert exception.message == message

    def test_validation_exception_with_original_error(self) -> None:
        """Test ValidationException preserves original error."""
        original_error = ValueError("Invalid data type")
        exception = ValidationException("Validation failed", original_error)
        
        assert exception.original_error is original_error

    def test_validation_exception_is_plexapi_exception(self) -> None:
        """Test that ValidationException inherits from PlexAPIException."""
        exception = ValidationException()
        assert isinstance(exception, PlexAPIException)
        assert isinstance(exception, Exception)


class TestHandlePlexAPIError:
    """Test PlexAPI error handling function."""

    # Create test exception classes that mimic PlexAPI exceptions
    class MockUnauthorized(Exception):
        """Mock Unauthorized exception for testing."""
        pass

    class MockBadRequest(Exception):
        """Mock BadRequest exception for testing."""  
        pass

    class MockNotFound(Exception):
        """Mock NotFound exception for testing."""
        pass

    def test_handle_unauthorized_with_token_keyword(self) -> None:
        """Test handling Unauthorized error with token in message."""
        with patch('plexapi.exceptions.Unauthorized', self.MockUnauthorized), \
             patch('plexapi.exceptions.BadRequest', self.MockBadRequest), \
             patch('plexapi.exceptions.NotFound', self.MockNotFound):
            error = self.MockUnauthorized("Invalid token provided")
            result = handle_plexapi_error(error, "user login")
            
            assert isinstance(result, AuthenticationException)
            assert "Authentication failed during user login" in str(result)
            assert result.original_error is error

    def test_handle_unauthorized_without_token_keyword(self) -> None:
        """Test handling Unauthorized error without token/auth keywords."""
        with patch('plexapi.exceptions.Unauthorized', self.MockUnauthorized), \
             patch('plexapi.exceptions.BadRequest', self.MockBadRequest), \
             patch('plexapi.exceptions.NotFound', self.MockNotFound):
            error = self.MockUnauthorized("Insufficient permissions")
            result = handle_plexapi_error(error, "media access")
            
            assert isinstance(result, AuthorizationException)
            assert "Access denied during media access" in str(result)
            assert result.original_error is error

    def test_handle_bad_request_with_connection_keyword(self) -> None:
        """Test handling BadRequest error with connection keywords."""
        with patch('plexapi.exceptions.Unauthorized', self.MockUnauthorized), \
             patch('plexapi.exceptions.BadRequest', self.MockBadRequest), \
             patch('plexapi.exceptions.NotFound', self.MockNotFound):
            error = self.MockBadRequest("Connection timeout occurred")
            result = handle_plexapi_error(error, "server ping")
            
            assert isinstance(result, ConnectionException)
            assert "Failed to connect to Plex API during server ping" in str(result)
            assert result.original_error is error

    def test_handle_bad_request_without_connection_keyword(self) -> None:
        """Test handling BadRequest error without connection keywords."""
        with patch('plexapi.exceptions.Unauthorized', self.MockUnauthorized), \
             patch('plexapi.exceptions.BadRequest', self.MockBadRequest), \
             patch('plexapi.exceptions.NotFound', self.MockNotFound):
            error = self.MockBadRequest("Invalid parameter value")
            result = handle_plexapi_error(error, "API call")
            
            assert isinstance(result, PlexAPIException)
            assert "Invalid request during API call" in str(result)
            assert result.original_error is error

    def test_handle_not_found_error(self) -> None:
        """Test handling NotFound error."""
        with patch('plexapi.exceptions.Unauthorized', self.MockUnauthorized), \
             patch('plexapi.exceptions.BadRequest', self.MockBadRequest), \
             patch('plexapi.exceptions.NotFound', self.MockNotFound):
            error = self.MockNotFound("Resource not found")
            result = handle_plexapi_error(error, "resource lookup")
            
            assert isinstance(result, PlexAPIException)
            assert "Resource not found during resource lookup" in str(result)
            assert result.original_error is error

    def test_handle_unknown_error(self) -> None:
        """Test handling unknown/unexpected error types."""
        error = RuntimeError("Unexpected runtime error")
        result = handle_plexapi_error(error, "unknown operation")
        
        assert isinstance(result, PlexAPIException)
        assert "Unexpected error during unknown operation" in str(result)
        assert "Unexpected runtime error" in str(result)
        assert result.original_error is error

    def test_handle_error_default_context(self) -> None:
        """Test error handling with default context."""
        error = ValueError("Test error")
        result = handle_plexapi_error(error)
        
        assert isinstance(result, PlexAPIException)
        assert "PlexAPI operation" in str(result)
        assert result.original_error is error

    def test_error_mapping_preserves_privacy(self) -> None:
        """Test that error mapping doesn't expose sensitive information."""
        with patch('plexapi.exceptions.Unauthorized', self.MockUnauthorized), \
             patch('plexapi.exceptions.BadRequest', self.MockBadRequest), \
             patch('plexapi.exceptions.NotFound', self.MockNotFound):
            # Test that sensitive details are not exposed in user-facing messages
            error = self.MockUnauthorized("API_KEY_12345_INVALID_TOKEN_SECRET")
            result = handle_plexapi_error(error, "authentication")
            
            # The user-facing message should not contain sensitive details
            assert "API_KEY" not in str(result)
            assert "SECRET" not in str(result)
            assert "Authentication failed during authentication" == str(result)
            
            # But original error should be preserved for debugging
            assert result.original_error is error

    def test_handle_unauthorized_with_authentication_keyword(self) -> None:
        """Test handling Unauthorized error with authentication keyword."""
        with patch('plexapi.exceptions.Unauthorized', self.MockUnauthorized), \
             patch('plexapi.exceptions.BadRequest', self.MockBadRequest), \
             patch('plexapi.exceptions.NotFound', self.MockNotFound):
            error = self.MockUnauthorized("Authentication failed for user")
            result = handle_plexapi_error(error, "user verification")
            
            assert isinstance(result, AuthenticationException)
            assert "Authentication failed during user verification" in str(result)
            assert result.original_error is error

    def test_handle_bad_request_with_network_keyword(self) -> None:
        """Test handling BadRequest error with network keyword."""
        with patch('plexapi.exceptions.Unauthorized', self.MockUnauthorized), \
             patch('plexapi.exceptions.BadRequest', self.MockBadRequest), \
             patch('plexapi.exceptions.NotFound', self.MockNotFound):
            error = self.MockBadRequest("Network error occurred")
            result = handle_plexapi_error(error, "server communication")
            
            assert isinstance(result, ConnectionException)
            assert "Failed to connect to Plex API during server communication" in str(result)
            assert result.original_error is error


class TestExceptionHierarchy:
    """Test the overall exception hierarchy structure."""

    def test_all_custom_exceptions_inherit_from_plexapi_exception(self) -> None:
        """Test that all custom exceptions inherit from PlexAPIException."""
        exceptions = [
            AuthenticationException(),
            AuthorizationException(),
            ConnectionException(),
            RateLimitException(),
            ValidationException(),
        ]
        
        for exception in exceptions:
            assert isinstance(exception, PlexAPIException)
            assert isinstance(exception, Exception)

    def test_exception_inheritance_chain(self) -> None:
        """Test the complete inheritance chain."""
        # Test method resolution order
        mro = AuthenticationException.__mro__
        expected_classes = [AuthenticationException, PlexAPIException, Exception, object]
        
        for expected_class in expected_classes:
            assert expected_class in mro

    def test_exception_types_are_distinct(self) -> None:
        """Test that different exception types are distinguishable."""
        auth_exc = AuthenticationException()
        authz_exc = AuthorizationException()
        conn_exc = ConnectionException()
        rate_exc = RateLimitException()
        valid_exc = ValidationException()
        
        # Each exception should be its own type
        assert type(auth_exc) is not type(authz_exc)
        assert type(auth_exc) is not type(conn_exc)
        assert type(conn_exc) is not type(rate_exc)
        assert type(rate_exc) is not type(valid_exc)
        
        # But all should be PlexAPIException instances
        exceptions = [auth_exc, authz_exc, conn_exc, rate_exc, valid_exc]
        for exc in exceptions:
            assert isinstance(exc, PlexAPIException) 


class TestGlobalExceptionHandlers:
    """Test global FastAPI exception handlers."""

    @pytest.mark.asyncio
    async def test_handle_plexapi_exceptions_with_user_friendly_messages(self) -> None:
        """Test case: Handle PlexAPI exceptions with user-friendly messages."""
        # Mock request
        request = MagicMock(spec=Request)
        request.method = "GET"
        request.url = MagicMock()
        request.url.path = "/api/test"  # pyright: ignore[reportAny]
        request.headers = {}
        
        # Test PlexAPIException handling - should return 500 with user-friendly message
        from app.utils.exceptions import plexapi_exception_handler
        exception = PlexAPIException("Connection to Plex server failed")
        
        response = await plexapi_exception_handler(request, exception)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == 500
        
        # Parse response content
        response_data = _parse_json_response(response)
        assert response_data["error"] == "Connection to Plex server failed"
        assert response_data["detail"] is None  # No sensitive details exposed
        assert "timestamp" in response_data

    @pytest.mark.asyncio
    async def test_handle_authentication_exceptions_with_proper_http_status(self) -> None:
        """Test case: Handle authentication exceptions with proper HTTP status."""
        # Mock request
        request = MagicMock(spec=Request)
        request.method = "POST"
        request.url = MagicMock()
        request.url.path = "/auth/login"  # pyright: ignore[reportAny]
        request.headers = {}
        
        # Test AuthenticationException handling - should return 401
        from app.utils.exceptions import authentication_exception_handler
        exception = AuthenticationException("Authentication failed")
        
        response = await authentication_exception_handler(request, exception)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == 401
        
        response_data = _parse_json_response(response)
        assert response_data["error"] == "Authentication failed"
        assert "timestamp" in response_data

    @pytest.mark.asyncio
    async def test_handle_authorization_exceptions_with_proper_http_status(self) -> None:
        """Test case: Handle authorization exceptions with proper HTTP status."""
        # Mock request
        request = MagicMock(spec=Request)
        request.method = "GET"
        request.url = MagicMock()
        request.url.path = "/api/media-sources"  # pyright: ignore[reportAny]
        request.headers = {}
        
        # Test AuthorizationException handling - should return 403
        from app.utils.exceptions import authorization_exception_handler
        exception = AuthorizationException("Insufficient permissions")
        
        response = await authorization_exception_handler(request, exception)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == 403
        
        response_data = _parse_json_response(response)
        assert response_data["error"] == "Insufficient permissions"

    @pytest.mark.asyncio
    async def test_handle_validation_exceptions(self) -> None:
        """Test case: Handle validation exceptions."""
        # Mock request
        request = MagicMock(spec=Request)
        request.method = "POST"
        request.url = MagicMock()
        request.url.path = "/api/media-sources/toggle"  # pyright: ignore[reportAny]
        request.headers = {}
        
        # Test ValidationException handling - should return 422
        from app.utils.exceptions import validation_exception_handler
        exception = ValidationException("Invalid media source ID format")
        
        response = await validation_exception_handler(request, exception)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == 422
        
        response_data = _parse_json_response(response)
        assert response_data["error"] == "Invalid media source ID format"

    @pytest.mark.asyncio
    async def test_handle_pydantic_validation_errors(self) -> None:
        """Test case: Handle Pydantic validation errors with proper formatting."""
        # Mock request
        request = MagicMock(spec=Request)
        request.method = "POST"
        request.url = MagicMock()
        request.url.path = "/api/test"  # pyright: ignore[reportAny]
        request.headers = {}
        
        # Create a mock ValidationError
        mock_error = MagicMock(spec=ValidationError)
        mock_error.errors.return_value = [  # pyright: ignore[reportAny]
            {
                "loc": ("field_name",),
                "msg": "field required",
                "type": "value_error.missing"
            }
        ]
        
        from app.utils.exceptions import pydantic_validation_exception_handler
        response = await pydantic_validation_exception_handler(request, mock_error)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == 422
        
        response_data = _parse_json_response(response)
        assert "error" in response_data
        assert "validation_errors" in response_data

    @pytest.mark.asyncio
    async def test_handle_connection_exceptions(self) -> None:
        """Test case: Handle connection exceptions with appropriate status."""
        # Mock request
        request = MagicMock(spec=Request)
        request.method = "GET"
        request.url = MagicMock()
        request.url.path = "/api/media-sources"  # pyright: ignore[reportAny]
        request.headers = {}
        
        # Test ConnectionException handling - should return 503
        from app.utils.exceptions import connection_exception_handler
        exception = ConnectionException("Unable to reach Plex server")
        
        response = await connection_exception_handler(request, exception)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == 503
        
        response_data = _parse_json_response(response)
        assert response_data["error"] == "Unable to reach Plex server"

    @pytest.mark.asyncio
    async def test_handle_rate_limit_exceptions(self) -> None:
        """Test case: Handle rate limit exceptions with retry information."""
        # Mock request
        request = MagicMock(spec=Request)
        request.method = "POST"
        request.url = MagicMock()
        request.url.path = "/api/media-sources/disable-all"  # pyright: ignore[reportAny]
        request.headers = {}
        
        # Test RateLimitException handling - should return 429
        from app.utils.exceptions import rate_limit_exception_handler
        exception = RateLimitException("Too many requests, please try again later")
        
        response = await rate_limit_exception_handler(request, exception)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == 429
        
        response_data = _parse_json_response(response)
        assert response_data["error"] == "Too many requests, please try again later"
        assert "retry_after" in response_data

    @pytest.mark.asyncio
    async def test_log_errors_without_exposing_sensitive_information(self) -> None:
        """Test case: Log errors without exposing sensitive information."""
        # Mock request with sensitive information
        request = MagicMock(spec=Request)
        request.method = "POST"
        request.url = MagicMock()
        request.url.path = "/auth/callback"  # pyright: ignore[reportAny]
        request.headers = {"authorization": "Bearer secret_token_12345"}
        
        # Mock logger
        with patch('app.utils.exceptions.logger') as mock_logger:
            from app.utils.exceptions import authentication_exception_handler
            exception = AuthenticationException(
                "Authentication failed", 
                original_error=Exception("Invalid token: secret_token_12345")
            )
            
            _ = await authentication_exception_handler(request, exception)
            
            # Verify logging was called
            assert mock_logger.error.called  # pyright: ignore[reportAny]
            
            # Check the call arguments - simplified approach
            call_args = mock_logger.error.call_args  # pyright: ignore[reportAny]
            if call_args:
                # Convert to string for safe checking
                call_str = str(call_args)  # pyright: ignore[reportAny]
                
                # Check that handler name is in the log
                assert "authentication_exception_handler" in call_str
                
                # Check that exception type is logged
                assert "AuthenticationException" in call_str
                
                # Check that headers don't contain sensitive auth info
                assert "authorization" not in call_str

    @pytest.mark.asyncio
    async def test_exception_handler_preserves_request_id(self) -> None:
        """Test case: Exception handlers preserve request ID for tracing."""
        # Mock request with request ID
        request = MagicMock(spec=Request)
        request.method = "GET"
        request.url = MagicMock()
        request.url.path = "/api/media-sources"  # pyright: ignore[reportAny]
        request.headers = {"x-request-id": "req_12345"}
        
        from app.utils.exceptions import plexapi_exception_handler
        exception = PlexAPIException("Test error")
        
        response = await plexapi_exception_handler(request, exception)
        response_data = _parse_json_response(response)
        
        # Should include request ID in response for debugging
        assert "request_id" in response_data
        assert response_data["request_id"] == "req_12345"

    @pytest.mark.asyncio
    async def test_exception_handlers_include_timestamp(self) -> None:
        """Test case: Exception handlers include timestamp for debugging."""
        # Mock request
        request = MagicMock(spec=Request)
        request.method = "GET"
        request.url = MagicMock()
        request.url.path = "/api/test"  # pyright: ignore[reportAny]
        request.headers = {}
        
        from app.utils.exceptions import plexapi_exception_handler
        exception = PlexAPIException("Test error")
        
        with patch('app.utils.exceptions.datetime') as mock_datetime:
            # Properly configure the mock to return expected values
            mock_datetime.now.return_value.isoformat.return_value = "2024-01-01T12:00:00"  # pyright: ignore[reportAny]
            
            response = await plexapi_exception_handler(request, exception)
            response_data = _parse_json_response(response)
            
            assert "timestamp" in response_data
            assert response_data["timestamp"] == "2024-01-01T12:00:00"

    @pytest.mark.asyncio
    async def test_exception_handlers_sanitize_error_messages(self) -> None:
        """Test case: Exception handlers sanitize error messages to prevent information disclosure."""
        # Mock request
        request = MagicMock(spec=Request)
        request.method = "POST"
        request.url = MagicMock()
        request.url.path = "/api/test"  # pyright: ignore[reportAny]
        request.headers = {}
        
        # Create exception with potentially sensitive information
        from app.utils.exceptions import plexapi_exception_handler
        exception = PlexAPIException("Database connection failed: password=secret123, host=internal.server.com")
        
        response = await plexapi_exception_handler(request, exception)
        response_data = _parse_json_response(response)
        
        # Should sanitize the error message
        error_message = str(response_data["error"])
        assert "secret123" not in error_message
        assert "internal.server.com" not in error_message
        
        # Check that password and host values are masked
        assert "password=***" in error_message
        assert "host=***" in error_message
        
        # But should still be informative
        assert "connection failed" in error_message.lower() 