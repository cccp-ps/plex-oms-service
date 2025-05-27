"""
Unit tests for custom exception classes.

Tests all custom exception functionality including:
- Exception initialization and messaging
- PlexAPI error mapping and transformation 
- Privacy-focused error handling
- Exception hierarchy correctness
"""

from unittest.mock import patch

from app.utils.exceptions import (
    PlexAPIException,
    AuthenticationException,
    AuthorizationException,
    ConnectionException,
    RateLimitException,
    ValidationException,
    handle_plexapi_error,
)


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