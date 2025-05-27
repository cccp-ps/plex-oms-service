"""
Unit tests for OAuth and request validation utilities.

Tests for secure OAuth state parameter validation, Plex token format validation,
redirect URI validation, and callback parameter sanitization.

Follows TDD principles with comprehensive test coverage for security-critical validation.
"""

import pytest

from app.utils.validators import (
    validate_oauth_state,
    validate_plex_token_format,
    validate_redirect_uri,
    sanitize_callback_parameters,
    ValidationError,
)


class TestOAuthStateValidation:
    """Test cases for OAuth state parameter validation."""

    def test_valid_state_parameter_passes_validation(self) -> None:
        """Test that valid state parameters pass validation."""
        # Valid state should be at least 32 characters, URL-safe
        valid_state = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12345"
        
        result = validate_oauth_state(valid_state)
        assert result is True

    def test_short_state_parameter_fails_validation(self) -> None:
        """Test that state parameters shorter than 32 characters fail validation."""
        short_state = "too_short"
        
        with pytest.raises(ValidationError, match="State parameter must be at least 32 characters"):
            _ = validate_oauth_state(short_state)

    def test_empty_state_parameter_fails_validation(self) -> None:
        """Test that empty state parameters fail validation."""
        with pytest.raises(ValidationError, match="State parameter cannot be empty"):
            _ = validate_oauth_state("")

    def test_none_state_parameter_fails_validation(self) -> None:
        """Test that None state parameters fail validation."""
        with pytest.raises(ValidationError, match="State parameter cannot be empty"):
            _ = validate_oauth_state(None)

    def test_whitespace_only_state_fails_validation(self) -> None:
        """Test that whitespace-only state parameters fail validation."""
        whitespace_state = "   \t\n   "
        
        with pytest.raises(ValidationError, match="State parameter cannot be empty"):
            _ = validate_oauth_state(whitespace_state)

    def test_state_with_invalid_characters_fails_validation(self) -> None:
        """Test that state parameters with invalid characters fail validation."""
        # State with spaces and special characters that aren't URL-safe
        invalid_state = "This has spaces and special chars!"
        
        with pytest.raises(ValidationError, match="State parameter contains invalid characters"):
            _ = validate_oauth_state(invalid_state)

    def test_sql_injection_in_state_fails_validation(self) -> None:
        """Test that potential SQL injection attempts in state fail validation."""
        sql_injection_state = "'; DROP TABLE users; --"
        
        with pytest.raises(ValidationError, match="State parameter contains invalid characters"):
            _ = validate_oauth_state(sql_injection_state)

    def test_script_injection_in_state_fails_validation(self) -> None:
        """Test that potential script injection attempts in state fail validation."""
        script_injection_state = "<script>alert('xss')</script>"
        
        with pytest.raises(ValidationError, match="State parameter contains invalid characters"):
            _ = validate_oauth_state(script_injection_state)


class TestPlexTokenFormatValidation:
    """Test cases for Plex token format validation."""

    def test_valid_plex_token_passes_validation(self) -> None:
        """Test that valid Plex tokens pass validation."""
        # Typical Plex token format: 20+ alphanumeric characters
        valid_token = "xYz123AbC789DeF456GhI012"
        
        result = validate_plex_token_format(valid_token)
        assert result is True

    def test_short_plex_token_fails_validation(self) -> None:
        """Test that tokens shorter than minimum length fail validation."""
        short_token = "too_short"
        
        with pytest.raises(ValidationError, match="Plex token must be at least 20 characters"):
            _ = validate_plex_token_format(short_token)

    def test_empty_plex_token_fails_validation(self) -> None:
        """Test that empty tokens fail validation."""
        with pytest.raises(ValidationError, match="Plex token cannot be empty"):
            _ = validate_plex_token_format("")

    def test_none_plex_token_fails_validation(self) -> None:
        """Test that None tokens fail validation."""
        with pytest.raises(ValidationError, match="Plex token cannot be empty"):
            _ = validate_plex_token_format(None)

    def test_plex_token_with_invalid_characters_fails_validation(self) -> None:
        """Test that tokens with invalid characters fail validation."""
        # Plex tokens should be alphanumeric
        invalid_token = "invalid-token-with-dashes!"
        
        with pytest.raises(ValidationError, match="Plex token contains invalid characters"):
            _ = validate_plex_token_format(invalid_token)

    def test_plex_token_with_spaces_fails_validation(self) -> None:
        """Test that tokens with spaces fail validation."""
        token_with_spaces = "token with spaces in middle"
        
        with pytest.raises(ValidationError, match="Plex token contains invalid characters"):
            _ = validate_plex_token_format(token_with_spaces)

    def test_plex_token_too_long_fails_validation(self) -> None:
        """Test that excessively long tokens fail validation."""
        # Very long token (over 200 characters)
        long_token = "a" * 201
        
        with pytest.raises(ValidationError, match="Plex token is too long"):
            _ = validate_plex_token_format(long_token)


class TestRedirectUriValidation:
    """Test cases for OAuth redirect URI validation."""

    def test_valid_http_localhost_uri_passes_validation(self) -> None:
        """Test that valid localhost HTTP URIs pass validation."""
        valid_uri = "http://localhost:8000/auth/callback"
        
        result = validate_redirect_uri(valid_uri)
        assert result is True

    def test_valid_https_uri_passes_validation(self) -> None:
        """Test that valid HTTPS URIs pass validation."""
        valid_uri = "https://myapp.example.com/auth/callback"
        
        result = validate_redirect_uri(valid_uri)
        assert result is True

    def test_non_http_scheme_fails_validation(self) -> None:
        """Test that non-HTTP/HTTPS schemes fail validation."""
        invalid_uri = "ftp://example.com/callback"
        
        with pytest.raises(ValidationError, match="Redirect URI must use HTTP or HTTPS scheme"):
            _ = validate_redirect_uri(invalid_uri)

    def test_empty_redirect_uri_fails_validation(self) -> None:
        """Test that empty URIs fail validation."""
        with pytest.raises(ValidationError, match="Redirect URI cannot be empty"):
            _ = validate_redirect_uri("")

    def test_none_redirect_uri_fails_validation(self) -> None:
        """Test that None URIs fail validation."""
        with pytest.raises(ValidationError, match="Redirect URI cannot be empty"):
            _ = validate_redirect_uri(None)

    def test_malformed_uri_fails_validation(self) -> None:
        """Test that malformed URIs fail validation."""
        malformed_uri = "not-a-valid-uri"
        
        with pytest.raises(ValidationError, match="Invalid redirect URI format"):
            _ = validate_redirect_uri(malformed_uri)

    def test_uri_with_fragment_fails_validation(self) -> None:
        """Test that URIs with fragments fail validation for security."""
        uri_with_fragment = "https://example.com/callback#fragment"
        
        with pytest.raises(ValidationError, match="Redirect URI cannot contain fragments"):
            _ = validate_redirect_uri(uri_with_fragment)

    def test_http_non_localhost_fails_validation(self) -> None:
        """Test that HTTP URIs for non-localhost fail validation."""
        insecure_uri = "http://example.com/callback"
        
        with pytest.raises(ValidationError, match="HTTP redirect URIs are only allowed for localhost"):
            _ = validate_redirect_uri(insecure_uri)

    def test_uri_with_credentials_fails_validation(self) -> None:
        """Test that URIs with embedded credentials fail validation."""
        uri_with_creds = "https://user:pass@example.com/callback"
        
        with pytest.raises(ValidationError, match="Redirect URI cannot contain credentials"):
            _ = validate_redirect_uri(uri_with_creds)


class TestCallbackParameterSanitization:
    """Test cases for OAuth callback parameter sanitization."""

    def test_valid_callback_parameters_are_sanitized(self) -> None:
        """Test that valid callback parameters are properly sanitized."""
        params = {
            "code": "valid_auth_code_123",
            "state": "valid_state_parameter_456",
            "error": None,
            "error_description": None
        }
        
        sanitized = sanitize_callback_parameters(params)
        
        assert sanitized["code"] == "valid_auth_code_123"
        assert sanitized["state"] == "valid_state_parameter_456"
        assert "error" not in sanitized
        assert "error_description" not in sanitized

    def test_parameters_with_xss_attempts_are_sanitized(self) -> None:
        """Test that XSS attempts in parameters are properly sanitized."""
        params = {
            "code": "<script>alert('xss')</script>",
            "state": "javascript:alert('xss')",
            "error": "<img src=x onerror=alert('xss')>"
        }
        
        sanitized = sanitize_callback_parameters(params)
        
        # Should remove or escape dangerous content
        assert "<script>" not in sanitized.get("code", "")
        assert "javascript:" not in sanitized.get("state", "")
        assert "<img" not in sanitized.get("error", "")

    def test_parameters_with_sql_injection_are_sanitized(self) -> None:
        """Test that SQL injection attempts in parameters are sanitized."""
        params = {
            "code": "'; DROP TABLE users; --",
            "state": "1 OR 1=1",
            "custom_param": "UNION SELECT * FROM secrets"
        }
        
        sanitized = sanitize_callback_parameters(params)
        
        # Should only contain safe alphanumeric characters
        for _, value in sanitized.items():
            assert "DROP" not in str(value)
            assert "UNION" not in str(value)
            assert "SELECT" not in str(value)

    def test_empty_parameters_are_handled_correctly(self) -> None:
        """Test that empty parameter dictionaries are handled correctly."""
        params: dict[str, object] = {}
        
        sanitized = sanitize_callback_parameters(params)
        
        assert isinstance(sanitized, dict)
        assert len(sanitized) == 0

    def test_none_parameters_are_handled_correctly(self) -> None:
        """Test that None parameter input is handled correctly."""
        sanitized = sanitize_callback_parameters(None)
        
        assert isinstance(sanitized, dict)
        assert len(sanitized) == 0

    def test_non_string_parameters_are_handled_correctly(self) -> None:
        """Test that non-string parameters are handled appropriately."""
        params = {
            "code": 12345,
            "state": ["not", "a", "string"],
            "valid_param": "valid_string",
            "none_param": None
        }
        
        sanitized = sanitize_callback_parameters(params)
        
        # Should only include valid string parameters
        assert "valid_param" in sanitized
        assert sanitized["valid_param"] == "valid_string"
        assert "none_param" not in sanitized

    def test_excessively_long_parameters_are_truncated(self) -> None:
        """Test that excessively long parameters are truncated for security."""
        long_value = "a" * 10000  # Very long parameter value
        params = {
            "code": long_value,
            "state": "normal_state"
        }
        
        sanitized = sanitize_callback_parameters(params)
        
        # Should truncate long values
        assert len(sanitized.get("code", "")) <= 1000  # Reasonable max length
        assert sanitized["state"] == "normal_state"

    def test_known_dangerous_patterns_are_removed(self) -> None:
        """Test that known dangerous patterns are completely removed."""
        params = {
            "code": "data:text/html,<script>alert('xss')</script>",
            "state": "vbscript:msgbox('xss')",
            "error": "file:///etc/passwd"
        }
        
        sanitized = sanitize_callback_parameters(params)
        
        # These dangerous patterns should be completely removed
        for value in sanitized.values():
            assert "data:" not in str(value)
            assert "vbscript:" not in str(value)
            assert "file://" not in str(value) 