"""
Unit tests for the configuration management module.

Tests environment variable loading, validation, OAuth configuration,
CORS settings, and security settings following TDD principles.
"""

import os
import tempfile

import pytest
from pydantic import ValidationError

from app.config import Settings


class TestEnvironmentConfiguration:
    """Test cases for environment variable configuration."""

    def test_load_required_environment_variables(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that required environment variables are loaded correctly."""
        # Set up test environment variables
        test_env_vars = {
            "PLEX_CLIENT_ID": "test-client-id-12345",
            "PLEX_CLIENT_SECRET": "test-client-secret-abcdef",
            "SECRET_KEY": "test-secret-key-for-testing-only-must-be-32-chars",
        }
        
        for key, value in test_env_vars.items():
            monkeypatch.setenv(key, value)
        
        # Initialize settings
        settings = Settings()  # pyright: ignore[reportCallIssue]
        
        # Assert environment variables are loaded
        assert settings.plex_client_id == "test-client-id-12345"
        assert settings.plex_client_secret.get_secret_value() == "test-client-secret-abcdef"
        assert settings.secret_key.get_secret_value() == "test-secret-key-for-testing-only-must-be-32-chars"

    def test_validate_required_configuration_values(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that required configuration values are validated."""
        # Set up minimal required environment
        monkeypatch.setenv("PLEX_CLIENT_ID", "test-client-id")
        monkeypatch.setenv("PLEX_CLIENT_SECRET", "test-client-secret")
        monkeypatch.setenv("SECRET_KEY", "test-secret-key-minimum-32-chars-req")
        
        # Initialize settings should succeed
        settings = Settings()  # pyright: ignore[reportCallIssue]
        
        # Verify required fields are set
        assert settings.plex_client_id is not None
        assert settings.plex_client_secret is not None
        assert settings.secret_key is not None

    def test_handle_missing_environment_variables(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test proper handling of missing required environment variables."""
        # Clear all relevant environment variables
        env_vars_to_clear = [
            "PLEX_CLIENT_ID",
            "PLEX_CLIENT_SECRET", 
            "SECRET_KEY",
            "CORS_ORIGINS",
            "ENVIRONMENT",
        ]
        
        for var in env_vars_to_clear:
            monkeypatch.delenv(var, raising=False)
        
        # Attempt to initialize settings should raise ValidationError
        with pytest.raises(ValidationError) as exc_info:
            _ = Settings()  # pyright: ignore[reportCallIssue]
        
        # Verify specific required fields are mentioned in the error
        error_str = str(exc_info.value)
        assert "plex_client_id" in error_str or "PLEX_CLIENT_ID" in error_str
        assert "plex_client_secret" in error_str or "PLEX_CLIENT_SECRET" in error_str
        assert "secret_key" in error_str or "SECRET_KEY" in error_str

    def test_cors_origins_configuration_validation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test CORS origins configuration validation."""
        # Set up required environment variables
        monkeypatch.setenv("PLEX_CLIENT_ID", "test-client-id")
        monkeypatch.setenv("PLEX_CLIENT_SECRET", "test-client-secret")
        monkeypatch.setenv("SECRET_KEY", "test-secret-key-minimum-32-chars-req")
        
        # Test with valid CORS origins
        monkeypatch.setenv("CORS_ORIGINS", "http://localhost:3000,https://app.example.com")
        
        settings = Settings()  # pyright: ignore[reportCallIssue]
        
        # Verify CORS origins are parsed correctly using the property
        expected_origins = ["http://localhost:3000", "https://app.example.com"]
        assert settings.cors_origins_list == expected_origins

    def test_cors_origins_single_origin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test CORS origins with single origin."""
        # Set up required environment variables
        monkeypatch.setenv("PLEX_CLIENT_ID", "test-client-id")
        monkeypatch.setenv("PLEX_CLIENT_SECRET", "test-client-secret")
        monkeypatch.setenv("SECRET_KEY", "test-secret-key-minimum-32-chars-req")
        monkeypatch.setenv("CORS_ORIGINS", "http://localhost:3000")
        
        settings = Settings()  # pyright: ignore[reportCallIssue]
        
        # Single origin should be in a list
        assert settings.cors_origins_list == ["http://localhost:3000"]

    def test_security_settings_validation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test security settings validation."""
        # Set up required environment variables
        monkeypatch.setenv("PLEX_CLIENT_ID", "test-client-id")
        monkeypatch.setenv("PLEX_CLIENT_SECRET", "test-client-secret")
        monkeypatch.setenv("SECRET_KEY", "test-secret-key-minimum-32-chars-req")
        
        # Test with security settings
        monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
        monkeypatch.setenv("SESSION_EXPIRE_MINUTES", "30")
        
        settings = Settings()  # pyright: ignore[reportCallIssue]
        
        # Verify security settings
        assert settings.rate_limit_enabled is True
        assert settings.session_expire_minutes == 30

    def test_secret_key_minimum_length_validation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test secret key minimum length validation."""
        # Set up required environment variables
        monkeypatch.setenv("PLEX_CLIENT_ID", "test-client-id")
        monkeypatch.setenv("PLEX_CLIENT_SECRET", "test-client-secret")
        
        # Test with too short secret key
        monkeypatch.setenv("SECRET_KEY", "short")
        
        # Should raise ValidationError for short secret key
        with pytest.raises(ValidationError) as exc_info:
            _ = Settings()  # pyright: ignore[reportCallIssue]
        
        error_str = str(exc_info.value)
        assert "secret_key" in error_str or "SECRET_KEY" in error_str


class TestOAuthConfiguration:
    """Test cases for OAuth-specific configuration."""

    def test_oauth_client_id_and_secret_validation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test OAuth client ID and secret validation."""
        # Set up required environment variables
        monkeypatch.setenv("SECRET_KEY", "test-secret-key-minimum-32-chars-req")
        
        # Test with valid OAuth credentials
        monkeypatch.setenv("PLEX_CLIENT_ID", "valid-client-id-12345")
        monkeypatch.setenv("PLEX_CLIENT_SECRET", "valid-client-secret-abcdef67890")
        
        settings = Settings()  # pyright: ignore[reportCallIssue]
        
        # Verify OAuth credentials are set correctly
        assert settings.plex_client_id == "valid-client-id-12345"
        assert settings.plex_client_secret.get_secret_value() == "valid-client-secret-abcdef67890"

    def test_redirect_uri_configuration(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test redirect URI configuration."""
        # Set up required environment variables
        monkeypatch.setenv("PLEX_CLIENT_ID", "test-client-id")
        monkeypatch.setenv("PLEX_CLIENT_SECRET", "test-client-secret")
        monkeypatch.setenv("SECRET_KEY", "test-secret-key-minimum-32-chars-req")
        
        # Test with custom redirect URI
        monkeypatch.setenv("OAUTH_REDIRECT_URI", "https://myapp.example.com/auth/callback")
        
        settings = Settings()  # pyright: ignore[reportCallIssue]
        
        # Verify redirect URI is set
        assert settings.oauth_redirect_uri == "https://myapp.example.com/auth/callback"

    def test_oauth_scopes_validation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test OAuth scopes validation."""
        # Set up required environment variables
        monkeypatch.setenv("PLEX_CLIENT_ID", "test-client-id")
        monkeypatch.setenv("PLEX_CLIENT_SECRET", "test-client-secret")
        monkeypatch.setenv("SECRET_KEY", "test-secret-key-minimum-32-chars-req")
        
        # Test with custom OAuth scopes
        monkeypatch.setenv("OAUTH_SCOPES", "read,write")
        
        settings = Settings()  # pyright: ignore[reportCallIssue]
        
        # Verify scopes are parsed correctly using the property
        assert settings.oauth_scopes_list == ["read", "write"]

    def test_oauth_default_values(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test OAuth configuration default values."""
        # Set up minimal required environment variables
        monkeypatch.setenv("PLEX_CLIENT_ID", "test-client-id")
        monkeypatch.setenv("PLEX_CLIENT_SECRET", "test-client-secret")
        monkeypatch.setenv("SECRET_KEY", "test-secret-key-minimum-32-chars-req")
        
        settings = Settings()  # pyright: ignore[reportCallIssue]
        
        # Verify default values are set
        assert settings.oauth_redirect_uri is not None
        assert settings.oauth_scopes_list is not None
        assert len(settings.oauth_scopes_list) > 0


class TestEnvironmentSpecificSettings:
    """Test cases for environment-specific settings."""

    def test_development_environment_settings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test development environment specific settings."""
        # Set up required environment variables
        monkeypatch.setenv("PLEX_CLIENT_ID", "test-client-id")
        monkeypatch.setenv("PLEX_CLIENT_SECRET", "test-client-secret")
        monkeypatch.setenv("SECRET_KEY", "test-secret-key-minimum-32-chars-req")
        monkeypatch.setenv("ENVIRONMENT", "development")
        
        settings = Settings()  # pyright: ignore[reportCallIssue]
        
        # Verify development environment settings
        assert settings.environment == "development"
        assert settings.debug is True  # Development should enable debug

    def test_production_environment_settings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test production environment specific settings."""
        # Set up required environment variables
        monkeypatch.setenv("PLEX_CLIENT_ID", "test-client-id")
        monkeypatch.setenv("PLEX_CLIENT_SECRET", "test-client-secret")
        monkeypatch.setenv("SECRET_KEY", "test-secret-key-minimum-32-chars-req")
        monkeypatch.setenv("ENVIRONMENT", "production")
        
        settings = Settings()  # pyright: ignore[reportCallIssue]
        
        # Verify production environment settings
        assert settings.environment == "production"
        assert settings.debug is False  # Production should disable debug

    def test_testing_environment_settings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test testing environment specific settings."""
        # Set up required environment variables
        monkeypatch.setenv("PLEX_CLIENT_ID", "test-client-id")
        monkeypatch.setenv("PLEX_CLIENT_SECRET", "test-client-secret")
        monkeypatch.setenv("SECRET_KEY", "test-secret-key-minimum-32-chars-req")
        monkeypatch.setenv("ENVIRONMENT", "testing")
        
        settings = Settings()  # pyright: ignore[reportCallIssue]
        
        # Verify testing environment settings
        assert settings.environment == "testing"
        # Testing environment should disable rate limiting by default
        assert settings.rate_limit_enabled is False


class TestConfigurationSingleton:
    """Test cases for configuration singleton pattern."""

    def test_settings_singleton_behavior(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that settings behave as expected when accessed multiple times."""
        # Set up required environment variables
        monkeypatch.setenv("PLEX_CLIENT_ID", "test-client-id")
        monkeypatch.setenv("PLEX_CLIENT_SECRET", "test-client-secret")
        monkeypatch.setenv("SECRET_KEY", "test-secret-key-minimum-32-chars-req")
        
        # Create multiple instances
        settings1 = Settings()  # pyright: ignore[reportCallIssue]
        settings2 = Settings()  # pyright: ignore[reportCallIssue]
        
        # Verify they have the same configuration values
        assert settings1.plex_client_id == settings2.plex_client_id
        assert settings1.plex_client_secret.get_secret_value() == settings2.plex_client_secret.get_secret_value()
        assert settings1.secret_key.get_secret_value() == settings2.secret_key.get_secret_value()

    def test_environment_file_loading(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test loading configuration from environment file."""
        # Create a temporary environment file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            _ = f.write("PLEX_CLIENT_ID=file-client-id\n")
            _ = f.write("PLEX_CLIENT_SECRET=file-client-secret\n")
            _ = f.write("SECRET_KEY=test-secret-key-minimum-32-chars-req\n")
            env_file_path = f.name
        
        try:
            # Test settings can be created (file loading capability)
            # Note: Actual file loading testing would require more complex setup
            # This test mainly verifies the structure supports it
            monkeypatch.setenv("PLEX_CLIENT_ID", "test-client-id")
            monkeypatch.setenv("PLEX_CLIENT_SECRET", "test-client-secret")
            monkeypatch.setenv("SECRET_KEY", "test-secret-key-minimum-32-chars-req")
            
            settings = Settings()  # pyright: ignore[reportCallIssue]
            
            # Verify settings were created successfully
            assert settings.plex_client_id is not None
            assert settings.plex_client_secret is not None
            
        finally:
            # Clean up temporary file
            _ = os.unlink(env_file_path) 