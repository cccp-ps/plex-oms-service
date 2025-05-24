"""
Configuration management module for Plex Online Media Sources Manager.

Uses Pydantic BaseSettings for environment variable handling with validation.
Supports OAuth configuration, CORS settings, and security validation.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application configuration using Pydantic BaseSettings with environment variables.
    
    This class handles all configuration for the Plex OMS Service, including:
    - OAuth credentials for Plex API integration
    - Security settings (secret keys, rate limiting, CORS)
    - Environment-specific configuration (development, production, testing)
    
    All required fields must be provided via environment variables.
    """
    
    # Environment and debugging
    environment: Literal["development", "production", "testing"] = Field(
        default="production", 
        alias="ENVIRONMENT",
        description="Application environment (development, production, testing)"
    )
    debug: bool = Field(
        default=False,
        description="Debug mode - automatically set based on environment"
    )
    
    # OAuth Configuration - Required
    plex_client_id: str = Field(
        alias="PLEX_CLIENT_ID",
        description="Plex OAuth client ID (required)"
    )
    plex_client_secret: SecretStr = Field(
        alias="PLEX_CLIENT_SECRET", 
        description="Plex OAuth client secret (required)"
    )
    
    # OAuth Configuration - Optional with defaults
    oauth_redirect_uri: str = Field(
        default="http://localhost:8000/auth/callback",
        alias="OAUTH_REDIRECT_URI",
        description="OAuth redirect URI for callback handling"
    )
    oauth_scopes: str = Field(
        default="read",
        alias="OAUTH_SCOPES", 
        description="OAuth scopes (comma-separated)"
    )
    
    # Security Configuration
    secret_key: SecretStr = Field(
        alias="SECRET_KEY",
        min_length=32,
        description="Secret key for session encryption (minimum 32 characters)"
    )
    
    # CORS Configuration
    cors_origins: str = Field(
        default="http://localhost:3000",
        alias="CORS_ORIGINS",
        description="Allowed CORS origins (comma-separated)"
    )
    
    # Rate limiting and security
    rate_limit_enabled: bool = Field(
        default=True,
        alias="RATE_LIMIT_ENABLED",
        description="Enable rate limiting for API endpoints"
    )
    session_expire_minutes: int = Field(
        default=60,
        alias="SESSION_EXPIRE_MINUTES",
        description="Session expiration time in minutes"
    )
    
    @model_validator(mode='after')
    def set_environment_specific_values(self) -> 'Settings':
        """Set debug and rate limiting based on environment after validation."""
        # Set debug mode based on environment
        if self.environment == "development":
            object.__setattr__(self, 'debug', True)
        elif self.environment == "production":
            object.__setattr__(self, 'debug', False)
        
        # Disable rate limiting in testing environment
        if self.environment == "testing":
            object.__setattr__(self, 'rate_limit_enabled', False)
            
        return self
    
    # Computed properties for parsed values
    @property
    def cors_origins_list(self) -> list[str]:
        """Parse CORS origins from comma-separated string into a list."""
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]
    
    @property 
    def oauth_scopes_list(self) -> list[str]:
        """Parse OAuth scopes from comma-separated string into a list."""
        return [scope.strip() for scope in self.oauth_scopes.split(",") if scope.strip()]
    
    model_config = SettingsConfigDict(  # pyright: ignore[reportUnannotatedClassAttribute]
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        validate_assignment=True,
        extra="ignore"
    )


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    Uses LRU cache to ensure settings are loaded only once.
    Requires proper environment variables to be set.
    
    Returns:
        Settings: Cached configuration instance
        
    Raises:
        ValidationError: If required environment variables are missing or invalid
    """
    return Settings()  # pyright: ignore[reportCallIssue] 