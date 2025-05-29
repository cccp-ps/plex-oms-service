"""
Authentication request and response schemas.

Pydantic models for OAuth authentication endpoints including:
- OAuth initiation request and response
- OAuth callback request and response
- Session management schemas

Following security best practices with proper validation.
"""

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

from app.models.plex_models import PlexUser


class OAuthInitiationRequest(BaseModel):
    """Request schema for OAuth initiation endpoint."""
    
    redirect_uri: HttpUrl = Field(
        default=HttpUrl("http://localhost:8000/auth/callback"),
        description="OAuth redirect URI for callback after authorization",
        examples=["https://app.example.com/auth/callback", "http://localhost:3000/auth/callback"]
    )
    
    scopes: list[str] = Field(
        default=["read"],
        min_length=1,
        description="OAuth scopes requested for authorization",
        examples=[["read"], ["read", "write"]]
    )
    
    forward_url: HttpUrl | None = Field(
        default=None,
        description="Optional URL to redirect to after OAuth completion",
        examples=["http://localhost:3000/dashboard", "https://example.com/callback"]
    )
    
    @field_validator('scopes')
    @classmethod
    def validate_scopes_not_empty(cls, v: list[str]) -> list[str]:
        """Validate scopes list is not empty."""
        if not v or len(v) == 0:
            raise ValueError('Scopes list cannot be empty')
        return v
    
    model_config = ConfigDict(  # pyright: ignore[reportUnannotatedClassAttribute]
        # Ensure model is immutable after creation for security
        frozen=True,
        # Use enums by value for JSON serialization
        use_enum_values=True,
        # Validate assignment to catch errors early
        validate_assignment=True,
        # Populate by name to handle API field name variations
        populate_by_name=True,
        # Extra fields not allowed to maintain data minimization
        extra="forbid",
    )


class OAuthInitiationResponse(BaseModel):
    """Response schema for OAuth initiation endpoint."""
    
    oauth_url: str = Field(
        ...,
        description="OAuth URL for direct Plex account login",
        examples=["https://app.plex.tv/auth/#!?clientID=test&code=abc123"]
    )
    
    state: str = Field(
        ...,
        min_length=32,
        description="Secure state parameter for CSRF protection",
        examples=["abcdef123456789_secure_state_parameter_that_is_at_least_32_chars"]
    )
    
    code: str = Field(
        ...,
        min_length=1,
        description="OAuth authorization code for tracking the flow",
        examples=["auth-code-12345"]
    )
    
    expires_at: datetime | None = Field(
        default=None,
        description="When the OAuth state expires (UTC timestamp)",
    )
    
    @field_validator('oauth_url')
    @classmethod
    def validate_oauth_url(cls, v: str) -> str:
        """Validate OAuth URL format."""
        if not v.startswith("https://app.plex.tv/auth"):
            raise ValueError("OAuth URL must be a valid Plex OAuth URL")
        return v
    
    @field_validator('state')
    @classmethod
    def validate_state(cls, v: str) -> str:
        """Validate state parameter security."""
        if len(v) < 32:
            raise ValueError("State parameter must be at least 32 characters")
        # Verify only URL-safe characters
        import string
        allowed_chars = string.ascii_letters + string.digits + "-_"
        if not all(c in allowed_chars for c in v):
            raise ValueError("State parameter must contain only URL-safe characters")
        return v


class OAuthCallbackRequest(BaseModel):
    """Request schema for OAuth callback endpoint."""
    
    code: str = Field(
        ...,
        min_length=1,
        description="OAuth authorization code from Plex callback",
        examples=["auth-code-12345"]
    )
    
    state: str = Field(
        ...,
        min_length=32,
        description="State parameter for CSRF protection validation",
        examples=["abcdef123456789_secure_state_parameter_that_is_at_least_32_chars"]
    )


class OAuthCallbackResponse(BaseModel):
    """Response schema for OAuth callback endpoint."""
    
    access_token: str = Field(
        ...,
        description="Plex authentication token",
        examples=["plex-token-abcdef123456"]
    )
    
    token_type: Literal["Bearer"] = Field(
        default="Bearer",
        description="Token type (always Bearer for OAuth 2.0)"
    )
    
    user: PlexUser = Field(
        ...,
        description="User information from Plex account"
    )
    
    expires_in: int = Field(
        ...,
        ge=0,
        description="Token expiration time in seconds"
    )
    
    model_config = ConfigDict(  # pyright: ignore[reportUnannotatedClassAttribute]
        # Ensure model is immutable after creation for security
        frozen=True,
        # Use enums by value for JSON serialization
        use_enum_values=True,
        # Validate assignment to catch errors early
        validate_assignment=True,
        # Populate by name to handle API field name variations
        populate_by_name=True,
        # Extra fields not allowed to maintain data minimization
        extra="forbid",
    )


class AuthStatusResponse(BaseModel):
    """Response schema for authentication status endpoint."""
    
    authenticated: bool = Field(
        ...,
        description="Whether user is currently authenticated"
    )
    
    user: dict[str, object] | None = Field(
        default=None,
        description="User information if authenticated"
    )


class LogoutResponse(BaseModel):
    """Response schema for logout endpoint."""
    
    success: bool = Field(
        default=True,
        description="Whether logout was successful"
    )
    
    message: str = Field(
        default="Successfully logged out",
        description="Logout confirmation message"
    )


class TokenRefreshRequest(BaseModel):
    """
    Request schema for token refresh.
    
    Used for POST /auth/refresh endpoint to refresh an expired or
    soon-to-expire access token using a refresh token.
    """
    
    refresh_token: str = Field(
        ...,
        min_length=1,
        description="Refresh token for obtaining new access token",
        examples=["refresh-token-abcdef123456"]
    )
    
    @field_validator('refresh_token')
    @classmethod
    def validate_refresh_token_not_empty(cls, v: str) -> str:
        """Validate refresh token is not empty or whitespace-only."""
        if not v or not v.strip():
            raise ValueError('Refresh token cannot be empty or whitespace-only')
        return v.strip()
    
    model_config = ConfigDict(  # pyright: ignore[reportUnannotatedClassAttribute]
        # Ensure model is immutable after creation for security
        frozen=True,
        # Use enums by value for JSON serialization
        use_enum_values=True,
        # Validate assignment to catch errors early
        validate_assignment=True,
        # Populate by name to handle API field name variations
        populate_by_name=True,
        # Extra fields not allowed to maintain data minimization
        extra="forbid",
    )


class TokenRefreshResponse(BaseModel):
    """
    Response schema for successful token refresh.
    
    Returned by POST /auth/refresh endpoint after successful token refresh
    with MyPlexAccount token validation.
    """
    
    access_token: str = Field(
        ...,
        min_length=1,
        description="New Plex access token for API authentication",
        examples=["new-access-token-12345"]
    )
    
    token_type: Literal["Bearer"] = Field(
        default="Bearer",
        description="Token type (always Bearer for OAuth 2.0)",
        examples=["Bearer"]
    )
    
    expires_in: int = Field(
        ...,
        ge=0,
        description="New token expiration time in seconds from now",
        examples=[3600, 7200]
    )
    
    refresh_token: str | None = Field(
        default=None,
        description="New refresh token (if rotation is enabled)",
        examples=["new-refresh-token-67890"]
    )
    
    @field_validator('access_token')
    @classmethod
    def validate_access_token_not_empty(cls, v: str) -> str:
        """Validate access token is not empty or whitespace-only."""
        if not v or not v.strip():
            raise ValueError('Access token cannot be empty or whitespace-only')
        return v.strip()
    
    model_config = ConfigDict(  # pyright: ignore[reportUnannotatedClassAttribute]
        # Ensure model is immutable after creation for security
        frozen=True,
        # Use enums by value for JSON serialization
        use_enum_values=True,
        # Validate assignment to catch errors early
        validate_assignment=True,
        # Populate by name to handle API field name variations
        populate_by_name=True,
        # Extra fields not allowed to maintain data minimization
        extra="forbid",
    )


class AuthenticationErrorResponse(BaseModel):
    """
    Response schema for authentication errors.
    
    Used by all authentication endpoints to return standardized error responses
    following OAuth 2.0 error format and privacy-compliant error handling.
    
    Designed to provide helpful error information without exposing sensitive details.
    """
    
    error: str = Field(
        ...,
        min_length=1,
        description="OAuth 2.0 error code (e.g., invalid_request, invalid_grant)",
        examples=["invalid_request", "invalid_grant", "access_denied", "server_error"]
    )
    
    error_description: str | None = Field(
        default=None,
        description="Human-readable error description (optional)",
        examples=["The request is missing a required parameter", "Invalid authorization code"]
    )
    
    error_code: str | None = Field(
        default=None,
        description="Application-specific error code for debugging (optional)",
        examples=["AUTH_001", "AUTH_002", "PLEX_API_ERROR"]
    )
    
    @field_validator('error')
    @classmethod
    def validate_error_not_empty(cls, v: str) -> str:
        """Validate error code is not empty or whitespace-only."""
        if not v or not v.strip():
            raise ValueError('Error code cannot be empty or whitespace-only')
        return v.strip()
    
    model_config = ConfigDict(  # pyright: ignore[reportUnannotatedClassAttribute]
        # Ensure model is immutable after creation for security
        frozen=True,
        # Use enums by value for JSON serialization
        use_enum_values=True,
        # Validate assignment to catch errors early
        validate_assignment=True,
        # Populate by name to handle API field name variations
        populate_by_name=True,
        # Extra fields not allowed to maintain data minimization
        extra="forbid",
    )


class UserInfoResponse(BaseModel):
    """
    Response schema for user information endpoint.
    
    Used by GET /auth/me endpoint to return current authentication status
    and user information for session management.
    
    Privacy-focused design: Only returns essential user data when authenticated.
    """
    
    user: PlexUser | None = Field(
        default=None,
        description="Authenticated Plex user information (null if not authenticated)"
    )
    
    authenticated: bool = Field(
        ...,
        description="Whether the user is currently authenticated",
        examples=[True, False]
    )
    
    session_expires_at: datetime | None = Field(
        default=None,
        description="When the current session expires (UTC, null if not authenticated)"
    )
    
    model_config = ConfigDict(  # pyright: ignore[reportUnannotatedClassAttribute]
        # Ensure model is immutable after creation for security
        frozen=True,
        # Use enums by value for JSON serialization
        use_enum_values=True,
        # Validate assignment to catch errors early
        validate_assignment=True,
        # Populate by name to handle API field name variations
        populate_by_name=True,
        # Extra fields not allowed to maintain data minimization
        extra="forbid",
    ) 