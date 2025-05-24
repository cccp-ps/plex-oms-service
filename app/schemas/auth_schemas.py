"""
Authentication request/response schemas for Plex OAuth 2.0 flow.

This module contains Pydantic v2 models for authentication endpoints,
including OAuth initiation, callback, token refresh, and error handling schemas.

Schemas are designed to:
- Validate OAuth 2.0 flow requests and responses
- Provide type safety throughout the authentication system
- Minimize data collection (privacy-first approach)
- Ensure immutability for security
- Follow OAuth 2.0 and Plex API standards
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

from app.models.plex_models import PlexUser


class OAuthInitiationRequest(BaseModel):
    """
    Request schema for OAuth flow initiation.
    
    Used for POST /auth/login endpoint to start the OAuth 2.0 flow
    with Plex using MyPlexPinLogin(oauth=True) for direct login experience.
    
    Privacy-focused design: Only essential OAuth parameters are included.
    """
    
    redirect_uri: HttpUrl = Field(
        default=HttpUrl("http://localhost:8000/auth/callback"),
        description="OAuth redirect URI for callback handling",
        examples=["https://app.example.com/auth/callback", "http://localhost:3000/auth/callback"]
    )
    
    scopes: list[str] = Field(
        default=["read"],
        min_length=1,
        description="OAuth scopes for Plex API access",
        examples=[["read"], ["read", "write"]]
    )
    
    @field_validator('scopes')
    @classmethod
    def validate_scopes_not_empty(cls, v: list[str]) -> list[str]:
        """Validate that scopes list is not empty."""
        if not v or len(v) == 0:
            raise ValueError('Scopes list cannot be empty')
        
        # Filter out empty/whitespace-only scopes
        filtered_scopes = [scope.strip() for scope in v if scope and scope.strip()]
        
        if not filtered_scopes:
            raise ValueError('Scopes list cannot contain only empty values')
        
        return filtered_scopes
    
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
    """
    Response schema for OAuth flow initiation.
    
    Returned by POST /auth/login endpoint after creating OAuth flow
    with MyPlexPinLogin(oauth=True) for direct Plex account login.
    """
    
    oauth_url: HttpUrl = Field(
        ...,
        description="OAuth URL for user to authenticate with Plex",
        examples=["https://app.plex.tv/auth/#!?clientID=test&code=abc123"]
    )
    
    state: str = Field(
        ...,
        min_length=1,
        description="Secure state parameter for CSRF protection",
        examples=["secure-state-parameter-xyz789"]
    )
    
    expires_at: datetime = Field(
        ...,
        description="When the OAuth session expires (UTC)",
        examples=[datetime.now()]
    )
    
    @field_validator('state')
    @classmethod
    def validate_state_not_empty(cls, v: str) -> str:
        """Validate state parameter is not empty or whitespace-only."""
        if not v or not v.strip():
            raise ValueError('State parameter cannot be empty or whitespace-only')
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


class OAuthCallbackRequest(BaseModel):
    """
    Request schema for OAuth callback handling.
    
    Used for POST /auth/callback endpoint to complete the OAuth 2.0 flow
    after user authentication with Plex.
    
    Contains authorization code and state parameter for validation.
    """
    
    code: str = Field(
        ...,
        min_length=1,
        description="Authorization code from Plex OAuth callback",
        examples=["auth-code-12345"]
    )
    
    state: str = Field(
        ...,
        min_length=1,
        description="State parameter for CSRF protection validation",
        examples=["secure-state-parameter-xyz789"]
    )
    
    @field_validator('code')
    @classmethod
    def validate_code_not_empty(cls, v: str) -> str:
        """Validate authorization code is not empty or whitespace-only."""
        if not v or not v.strip():
            raise ValueError('Authorization code cannot be empty or whitespace-only')
        return v.strip()
    
    @field_validator('state')
    @classmethod
    def validate_state_not_empty(cls, v: str) -> str:
        """Validate state parameter is not empty or whitespace-only."""
        if not v or not v.strip():
            raise ValueError('State parameter cannot be empty or whitespace-only')
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


class OAuthCallbackResponse(BaseModel):
    """
    Response schema for successful OAuth callback completion.
    
    Returned by POST /auth/callback endpoint after successful authentication
    with Plex OAuth and MyPlexAccount creation.
    
    Contains access token and essential user information for session management.
    """
    
    access_token: str = Field(
        ...,
        min_length=1,
        description="Plex access token for API authentication",
        examples=["plex-access-token-12345"]
    )
    
    token_type: Literal["Bearer"] = Field(
        default="Bearer",
        description="Token type (always Bearer for OAuth 2.0)",
        examples=["Bearer"]
    )
    
    expires_in: int = Field(
        ...,
        ge=0,
        description="Token expiration time in seconds from now",
        examples=[3600, 7200]
    )
    
    user: PlexUser = Field(
        ...,
        description="Authenticated Plex user information"
    )
    
    refresh_token: str | None = Field(
        default=None,
        description="Refresh token for token renewal (if supported)",
        examples=["refresh-token-67890"]
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