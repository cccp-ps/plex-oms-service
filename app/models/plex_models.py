"""
Pydantic models for Plex API data structures.

This module contains Pydantic v2 models representing Plex API response structures,
including PlexUser and OnlineMediaSource models with validation and privacy-focused design.

Models are designed to:
- Validate Plex API response data
- Provide type safety throughout the application
- Minimize data collection (privacy-first approach)
- Ensure immutability for security
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class PlexUser(BaseModel):
    """
    Pydantic model representing a Plex user with essential authentication data.
    
    This model is designed with privacy-first principles, containing only
    the essential user information needed for authentication and authorization.
    
    Fields are based on PlexAPI MyPlexAccount response structure but filtered
    to include only necessary data for our application functionality.
    """
    
    # Required fields for user identification and authentication
    id: int = Field(
        ...,
        description="Plex user ID (unique identifier)",
        examples=[12345]
    )
    
    uuid: str = Field(
        ..., 
        min_length=1,
        description="Plex user UUID (unique identifier string)",
        examples=["abcd1234-5678-90ef-ghij-klmnopqrstuv"]
    )
    
    username: str = Field(
        ...,
        min_length=1,
        description="Plex username",
        examples=["myusername"]
    )
    
    email: EmailStr = Field(
        ...,
        description="User's email address (validated format)",
        examples=["user@example.com"]
    )
    
    authentication_token: str = Field(
        ...,
        min_length=1, 
        description="Plex authentication token for API access",
        examples=["abcdef123456789"]
    )
    
    # Optional fields with security-focused defaults
    thumb: str | None = Field(
        default=None,
        description="User avatar/thumbnail URL",
        examples=["https://plex.tv/users/username/avatar"]
    )
    
    confirmed: bool = Field(
        default=False,
        description="Whether user account is confirmed (defaults to False for security)"
    )
    
    restricted: bool = Field(
        default=False, 
        description="Whether user has restricted access"
    )
    
    guest: bool = Field(
        default=False,
        description="Whether user is a guest account"
    )
    
    subscription_active: bool = Field(
        default=False,
        description="Whether user has active Plex Pass subscription"
    )
    
    subscription_plan: str | None = Field(
        default=None,
        description="User's subscription plan (e.g., 'plexpass')",
        examples=["plexpass", "free"]
    )
    
    # Token expiration for OAuth flow management
    token_expires_at: datetime | None = Field(
        default=None,
        description="When the authentication token expires (UTC)"
    )
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        """Validate username is not empty or whitespace-only."""
        if not v or not v.strip():
            raise ValueError('Username cannot be empty or whitespace-only')
        return v.strip()
    
    @field_validator('uuid')
    @classmethod
    def validate_uuid(cls, v: str) -> str:
        """Validate UUID is not empty or whitespace-only."""
        if not v or not v.strip():
            raise ValueError('UUID cannot be empty or whitespace-only')
        return v.strip()
    
    @field_validator('authentication_token') 
    @classmethod
    def validate_authentication_token(cls, v: str) -> str:
        """Validate authentication token is not empty or whitespace-only."""
        if not v or not v.strip():
            raise ValueError('Authentication token cannot be empty or whitespace-only')
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


class OnlineMediaSource(BaseModel):
    """
    Pydantic model representing a Plex online media source with privacy-focused design.
    
    This model represents individual online media sources (e.g., Spotify, TIDAL, YouTube)
    that can be enabled or disabled for Plex scrobbling. The model is designed with
    privacy-first principles, containing only essential source information.
    
    Fields are based on PlexAPI MyPlexAccount.onlineMediaSources() response structure
    but filtered to include only necessary data for our application functionality.
    """
    
    # Required fields for source identification
    identifier: str = Field(
        ...,
        min_length=1,
        description="Unique identifier for the online media source",
        examples=["tidal", "spotify", "youtube", "lastfm"]
    )
    
    title: str = Field(
        ...,
        min_length=1,
        description="Display name of the online media source",
        examples=["TIDAL", "Spotify", "YouTube", "Last.fm"]
    )
    
    # Optional fields with privacy-focused defaults
    scrobble_types: list[str] = Field(
        default_factory=list,
        description="Types of media that can be scrobbled (e.g., track, album, artist)",
        examples=[["track"], ["track", "album"]]
    )
    
    enabled: bool = Field(
        default=False,
        description="Whether the source is enabled for scrobbling (defaults to False for privacy)"
    )
    
    @field_validator('identifier')
    @classmethod
    def validate_identifier(cls, v: str) -> str:
        """Validate identifier is not empty or whitespace-only."""
        if not v or not v.strip():
            raise ValueError('Identifier cannot be empty or whitespace-only')
        return v.strip()
    
    @field_validator('title')
    @classmethod
    def validate_title(cls, v: str) -> str:
        """Validate title is not empty or whitespace-only."""
        if not v or not v.strip():
            raise ValueError('Title cannot be empty or whitespace-only')
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