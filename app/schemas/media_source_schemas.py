"""
Media source operation request/response schemas.

This module contains Pydantic v2 models for media source management operations,
including list responses, bulk operations, individual toggles, and error handling.

Schemas are designed to:
- Validate media source operation requests and responses
- Provide type safety throughout the media source management system
- Minimize data collection (privacy-first approach)
- Ensure immutability for security
- Follow consistent API design patterns
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.plex_models import OnlineMediaSource


# Type alias for error details that can contain various debugging information
ErrorDetails = dict[str, str | int | list[str] | bool]


class MediaSourcesListResponse(BaseModel):
    """
    Response schema for media sources listing.
    
    Used by GET /api/media-sources endpoint to return user's online media sources
    with aggregate statistics for overview.
    
    Privacy-focused design: Contains only essential source information and statistics.
    """
    
    media_sources: list[OnlineMediaSource] = Field(
        default_factory=list,
        description="List of user's online media sources"
    )
    
    total_count: int = Field(
        ...,
        ge=0,
        description="Total number of media sources",
        examples=[5, 0, 10]
    )
    
    enabled_count: int = Field(
        ...,
        ge=0,
        description="Number of currently enabled media sources",
        examples=[3, 0, 5]
    )
    
    disabled_count: int = Field(
        ...,
        ge=0,
        description="Number of currently disabled media sources",
        examples=[2, 0, 5]
    )
    
    @model_validator(mode='after')
    def validate_counts_consistency(self) -> 'MediaSourcesListResponse':
        """Validate that counts are consistent with actual data."""
        # Validate total count matches source list length
        if self.total_count != len(self.media_sources):
            raise ValueError("Total count must match the number of media sources")
        
        # Validate enabled + disabled equals total
        if self.enabled_count + self.disabled_count != self.total_count:
            raise ValueError("Enabled count plus disabled count must equal total count")
        
        # Validate actual enabled/disabled counts match reported counts
        actual_enabled = sum(1 for source in self.media_sources if source.enabled)
        actual_disabled = len(self.media_sources) - actual_enabled
        
        if actual_enabled != self.enabled_count:
            raise ValueError(f"Actual enabled count ({actual_enabled}) doesn't match reported enabled count ({self.enabled_count})")
        
        if actual_disabled != self.disabled_count:
            raise ValueError(f"Actual disabled count ({actual_disabled}) doesn't match reported disabled count ({self.disabled_count})")
        
        return self
    
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


class BulkDisableRequest(BaseModel):
    """
    Request schema for bulk disable operation.
    
    Used by POST /api/media-sources/disable-all endpoint to disable multiple
    or all media sources in a single operation.
    
    Includes safety confirmation requirement to prevent accidental bulk operations.
    """
    
    confirm: bool = Field(
        ...,
        description="Confirmation that user wants to perform bulk disable operation",
        examples=[True]
    )
    
    source_identifiers: list[str] = Field(
        default_factory=list,
        description="List of source identifiers to disable (empty means all sources)",
        examples=[[], ["spotify", "tidal"], ["lastfm", "youtube"]]
    )
    
    @field_validator('confirm')
    @classmethod
    def validate_confirmation_required(cls, v: bool) -> bool:
        """Validate that confirmation is provided for safety."""
        if v is not True:
            raise ValueError("Confirmation is required for bulk disable operations")
        return v
    
    @field_validator('source_identifiers')
    @classmethod
    def validate_and_filter_identifiers(cls, v: list[str]) -> list[str]:
        """Validate and filter source identifiers, removing empty/whitespace values."""
        if not v:
            return []
        
        # Filter out empty or whitespace-only identifiers
        filtered_identifiers = [
            identifier.strip() 
            for identifier in v 
            if identifier and identifier.strip()
        ]
        
        return filtered_identifiers
    
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


class BulkDisableResponse(BaseModel):
    """
    Response schema for bulk disable operation.
    
    Returned by POST /api/media-sources/disable-all endpoint after attempting
    to disable multiple media sources.
    
    Provides detailed operation results including partial failure handling.
    """
    
    success: bool = Field(
        ...,
        description="Whether the overall operation was successful",
        examples=[True, False]
    )
    
    total_requested: int = Field(
        ...,
        ge=0,
        description="Total number of sources requested to be disabled",
        examples=[5, 0, 10]
    )
    
    successful_count: int = Field(
        ...,
        ge=0,
        description="Number of sources successfully disabled",
        examples=[5, 3, 0]
    )
    
    failed_count: int = Field(
        ...,
        ge=0,
        description="Number of sources that failed to disable",
        examples=[0, 2, 5]
    )
    
    disabled_sources: list[str] = Field(
        default_factory=list,
        description="List of source identifiers that were successfully disabled",
        examples=[["spotify", "tidal"], [], ["lastfm"]]
    )
    
    failed_sources: list[str] = Field(
        default_factory=list,
        description="List of source identifiers that failed to disable",
        examples=[[], ["invalid_source"], ["error_source"]]
    )
    
    message: str = Field(
        ...,
        min_length=1,
        description="Human-readable message describing the operation result",
        examples=[
            "Successfully disabled 5 media sources",
            "Disabled 3 out of 5 media sources",
            "Failed to disable any media sources"
        ]
    )
    
    @model_validator(mode='after')
    def validate_counts_consistency(self) -> 'BulkDisableResponse':
        """Validate that counts are consistent with operation results."""
        # Validate successful + failed equals total requested
        if self.successful_count + self.failed_count != self.total_requested:
            raise ValueError("Successful count plus failed count must equal total requested")
        
        # Validate list lengths match counts
        if len(self.disabled_sources) != self.successful_count:
            raise ValueError("Length of disabled sources list must match successful count")
        
        if len(self.failed_sources) != self.failed_count:
            raise ValueError("Length of failed sources list must match failed count")
        
        return self
    
    @field_validator('message')
    @classmethod
    def validate_message_not_empty(cls, v: str) -> str:
        """Validate message is not empty or whitespace-only."""
        if not v or not v.strip():
            raise ValueError("Message cannot be empty or whitespace-only")
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


class IndividualSourceToggleRequest(BaseModel):
    """
    Request schema for individual source toggle operation.
    
    Used by PATCH /api/media-sources/{source_id} endpoint to enable or disable
    a specific media source.
    
    Simple boolean toggle for clear enable/disable semantics.
    """
    
    enabled: bool = Field(
        ...,
        description="Whether to enable (True) or disable (False) the media source",
        examples=[True, False]
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


class IndividualSourceToggleResponse(BaseModel):
    """
    Response schema for individual source toggle operation.
    
    Returned by PATCH /api/media-sources/{source_id} endpoint after attempting
    to toggle a specific media source.
    
    Includes updated source information on success or error details on failure.
    """
    
    success: bool = Field(
        ...,
        description="Whether the toggle operation was successful",
        examples=[True, False]
    )
    
    media_source: OnlineMediaSource | None = Field(
        default=None,
        description="Updated media source information (null on failure)"
    )
    
    message: str = Field(
        ...,
        min_length=1,
        description="Human-readable message describing the operation result",
        examples=[
            "Successfully enabled Spotify",
            "Successfully disabled TIDAL",
            "Failed to toggle source: Source not found"
        ]
    )
    
    @field_validator('message')
    @classmethod
    def validate_message_not_empty(cls, v: str) -> str:
        """Validate message is not empty or whitespace-only."""
        if not v or not v.strip():
            raise ValueError("Message cannot be empty or whitespace-only")
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


class MediaSourceOperationSuccess(BaseModel):
    """
    Generic success response schema for media source operations.
    
    Used as a standardized success response across different media source
    management endpoints for consistent API design.
    
    Provides operation metadata for logging and user feedback.
    """
    
    message: str = Field(
        ...,
        min_length=1,
        description="Human-readable success message",
        examples=[
            "Operation completed successfully",
            "Media source updated",
            "Bulk operation completed"
        ]
    )
    
    operation: str = Field(
        ...,
        min_length=1,
        description="Type of operation that was performed",
        examples=[
            "bulk_disable",
            "individual_toggle", 
            "source_list",
            "single_disable",
            "single_enable"
        ]
    )
    
    affected_count: int = Field(
        ...,
        ge=0,
        description="Number of media sources affected by the operation",
        examples=[0, 1, 5, 10]
    )
    
    timestamp: datetime = Field(
        default_factory=datetime.now,
        description="When the operation was completed (UTC)"
    )
    
    @field_validator('message')
    @classmethod
    def validate_message_not_empty(cls, v: str) -> str:
        """Validate message is not empty or whitespace-only."""
        if not v or not v.strip():
            raise ValueError("Message cannot be empty or whitespace-only")
        return v.strip()
    
    @field_validator('operation')
    @classmethod
    def validate_operation_not_empty(cls, v: str) -> str:
        """Validate operation is not empty or whitespace-only."""
        if not v or not v.strip():
            raise ValueError("Operation cannot be empty or whitespace-only")
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


class MediaSourceOperationError(BaseModel):
    """
    Generic error response schema for media source operations.
    
    Used as a standardized error response across different media source
    management endpoints for consistent API error handling.
    
    Follows RFC 7807 Problem Details format and OAuth 2.0 error patterns.
    """
    
    error: str = Field(
        ...,
        min_length=1,
        description="Error code identifying the type of error",
        examples=[
            "operation_failed",
            "source_not_found",
            "invalid_request",
            "plex_api_error",
            "validation_error"
        ]
    )
    
    message: str = Field(
        ...,
        min_length=1,
        description="Human-readable error message",
        examples=[
            "Failed to disable media sources",
            "Media source not found",
            "Invalid request parameters",
            "PlexAPI communication error"
        ]
    )
    
    operation: str = Field(
        ...,
        min_length=1,
        description="Type of operation that failed",
        examples=[
            "bulk_disable",
            "individual_toggle",
            "source_list",
            "single_disable",
            "single_enable"
        ]
    )
    
    error_code: str | None = Field(
        default=None,
        description="Application-specific error code for debugging",
        examples=["BULK_001", "SRC_404", "PLEX_CONN_ERR", "VAL_001"]
    )
    
    details: ErrorDetails | None = Field(
        default=None,
        description="Additional error details for debugging (optional)",
        examples=[
            {"failed_sources": ["invalid_source"]},
            {"validation_errors": ["field required"]},
            {"plex_api_status": 500}
        ]
    )
    
    @field_validator('error')
    @classmethod
    def validate_error_not_empty(cls, v: str) -> str:
        """Validate error code is not empty or whitespace-only."""
        if not v or not v.strip():
            raise ValueError("Error code cannot be empty or whitespace-only")
        return v.strip()
    
    @field_validator('message')
    @classmethod
    def validate_message_not_empty(cls, v: str) -> str:
        """Validate message is not empty or whitespace-only."""
        if not v or not v.strip():
            raise ValueError("Message cannot be empty or whitespace-only")
        return v.strip()
    
    @field_validator('operation')
    @classmethod
    def validate_operation_not_empty(cls, v: str) -> str:
        """Validate operation is not empty or whitespace-only."""
        if not v or not v.strip():
            raise ValueError("Operation cannot be empty or whitespace-only")
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