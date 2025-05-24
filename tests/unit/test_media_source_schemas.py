"""
Unit tests for media source operation schemas.

This module tests the Pydantic v2 models for media source management operations,
including list responses, bulk operations, individual toggles, and error handling.

Tests follow TDD principles and ensure:
- Schema validation works correctly
- Privacy-first design is maintained
- Type safety is enforced
- Security considerations are met
"""

import pytest
from datetime import datetime

from pydantic import ValidationError

from app.schemas.media_source_schemas import (
    MediaSourcesListResponse,
    BulkDisableRequest,
    BulkDisableResponse,
    IndividualSourceToggleRequest,
    IndividualSourceToggleResponse,
    MediaSourceOperationError,
    MediaSourceOperationSuccess,
)
from app.models.plex_models import OnlineMediaSource


class TestMediaSourcesListResponse:
    """Test cases for media sources list response schema."""
    
    def test_valid_media_sources_list_response(self) -> None:
        """Test MediaSourcesListResponse with valid data."""
        # Test data with multiple sources
        sources = [
            OnlineMediaSource(
                identifier="spotify",
                title="Spotify",
                scrobble_types=["track"],
                enabled=True
            ),
            OnlineMediaSource(
                identifier="tidal",
                title="TIDAL",
                scrobble_types=["track", "album"],
                enabled=False
            )
        ]
        
        response = MediaSourcesListResponse(
            media_sources=sources,
            total_count=2,
            enabled_count=1,
            disabled_count=1
        )
        
        assert response.total_count == 2
        assert response.enabled_count == 1
        assert response.disabled_count == 1
        assert len(response.media_sources) == 2
        assert response.media_sources[0].identifier == "spotify"
        assert response.media_sources[0].enabled is True
        assert response.media_sources[1].identifier == "tidal"
        assert response.media_sources[1].enabled is False
        
    def test_empty_media_sources_list_response(self) -> None:
        """Test MediaSourcesListResponse with empty sources list."""
        response = MediaSourcesListResponse(
            media_sources=[],
            total_count=0,
            enabled_count=0,
            disabled_count=0
        )
        
        assert response.total_count == 0
        assert response.enabled_count == 0
        assert response.disabled_count == 0
        assert len(response.media_sources) == 0
        
    def test_media_sources_list_response_count_validation(self) -> None:
        """Test MediaSourcesListResponse validates count consistency."""
        sources = [
            OnlineMediaSource(
                identifier="spotify",
                title="Spotify",
                scrobble_types=["track"],
                enabled=True
            )
        ]
        
        # Invalid: total_count doesn't match sources length
        with pytest.raises(ValidationError) as exc_info:
            _ = MediaSourcesListResponse(
                media_sources=sources,
                total_count=5,  # Should be 1
                enabled_count=1,
                disabled_count=0
            )
        assert "Total count must match the number of media sources" in str(exc_info.value)
        
        # Invalid: enabled + disabled doesn't equal total
        with pytest.raises(ValidationError) as exc_info:
            _ = MediaSourcesListResponse(
                media_sources=sources,
                total_count=1,
                enabled_count=1,
                disabled_count=1  # Should be 0
            )
        assert "Enabled count plus disabled count must equal total count" in str(exc_info.value)
        
    def test_media_sources_list_response_negative_counts(self) -> None:
        """Test MediaSourcesListResponse rejects negative counts."""
        with pytest.raises(ValidationError) as exc_info:
            _ = MediaSourcesListResponse(
                media_sources=[],
                total_count=-1,
                enabled_count=0,
                disabled_count=0
            )
        assert "Input should be greater than or equal to 0" in str(exc_info.value)


class TestBulkDisableRequest:
    """Test cases for bulk disable request schema."""
    
    def test_valid_bulk_disable_request(self) -> None:
        """Test BulkDisableRequest with valid data."""
        request = BulkDisableRequest(
            confirm=True,
            source_identifiers=["spotify", "tidal", "lastfm"]
        )
        
        assert request.confirm is True
        assert request.source_identifiers == ["spotify", "tidal", "lastfm"]
        
    def test_bulk_disable_request_without_confirmation(self) -> None:
        """Test BulkDisableRequest requires confirmation for safety."""
        with pytest.raises(ValidationError) as exc_info:
            _ = BulkDisableRequest(
                confirm=False,
                source_identifiers=["spotify"]
            )
        assert "Confirmation is required for bulk disable operations" in str(exc_info.value)
        
    def test_bulk_disable_request_empty_identifiers(self) -> None:
        """Test BulkDisableRequest handles empty identifiers list."""
        # Empty list should be valid (no-op operation)
        request = BulkDisableRequest(
            confirm=True,
            source_identifiers=[]
        )
        
        assert request.source_identifiers == []
        
    def test_bulk_disable_request_invalid_identifiers(self) -> None:
        """Test BulkDisableRequest validates identifier format."""
        # Empty/whitespace identifiers should be filtered out
        request = BulkDisableRequest(
            confirm=True,
            source_identifiers=["spotify", "", "  ", "tidal"]
        )
        
        assert request.source_identifiers == ["spotify", "tidal"]


class TestBulkDisableResponse:
    """Test cases for bulk disable response schema."""
    
    def test_valid_bulk_disable_response_success(self) -> None:
        """Test BulkDisableResponse with successful operation."""
        response = BulkDisableResponse(
            success=True,
            total_requested=3,
            successful_count=3,
            failed_count=0,
            disabled_sources=["spotify", "tidal", "lastfm"],
            failed_sources=[],
            message="Successfully disabled 3 media sources"
        )
        
        assert response.success is True
        assert response.total_requested == 3
        assert response.successful_count == 3
        assert response.failed_count == 0
        assert response.disabled_sources == ["spotify", "tidal", "lastfm"]
        assert response.failed_sources == []
        
    def test_valid_bulk_disable_response_partial_failure(self) -> None:
        """Test BulkDisableResponse with partial failures."""
        response = BulkDisableResponse(
            success=False,
            total_requested=3,
            successful_count=2,
            failed_count=1,
            disabled_sources=["spotify", "tidal"],
            failed_sources=["invalid_source"],
            message="Disabled 2 out of 3 media sources"
        )
        
        assert response.success is False
        assert response.total_requested == 3
        assert response.successful_count == 2
        assert response.failed_count == 1
        
    def test_bulk_disable_response_count_validation(self) -> None:
        """Test BulkDisableResponse validates count consistency."""
        # Invalid: successful + failed doesn't equal total
        with pytest.raises(ValidationError) as exc_info:
            _ = BulkDisableResponse(
                success=True,
                total_requested=3,
                successful_count=2,
                failed_count=2,  # Should be 1
                disabled_sources=["spotify", "tidal"],
                failed_sources=["lastfm"],
                message="Test message"
            )
        assert "Successful count plus failed count must equal total requested" in str(exc_info.value)


class TestIndividualSourceToggleRequest:
    """Test cases for individual source toggle request schema."""
    
    def test_valid_individual_toggle_request_enable(self) -> None:
        """Test IndividualSourceToggleRequest for enabling source."""
        request = IndividualSourceToggleRequest(enabled=True)
        assert request.enabled is True
        
    def test_valid_individual_toggle_request_disable(self) -> None:
        """Test IndividualSourceToggleRequest for disabling source."""
        request = IndividualSourceToggleRequest(enabled=False)
        assert request.enabled is False


class TestIndividualSourceToggleResponse:
    """Test cases for individual source toggle response schema."""
    
    def test_valid_individual_toggle_response(self) -> None:
        """Test IndividualSourceToggleResponse with valid data."""
        source = OnlineMediaSource(
            identifier="spotify",
            title="Spotify",
            scrobble_types=["track"],
            enabled=True
        )
        
        response = IndividualSourceToggleResponse(
            success=True,
            media_source=source,
            message="Successfully enabled Spotify"
        )
        
        assert response.success is True
        assert response.media_source is not None
        assert response.media_source.identifier == "spotify"
        assert response.media_source.enabled is True
        assert "Successfully enabled" in response.message
        
    def test_individual_toggle_response_with_error(self) -> None:
        """Test IndividualSourceToggleResponse with error."""
        response = IndividualSourceToggleResponse(
            success=False,
            media_source=None,
            message="Failed to toggle source: Source not found"
        )
        
        assert response.success is False
        assert response.media_source is None
        assert "Failed to toggle" in response.message


class TestMediaSourceOperationSuccess:
    """Test cases for operation success schema."""
    
    def test_valid_operation_success(self) -> None:
        """Test MediaSourceOperationSuccess with valid data."""
        timestamp = datetime.now()
        success = MediaSourceOperationSuccess(
            message="Operation completed successfully",
            operation="bulk_disable",
            affected_count=3,
            timestamp=timestamp
        )
        
        assert success.message == "Operation completed successfully"
        assert success.operation == "bulk_disable"
        assert success.affected_count == 3
        assert success.timestamp == timestamp
        
    def test_operation_success_negative_count(self) -> None:
        """Test MediaSourceOperationSuccess rejects negative affected count."""
        with pytest.raises(ValidationError) as exc_info:
            _ = MediaSourceOperationSuccess(
                message="Test",
                operation="test",
                affected_count=-1,
                timestamp=datetime.now()
            )
        assert "Input should be greater than or equal to 0" in str(exc_info.value)


class TestMediaSourceOperationError:
    """Test cases for operation error schema."""
    
    def test_valid_operation_error(self) -> None:
        """Test MediaSourceOperationError with valid data."""
        error = MediaSourceOperationError(
            error="operation_failed",
            message="Failed to disable media sources",
            operation="bulk_disable",
            error_code="BULK_001",
            details={"failed_sources": ["invalid_source"]}
        )
        
        assert error.error == "operation_failed"
        assert error.message == "Failed to disable media sources"
        assert error.operation == "bulk_disable"
        assert error.error_code == "BULK_001"
        assert error.details == {"failed_sources": ["invalid_source"]}
        
    def test_operation_error_minimal_data(self) -> None:
        """Test MediaSourceOperationError with minimal required data."""
        error = MediaSourceOperationError(
            error="unknown_error",
            message="An error occurred",
            operation="unknown"
        )
        
        assert error.error == "unknown_error"
        assert error.message == "An error occurred"
        assert error.operation == "unknown"
        assert error.error_code is None
        assert error.details is None
        
    def test_operation_error_empty_strings(self) -> None:
        """Test MediaSourceOperationError validates non-empty strings."""
        with pytest.raises(ValidationError) as exc_info:
            _ = MediaSourceOperationError(
                error="",
                message="Test message",
                operation="test"
            )
        assert "String should have at least 1 character" in str(exc_info.value) 