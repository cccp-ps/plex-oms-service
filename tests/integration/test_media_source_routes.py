"""
Integration tests for media sources API routes.

Tests the media sources management endpoints including listing, individual source
management, and bulk operations. Uses TDD methodology with failing tests first.

Tests follow privacy-first principles and include comprehensive error handling,
authentication validation, and PlexAPI integration testing.
"""

from typing import cast
from unittest.mock import MagicMock

import pytest
from fastapi import status
from httpx import AsyncClient

from app.models.plex_models import OnlineMediaSource

# Type alias for JSON values
JsonValue = str | int | bool | list[str] | None

class TestMediaSourcesListingEndpoint:
    """Test cases for GET /api/media-sources endpoint."""

    @pytest.mark.asyncio
    async def test_get_media_sources_returns_user_sources(
        self,
        async_client: AsyncClient,
        authenticated_headers: dict[str, str],
        mock_plex_service: MagicMock
    ) -> None:
        """Test case: GET /api/media-sources returns user's online media sources."""
        # Arrange
        expected_sources = [
            OnlineMediaSource(
                identifier="spotify",
                title="Spotify",
                enabled=True,
                scrobble_types=["track"]
            ),
            OnlineMediaSource(
                identifier="tidal",
                title="TIDAL",
                enabled=False,
                scrobble_types=["track"]
            )
        ]
        mock_plex_service.get_media_sources.return_value = expected_sources  # pyright: ignore[reportAny]

        # Act
        response = await async_client.get(
            "/api/media-sources",
            headers=authenticated_headers
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = cast(list[dict[str, JsonValue]], response.json())
        assert len(response_data) == 2
        assert response_data[0]["identifier"] == "spotify"
        assert response_data[0]["title"] == "Spotify"
        assert response_data[0]["enabled"] is True
        assert response_data[1]["identifier"] == "tidal"
        assert response_data[1]["title"] == "TIDAL"
        assert response_data[1]["enabled"] is False

    @pytest.mark.asyncio
    async def test_get_media_sources_requires_authentication(
        self,
        async_client: AsyncClient
    ) -> None:
        """Test case: Require authentication for access."""
        # Act
        response = await async_client.get("/api/media-sources")

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response_data = cast(dict[str, JsonValue], response.json())
        assert "detail" in response_data
        detail_str = str(response_data["detail"])
        assert "authenticate" in detail_str.lower()

    @pytest.mark.asyncio
    async def test_get_media_sources_filters_data_for_privacy(
        self,
        async_client: AsyncClient,
        authenticated_headers: dict[str, str],
        mock_plex_service: MagicMock
    ) -> None:
        """Test case: Filter and transform data for privacy compliance."""
        # Arrange
        privacy_safe_sources = [
            OnlineMediaSource(
                identifier="spotify",
                title="Spotify",
                enabled=True,
                scrobble_types=["track"]
            )
        ]
        mock_plex_service.get_media_sources.return_value = privacy_safe_sources  # pyright: ignore[reportAny]

        # Act
        response = await async_client.get(
            "/api/media-sources",
            headers=authenticated_headers
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = cast(list[dict[str, JsonValue]], response.json())

        # Verify only privacy-safe fields are returned
        required_fields = {"identifier", "title", "enabled", "scrobble_types"}
        for source in response_data:
            source_keys = set(source.keys())
            assert source_keys == required_fields
            # Verify no sensitive data is included
            assert "internal_id" not in source
            assert "user_data" not in source
            assert "metadata" not in source

    @pytest.mark.asyncio
    async def test_get_media_sources_handles_plex_api_errors_gracefully(
        self,
        async_client: AsyncClient,
        authenticated_headers: dict[str, str],
        mock_plex_service: MagicMock
    ) -> None:
        """Test case: Handle PlexAPI errors gracefully."""
        # Arrange
        from app.utils.exceptions import PlexAPIException
        mock_plex_service.get_media_sources.side_effect = PlexAPIException(  # pyright: ignore[reportAny]
            "Failed to connect to Plex API"
        )

        # Act
        response = await async_client.get(
            "/api/media-sources",
            headers=authenticated_headers
        )

        # Assert
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        response_data = cast(dict[str, JsonValue], response.json())
        assert "detail" in response_data
        detail_str = str(response_data["detail"])
        assert "plex" in detail_str.lower()

    @pytest.mark.asyncio
    async def test_get_media_sources_handles_authentication_errors(
        self,
        async_client: AsyncClient,
        authenticated_headers: dict[str, str],
        mock_plex_service: MagicMock
    ) -> None:
        """Test case: Handle authentication errors from PlexAPI."""
        # Arrange
        from app.utils.exceptions import AuthenticationException
        mock_plex_service.get_media_sources.side_effect = AuthenticationException(  # pyright: ignore[reportAny]
            "Authentication failed with provided token"
        )

        # Act
        response = await async_client.get(
            "/api/media-sources",
            headers=authenticated_headers
        )

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response_data = cast(dict[str, JsonValue], response.json())
        assert "detail" in response_data
        detail_str = str(response_data["detail"])
        assert "authentication" in detail_str.lower()

    @pytest.mark.asyncio
    async def test_get_media_sources_returns_proper_http_status_codes(
        self,
        async_client: AsyncClient,
        authenticated_headers: dict[str, str],
        mock_plex_service: MagicMock
    ) -> None:
        """Test case: Return proper HTTP status codes."""
        # Test successful response
        mock_plex_service.get_media_sources.return_value = []  # pyright: ignore[reportAny]
        response = await async_client.get(
            "/api/media-sources",
            headers=authenticated_headers
        )
        assert response.status_code == status.HTTP_200_OK

        # Test empty sources list
        mock_plex_service.get_media_sources.return_value = []  # pyright: ignore[reportAny]
        response = await async_client.get(
            "/api/media-sources",
            headers=authenticated_headers
        )
        assert response.status_code == status.HTTP_200_OK
        response_json = cast(list[dict[str, JsonValue]], response.json())
        assert response_json == []

    @pytest.mark.asyncio
    async def test_get_media_sources_handles_empty_sources_list(
        self,
        async_client: AsyncClient,
        authenticated_headers: dict[str, str],
        mock_plex_service: MagicMock
    ) -> None:
        """Test case: Handle empty media sources list."""
        # Arrange
        mock_plex_service.get_media_sources.return_value = []  # pyright: ignore[reportAny]

        # Act
        response = await async_client.get(
            "/api/media-sources",
            headers=authenticated_headers
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_json = cast(list[dict[str, JsonValue]], response.json())
        assert response_json == []

    @pytest.mark.asyncio
    async def test_get_media_sources_validates_authentication_token(
        self,
        async_client: AsyncClient,
        mock_plex_service: MagicMock
    ) -> None:
        """Test case: Validate authentication token format and presence."""
        # Test with invalid token format
        invalid_headers = {"Authorization": "Bearer invalid-token-format"}

        # Mock the service to raise authentication error for invalid token
        from app.utils.exceptions import AuthenticationException
        mock_plex_service.get_media_sources.side_effect = AuthenticationException(  # pyright: ignore[reportAny]
            "Invalid authentication token provided"
        )

        response = await async_client.get(
            "/api/media-sources",
            headers=invalid_headers
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_get_media_sources_includes_content_type_header(
        self,
        async_client: AsyncClient,
        authenticated_headers: dict[str, str],
        mock_plex_service: MagicMock
    ) -> None:
        """Test case: Response includes proper content-type header."""
        # Arrange
        mock_plex_service.get_media_sources.return_value = []  # pyright: ignore[reportAny]

        # Act
        response = await async_client.get(
            "/api/media-sources",
            headers=authenticated_headers
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.headers["content-type"] == "application/json"

    @pytest.mark.asyncio
    async def test_get_media_sources_logs_requests_securely(
        self,
        async_client: AsyncClient,
        authenticated_headers: dict[str, str],
        mock_plex_service: MagicMock,
        caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test case: Log requests securely without exposing sensitive data."""
        # Arrange
        mock_plex_service.get_media_sources.return_value = []  # pyright: ignore[reportAny]

        # Act
        response = await async_client.get(
            "/api/media-sources",
            headers=authenticated_headers
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK

        # Verify logs don't contain sensitive data
        log_messages = [record.message for record in caplog.records]
        for message in log_messages:
            # Should not contain tokens or sensitive headers
            assert "Bearer" not in message
            assert "test-token" not in message
            assert "Authorization" not in message

class TestIndividualSourceManagementEndpoint:
    """Test cases for PATCH /api/media-sources/{source_id} endpoint."""

    @pytest.mark.asyncio
    async def test_patch_media_source_toggles_individual_source(
        self,
        async_client: AsyncClient,
        authenticated_headers: dict[str, str],
        mock_plex_service: MagicMock
    ) -> None:
        """Test case: PATCH /api/media-sources/{source_id} toggles individual source."""
        # Arrange
        source_id = "spotify"
        expected_enabled_status = True
        expected_source = OnlineMediaSource(
            identifier=source_id,
            title="Spotify",
            enabled=expected_enabled_status,
            scrobble_types=["track"]
        )
        
        mock_plex_service.toggle_individual_source.return_value = True  # pyright: ignore[reportAny]
        mock_plex_service.get_individual_source_status.return_value = expected_source  # pyright: ignore[reportAny]

        request_payload = {"enabled": expected_enabled_status}

        # Act
        response = await async_client.patch(
            f"/api/media-sources/{source_id}",
            headers=authenticated_headers,
            json=request_payload
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = cast(dict[str, JsonValue], response.json())
        assert response_data["identifier"] == source_id
        assert response_data["enabled"] is expected_enabled_status
        assert response_data["title"] == "Spotify"
        assert response_data["scrobble_types"] == ["track"]

        # Verify service method was called correctly
        mock_plex_service.toggle_individual_source.assert_called_once()  # pyright: ignore[reportAny]
        args = mock_plex_service.toggle_individual_source.call_args  # pyright: ignore[reportAny]
        assert args[1]["source_identifier"] == source_id
        assert args[1]["enable"] is expected_enabled_status

    @pytest.mark.asyncio
    async def test_patch_media_source_validates_source_exists_and_belongs_to_user(
        self,
        async_client: AsyncClient,
        authenticated_headers: dict[str, str],
        mock_plex_service: MagicMock
    ) -> None:
        """Test case: Validate source exists and belongs to user."""
        # Arrange
        nonexistent_source_id = "nonexistent_source"
        from app.utils.exceptions import ValidationException
        
        mock_plex_service.toggle_individual_source.side_effect = ValidationException(  # pyright: ignore[reportAny]
            "Source not found or doesn't belong to user"
        )

        request_payload = {"enabled": True}

        # Act
        response = await async_client.patch(
            f"/api/media-sources/{nonexistent_source_id}",
            headers=authenticated_headers,
            json=request_payload
        )

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND
        response_data = cast(dict[str, JsonValue], response.json())
        assert "detail" in response_data
        detail_str = str(response_data["detail"])
        assert "source" in detail_str.lower()
        assert "not found" in detail_str.lower()

    @pytest.mark.asyncio
    async def test_patch_media_source_returns_updated_source_status(
        self,
        async_client: AsyncClient,
        authenticated_headers: dict[str, str],
        mock_plex_service: MagicMock
    ) -> None:
        """Test case: Return updated source status."""
        # Arrange
        source_id = "tidal"
        enable_request = True
        updated_source = OnlineMediaSource(
            identifier=source_id,
            title="TIDAL",
            enabled=enable_request,
            scrobble_types=["track"]
        )
        
        mock_plex_service.toggle_individual_source.return_value = True  # pyright: ignore[reportAny]
        mock_plex_service.get_individual_source_status.return_value = updated_source  # pyright: ignore[reportAny]

        request_payload = {"enabled": enable_request}

        # Act
        response = await async_client.patch(
            f"/api/media-sources/{source_id}",
            headers=authenticated_headers,
            json=request_payload
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = cast(dict[str, JsonValue], response.json())
        
        # Verify the response contains the updated status
        assert response_data["identifier"] == source_id
        assert response_data["enabled"] is enable_request
        assert response_data["title"] == "TIDAL"
        
        # Verify service was called to fetch updated status
        mock_plex_service.get_individual_source_status.assert_called_once()  # pyright: ignore[reportAny]

    @pytest.mark.asyncio
    async def test_patch_media_source_handles_plex_api_operation_errors(
        self,
        async_client: AsyncClient,
        authenticated_headers: dict[str, str],
        mock_plex_service: MagicMock
    ) -> None:
        """Test case: Handle PlexAPI operation errors."""
        # Arrange
        source_id = "spotify"
        from app.utils.exceptions import PlexAPIException
        
        mock_plex_service.toggle_individual_source.side_effect = PlexAPIException(  # pyright: ignore[reportAny]
            "Failed to communicate with Plex API"
        )

        request_payload = {"enabled": True}

        # Act
        response = await async_client.patch(
            f"/api/media-sources/{source_id}",
            headers=authenticated_headers,
            json=request_payload
        )

        # Assert
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        response_data = cast(dict[str, JsonValue], response.json())
        assert "detail" in response_data
        detail_str = str(response_data["detail"])
        assert "plex" in detail_str.lower()

    @pytest.mark.asyncio
    async def test_patch_media_source_applies_proper_authorization_checks(
        self,
        async_client: AsyncClient
    ) -> None:
        """Test case: Apply proper authorization checks."""
        # Arrange
        source_id = "spotify"
        request_payload = {"enabled": True}

        # Act - Request without authentication
        response = await async_client.patch(
            f"/api/media-sources/{source_id}",
            json=request_payload
        )

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response_data = cast(dict[str, JsonValue], response.json())
        assert "detail" in response_data
        detail_str = str(response_data["detail"])
        assert "authenticate" in detail_str.lower()

    @pytest.mark.asyncio
    async def test_patch_media_source_validates_request_payload(
        self,
        async_client: AsyncClient,
        authenticated_headers: dict[str, str]
    ) -> None:
        """Test case: Validate request payload format and required fields."""
        # Arrange
        source_id = "spotify"

        # Test missing 'enabled' field
        invalid_payload = {"invalid_field": "value"}

        # Act
        response = await async_client.patch(
            f"/api/media-sources/{source_id}",
            headers=authenticated_headers,
            json=invalid_payload
        )

        # Assert
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        response_data = cast(dict[str, JsonValue], response.json())
        assert "detail" in response_data

    @pytest.mark.asyncio
    async def test_patch_media_source_handles_authentication_errors(
        self,
        async_client: AsyncClient,
        authenticated_headers: dict[str, str],
        mock_plex_service: MagicMock
    ) -> None:
        """Test case: Handle authentication errors from PlexAPI."""
        # Arrange
        source_id = "spotify"
        from app.utils.exceptions import AuthenticationException
        
        mock_plex_service.toggle_individual_source.side_effect = AuthenticationException(  # pyright: ignore[reportAny]
            "Authentication failed with provided token"
        )

        request_payload = {"enabled": True}

        # Act
        response = await async_client.patch(
            f"/api/media-sources/{source_id}",
            headers=authenticated_headers,
            json=request_payload
        )

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response_data = cast(dict[str, JsonValue], response.json())
        assert "detail" in response_data
        detail_str = str(response_data["detail"])
        assert "authentication" in detail_str.lower()

    @pytest.mark.asyncio
    async def test_patch_media_source_validates_source_id_parameter(
        self,
        async_client: AsyncClient,
        authenticated_headers: dict[str, str],
        mock_plex_service: MagicMock
    ) -> None:
        """Test case: Validate source_id path parameter."""
        # Arrange - Use realistic invalid source IDs and mock ValidationException
        from app.utils.exceptions import ValidationException
        
        mock_plex_service.toggle_individual_source.side_effect = ValidationException(  # pyright: ignore[reportAny]
            "Source not found or doesn't belong to user"
        )
        
        invalid_source_ids = ["invalid_source", "nonexistent_source"]
        request_payload = {"enabled": True}

        for invalid_source_id in invalid_source_ids:
            # Act
            response = await async_client.patch(
                f"/api/media-sources/{invalid_source_id}",
                headers=authenticated_headers,
                json=request_payload
            )

            # Assert - For invalid sources, we expect 404 due to ValidationException
            assert response.status_code == status.HTTP_404_NOT_FOUND
            response_data = cast(dict[str, JsonValue], response.json())
            assert "detail" in response_data

    @pytest.mark.asyncio
    async def test_patch_media_source_handles_toggle_operation_failure(
        self,
        async_client: AsyncClient,
        authenticated_headers: dict[str, str],
        mock_plex_service: MagicMock
    ) -> None:
        """Test case: Handle toggle operation failure (service returns False)."""
        # Arrange
        source_id = "spotify"
        mock_plex_service.toggle_individual_source.return_value = False  # pyright: ignore[reportAny]

        request_payload = {"enabled": True}

        # Act
        response = await async_client.patch(
            f"/api/media-sources/{source_id}",
            headers=authenticated_headers,
            json=request_payload
        )

        # Assert
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        response_data = cast(dict[str, JsonValue], response.json())
        assert "detail" in response_data
        detail_str = str(response_data["detail"])
        assert "failed" in detail_str.lower() or "operation" in detail_str.lower()
