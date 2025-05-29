"""
Integration tests for media sources API routes.

Tests the media sources management endpoints including listing, individual source
management, and bulk operations. Uses TDD methodology with failing tests first.

Tests follow privacy-first principles and include comprehensive error handling,
authentication validation, and PlexAPI integration testing.
"""

import pytest
from fastapi import status
from httpx import AsyncClient
from unittest.mock import MagicMock

from app.models.plex_models import OnlineMediaSource


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
        mock_plex_service.get_media_sources.return_value = expected_sources

        # Act
        response = await async_client.get(
            "/api/media-sources",
            headers=authenticated_headers
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
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
        response_data = response.json()
        assert "detail" in response_data
        assert "authenticate" in response_data["detail"].lower()

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
        mock_plex_service.get_media_sources.return_value = privacy_safe_sources

        # Act
        response = await async_client.get(
            "/api/media-sources",
            headers=authenticated_headers
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        
        # Verify only privacy-safe fields are returned
        required_fields = {"identifier", "title", "enabled", "scrobble_types"}
        for source in response_data:
            assert set(source.keys()) == required_fields
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
        mock_plex_service.get_media_sources.side_effect = PlexAPIException(
            "Failed to connect to Plex API"
        )

        # Act
        response = await async_client.get(
            "/api/media-sources",
            headers=authenticated_headers
        )

        # Assert
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        response_data = response.json()
        assert "detail" in response_data
        assert "plex" in response_data["detail"].lower()

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
        mock_plex_service.get_media_sources.side_effect = AuthenticationException(
            "Authentication failed with provided token"
        )

        # Act
        response = await async_client.get(
            "/api/media-sources",
            headers=authenticated_headers
        )

        # Assert
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response_data = response.json()
        assert "detail" in response_data
        assert "authentication" in response_data["detail"].lower()

    @pytest.mark.asyncio
    async def test_get_media_sources_returns_proper_http_status_codes(
        self,
        async_client: AsyncClient,
        authenticated_headers: dict[str, str],
        mock_plex_service: MagicMock
    ) -> None:
        """Test case: Return proper HTTP status codes."""
        # Test successful response
        mock_plex_service.get_media_sources.return_value = []
        response = await async_client.get(
            "/api/media-sources",
            headers=authenticated_headers
        )
        assert response.status_code == status.HTTP_200_OK

        # Test empty sources list
        mock_plex_service.get_media_sources.return_value = []
        response = await async_client.get(
            "/api/media-sources",
            headers=authenticated_headers
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == []

    @pytest.mark.asyncio
    async def test_get_media_sources_handles_empty_sources_list(
        self,
        async_client: AsyncClient,
        authenticated_headers: dict[str, str],
        mock_plex_service: MagicMock
    ) -> None:
        """Test case: Handle empty media sources list."""
        # Arrange
        mock_plex_service.get_media_sources.return_value = []

        # Act
        response = await async_client.get(
            "/api/media-sources",
            headers=authenticated_headers
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == []

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
        mock_plex_service.get_media_sources.side_effect = AuthenticationException(
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
        mock_plex_service.get_media_sources.return_value = []

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
        """Test case: Verify secure logging without exposing sensitive data."""
        # Arrange
        mock_plex_service.get_media_sources.return_value = []

        # Act
        response = await async_client.get(
            "/api/media-sources",
            headers=authenticated_headers
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        
        # Verify logs don't contain sensitive information
        log_messages = [record.message for record in caplog.records]
        for message in log_messages:
            assert "token" not in message.lower()
            assert "password" not in message.lower()
            assert "secret" not in message.lower() 