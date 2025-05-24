"""
Unit tests for Plex API data models.

Tests for Pydantic models representing Plex API response structures,
including PlexUser and OnlineMediaSource models with validation.
"""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.models.plex_models import PlexUser, OnlineMediaSource


class TestPlexUserModel:
    """Test cases for PlexUser Pydantic model validation."""

    def test_plex_user_model_validation_with_valid_data(self) -> None:
        """Test PlexUser model validation with valid user data."""
        # This test should pass when model is implemented correctly
        user = PlexUser(
            id=12345,
            uuid="test-uuid-12345",
            username="testuser",
            email="test@example.com",
            authentication_token="test-token-abcdef123456",
            thumb="https://plex.tv/users/test/avatar.jpg",
            confirmed=True,
            restricted=False,
            guest=False,
            subscription_active=True,
            subscription_plan="plexpass",
        )
        
        # Verify all fields are set correctly
        assert user.id == 12345
        assert user.uuid == "test-uuid-12345"
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.authentication_token == "test-token-abcdef123456"
        assert user.thumb == "https://plex.tv/users/test/avatar.jpg"
        assert user.confirmed is True
        assert user.restricted is False
        assert user.guest is False
        assert user.subscription_active is True
        assert user.subscription_plan == "plexpass"

    def test_plex_user_model_handle_missing_required_fields(self) -> None:
        """Test PlexUser model validation with missing required fields."""
        # Test missing id
        with pytest.raises(ValidationError) as exc_info:
            invalid_data = {
                "uuid": "test-uuid",
                "username": "testuser", 
                "email": "test@example.com",
                "authentication_token": "test-token"
            }
            _ = PlexUser(**invalid_data)  # pyright: ignore[reportArgumentType]
        assert "id" in str(exc_info.value)
        
        # Test missing uuid
        with pytest.raises(ValidationError) as exc_info:
            invalid_data = {
                "id": 12345,
                "username": "testuser",
                "email": "test@example.com", 
                "authentication_token": "test-token"
            }
            _ = PlexUser(**invalid_data)  # pyright: ignore[reportArgumentType]
        assert "uuid" in str(exc_info.value)
        
        # Test missing username
        with pytest.raises(ValidationError) as exc_info:
            invalid_data = {
                "id": 12345,
                "uuid": "test-uuid",
                "email": "test@example.com",
                "authentication_token": "test-token"
            }
            _ = PlexUser(**invalid_data)  # pyright: ignore[reportArgumentType]
        assert "username" in str(exc_info.value)

    def test_plex_user_username_validation(self) -> None:
        """Test PlexUser username validation rules."""
        # Test empty username
        with pytest.raises(ValidationError) as exc_info:
            _ = PlexUser(
                id=12345,
                uuid="test-uuid-12345",
                email="test@example.com",
                authentication_token="test-token-abcdef123456",
                username=""
            )
        assert "username" in str(exc_info.value)
        
        # Test whitespace-only username
        with pytest.raises(ValidationError) as exc_info:
            _ = PlexUser(
                id=12345,
                uuid="test-uuid-12345",
                email="test@example.com",
                authentication_token="test-token-abcdef123456",
                username="   "
            )
        assert "username" in str(exc_info.value)
        
        # Test valid username
        user = PlexUser(
            id=12345,
            uuid="test-uuid-12345",
            email="test@example.com",
            authentication_token="test-token-abcdef123456",
            username="validuser123"
        )
        assert user.username == "validuser123"

    def test_plex_user_email_validation(self) -> None:
        """Test PlexUser email validation rules."""
        # Test invalid email format
        with pytest.raises(ValidationError) as exc_info:
            _ = PlexUser(
                id=12345,
                uuid="test-uuid-12345",
                username="testuser",
                authentication_token="test-token-abcdef123456",
                email="invalid-email"
            )
        assert "email" in str(exc_info.value)
        
        # Test empty email
        with pytest.raises(ValidationError) as exc_info:
            _ = PlexUser(
                id=12345,
                uuid="test-uuid-12345",
                username="testuser",
                authentication_token="test-token-abcdef123456",
                email=""
            )
        assert "email" in str(exc_info.value)
        
        # Test valid email
        user = PlexUser(
            id=12345,
            uuid="test-uuid-12345",
            username="testuser",
            authentication_token="test-token-abcdef123456",
            email="valid@example.com"
        )
        assert user.email == "valid@example.com"

    def test_plex_user_oauth_token_model_with_expiration_handling(self) -> None:
        """Test PlexUser OAuth token model with expiration handling."""
        # Test with token expiration time
        user = PlexUser(
            id=12345,
            uuid="test-uuid-12345",
            username="testuser",
            email="test@example.com",
            authentication_token="test-token-abcdef123456",
            token_expires_at=datetime.now(timezone.utc),
        )
        
        assert user.authentication_token == "test-token-abcdef123456"
        assert user.token_expires_at is not None
        assert isinstance(user.token_expires_at, datetime)

    def test_plex_user_optional_fields_defaults(self) -> None:
        """Test PlexUser model with optional fields having proper defaults."""
        user = PlexUser(
            id=12345,
            uuid="test-uuid-12345",
            username="testuser",
            email="test@example.com",
            authentication_token="test-token-abcdef123456",
        )
        
        # Check optional fields have appropriate defaults
        assert user.thumb is None
        assert user.confirmed is False  # Should default to False for security
        assert user.restricted is False
        assert user.guest is False
        assert user.subscription_active is False
        assert user.subscription_plan is None

    def test_plex_user_privacy_focused_data_filtering(self) -> None:
        """Test PlexUser model filters sensitive data appropriately."""
        # This model should only contain essential user data for our application
        user = PlexUser(
            id=12345,
            uuid="test-uuid-12345",
            username="testuser",
            email="test@example.com",
            authentication_token="test-token-abcdef123456",
            thumb="https://plex.tv/users/test/avatar.jpg",
        )
        
        # Verify we only store essential data (privacy-first approach)
        required_fields = ["id", "uuid", "username", "email", "authentication_token"]
        for field in required_fields:
            assert hasattr(user, field)
            
        # Should not contain sensitive personal information beyond what's needed
        assert not hasattr(user, "password")
        assert not hasattr(user, "personal_info")

    def test_plex_user_model_immutability(self) -> None:
        """Test PlexUser model configuration for immutability and security."""
        user = PlexUser(
            id=12345,
            uuid="test-uuid-12345",
            username="testuser",
            email="test@example.com",
            authentication_token="test-token-abcdef123456",
        )
        
        # The model should be configured to prevent modification after creation
        # This will be enforced by Pydantic's frozen=True configuration
        with pytest.raises((ValidationError, AttributeError)):
            user.username = "modified_username"


class TestOnlineMediaSourceModel:
    """Test cases for OnlineMediaSource Pydantic model validation."""

    def test_online_media_source_model_with_source_metadata(self) -> None:
        """Test OnlineMediaSource model validation with valid source metadata."""
        # This test should pass when model is implemented correctly
        source = OnlineMediaSource(
            identifier="tidal",
            title="TIDAL",
            scrobble_types=["track"],
            enabled=True
        )
        
        # Verify all fields are set correctly
        assert source.identifier == "tidal"
        assert source.title == "TIDAL"
        assert source.scrobble_types == ["track"]
        assert source.enabled is True

    def test_online_media_source_type_validation(self) -> None:
        """Test OnlineMediaSource model source type validation rules."""
        # Test valid identifier formats
        valid_identifiers = ["tidal", "spotify", "youtube", "lastfm", "musicbrainz"]
        for identifier in valid_identifiers:
            source = OnlineMediaSource(
                identifier=identifier,
                title=f"Test {identifier.title()}",
                scrobble_types=["track"],
                enabled=True
            )
            assert source.identifier == identifier
        
        # Test empty identifier
        with pytest.raises(ValidationError) as exc_info:
            _ = OnlineMediaSource(
                identifier="",
                title="Empty Identifier",
                scrobble_types=["track"],
                enabled=True
            )
        assert "identifier" in str(exc_info.value)
        
        # Test whitespace-only identifier
        with pytest.raises(ValidationError) as exc_info:
            _ = OnlineMediaSource(
                identifier="   ",
                title="Whitespace Identifier",
                scrobble_types=["track"],
                enabled=True
            )
        assert "identifier" in str(exc_info.value)

    def test_online_media_source_enable_disable_status_handling(self) -> None:
        """Test OnlineMediaSource model enable/disable status handling."""
        # Test enabled source
        enabled_source = OnlineMediaSource(
            identifier="spotify",
            title="Spotify",
            scrobble_types=["track"],
            enabled=True
        )
        assert enabled_source.enabled is True
        
        # Test disabled source
        disabled_source = OnlineMediaSource(
            identifier="youtube",
            title="YouTube",
            scrobble_types=["track"],
            enabled=False
        )
        assert disabled_source.enabled is False
        
        # Test default enabled status (should default to False for privacy)
        default_source = OnlineMediaSource(
            identifier="lastfm",
            title="Last.fm",
            scrobble_types=["track"]
        )
        assert default_source.enabled is False

    def test_online_media_source_identifier_validation(self) -> None:
        """Test OnlineMediaSource identifier validation rules."""
        # Test missing identifier
        with pytest.raises(ValidationError) as exc_info:
            invalid_data = {
                "title": "Missing Identifier",
                "scrobble_types": ["track"],
                "enabled": True
            }
            _ = OnlineMediaSource(**invalid_data)  # pyright: ignore[reportArgumentType]
        assert "identifier" in str(exc_info.value)
        
        # Test missing title
        with pytest.raises(ValidationError) as exc_info:
            invalid_data = {
                "identifier": "test",
                "scrobble_types": ["track"],
                "enabled": True
            }
            _ = OnlineMediaSource(**invalid_data)  # pyright: ignore[reportArgumentType]
        assert "title" in str(exc_info.value)
        
        # Test valid minimal source
        minimal_source = OnlineMediaSource(
            identifier="minimal",
            title="Minimal Source",
            scrobble_types=["track"]
        )
        assert minimal_source.identifier == "minimal"
        assert minimal_source.title == "Minimal Source"
        assert minimal_source.scrobble_types == ["track"]
        assert minimal_source.enabled is False

    def test_online_media_source_scrobble_types_validation(self) -> None:
        """Test OnlineMediaSource scrobble types validation rules."""
        # Test valid scrobble types
        valid_types = [["track"], ["album"], ["artist"], ["track", "album"], ["track", "album", "artist"]]
        for scrobble_types in valid_types:
            source = OnlineMediaSource(
                identifier="test",
                title="Test Source",
                scrobble_types=scrobble_types,
                enabled=True
            )
            assert source.scrobble_types == scrobble_types
        
        # Test empty scrobble types (should be allowed but default to empty list)
        source_no_scrobble = OnlineMediaSource(
            identifier="test",
            title="Test Source",
            scrobble_types=[],
            enabled=True
        )
        assert source_no_scrobble.scrobble_types == []
        
        # Test default scrobble types
        source_default = OnlineMediaSource(
            identifier="test",
            title="Test Source"
        )
        assert source_default.scrobble_types == []

    def test_online_media_source_privacy_focused_data_filtering(self) -> None:
        """Test OnlineMediaSource model filters data appropriately for privacy."""
        source = OnlineMediaSource(
            identifier="spotify",
            title="Spotify",
            scrobble_types=["track"],
            enabled=True
        )
        
        # Verify we only store essential data (privacy-first approach)
        required_fields = ["identifier", "title", "scrobble_types", "enabled"]
        for field in required_fields:
            assert hasattr(source, field)
        
        # Should not contain sensitive personal information or tracking data
        assert not hasattr(source, "user_data")
        assert not hasattr(source, "personal_info")
        assert not hasattr(source, "access_token")

    def test_online_media_source_model_immutability(self) -> None:
        """Test OnlineMediaSource model configuration for immutability and security."""
        source = OnlineMediaSource(
            identifier="test",
            title="Test Source",
            scrobble_types=["track"],
            enabled=True
        )
        
        # The model should be configured to prevent modification after creation
        # This will be enforced by Pydantic's frozen=True configuration
        with pytest.raises((ValidationError, AttributeError)):
            source.enabled = False

    def test_online_media_source_optional_fields_defaults(self) -> None:
        """Test OnlineMediaSource model with optional fields having proper defaults."""
        source = OnlineMediaSource(
            identifier="test",
            title="Test Source"
        )
        
        # Check optional fields have appropriate defaults for privacy/security
        assert source.scrobble_types == []
        assert source.enabled is False  # Should default to False for privacy 