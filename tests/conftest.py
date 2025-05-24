"""
Pytest configuration and shared fixtures for the Plex OMS Service test suite.

This module provides fixtures for:
- FastAPI application testing with async test client
- Mock Plex API responses and objects
- Test database setup and teardown
- Authentication and security test helpers

Following TDD principles with type-safe fixture definitions.
"""

import tempfile
from collections.abc import AsyncGenerator, Callable, Generator
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from plexapi.exceptions import BadRequest, NotFound, Unauthorized  # pyright: ignore[reportMissingTypeStubs]
from plexapi.myplex import MyPlexAccount, MyPlexPinLogin  # pyright: ignore[reportMissingTypeStubs]
from plexapi.server import PlexServer  # pyright: ignore[reportMissingTypeStubs]


@pytest.fixture
def app() -> FastAPI:
    """Create FastAPI application instance for testing."""
    # Create a minimal FastAPI app for testing
    # This will be replaced with actual app factory when main.py is created
    test_app = FastAPI(title="Test Plex OMS Service", version="0.1.0")
    
    @test_app.get("/health")
    async def health_check() -> dict[str, str]:  # pyright: ignore[reportUnusedFunction]
        return {"status": "ok"}
    
    return test_app


@pytest_asyncio.fixture
async def async_client(app: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    """Create async test client for FastAPI application."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver"
    ) as client:
        yield client


@pytest.fixture
def temp_dir() -> Generator[str, None, None]:
    """Create temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


# Plex API Mock Fixtures

@pytest.fixture
def mock_plex_pin_login(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Mock MyPlexPinLogin for OAuth flow testing."""
    mock_pin_login = MagicMock(spec=MyPlexPinLogin)
    
    # Configure the mock for OAuth mode
    mock_pin_login.pin = "1234"  # Still available but not used in OAuth mode
    mock_pin_login.code = "test-code-12345"
    mock_pin_login.finished = False
    mock_pin_login.username = None
    mock_pin_login.token = None
    
    # Mock OAuth-specific methods
    mock_pin_login.oauthUrl = MagicMock(return_value="https://app.plex.tv/auth/#!?clientID=test&code=test-code-12345")
    mock_pin_login.run = MagicMock()
    mock_pin_login.waitForLogin = MagicMock()
    mock_pin_login.reload = MagicMock()
    
    # Patch the class
    def mock_pin_login_factory(*_args: object, **_kwargs: object) -> MagicMock:
        return mock_pin_login
    
    monkeypatch.setattr("plexapi.myplex.MyPlexPinLogin", mock_pin_login_factory)
    
    return mock_pin_login


@pytest.fixture
def mock_plex_account(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Mock MyPlexAccount for authenticated operations testing."""
    mock_account = MagicMock(spec=MyPlexAccount)
    
    # Configure user data
    mock_account.username = "testuser"
    mock_account.email = "test@example.com"
    mock_account.id = 12345
    mock_account.uuid = "test-uuid-12345"
    mock_account.authenticationToken = "test-token-abcdef"
    mock_account.thumb = "https://plex.tv/users/test/avatar"
    
    # Mock online media sources
    mock_account.onlineMediaSources = MagicMock(return_value=[
        {
            "identifier": "tidal",
            "title": "TIDAL",
            "scrobbleTypes": ["track"],
            "enabled": True
        },
        {
            "identifier": "youtube",
            "title": "YouTube",
            "scrobbleTypes": ["track"],
            "enabled": True
        },
        {
            "identifier": "spotify",
            "title": "Spotify",
            "scrobbleTypes": ["track"],
            "enabled": False
        }
    ])
    
    # Mock opt-out functionality
    mock_account.accountOptOut = MagicMock()
    mock_account.accountOptOut.optOut = MagicMock(return_value=True)  # pyright: ignore[reportAny]
    
    # Patch the class
    def mock_account_factory(*_args: object, **_kwargs: object) -> MagicMock:
        return mock_account
    
    monkeypatch.setattr("plexapi.myplex.MyPlexAccount", mock_account_factory)
    
    return mock_account


@pytest.fixture
def mock_plex_server(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Mock PlexServer for server operations testing (if needed)."""
    mock_server = MagicMock(spec=PlexServer)
    
    # Configure server data
    mock_server.friendlyName = "Test Plex Server"
    mock_server.machineIdentifier = "test-server-123"
    mock_server.version = "1.40.0.7998"
    mock_server.myPlexUsername = "testuser"
    
    def mock_server_factory(*_args: object, **_kwargs: object) -> MagicMock:
        return mock_server
    
    monkeypatch.setattr("plexapi.server.PlexServer", mock_server_factory)
    
    return mock_server


@pytest.fixture
def mock_oauth_flow_success(mock_plex_pin_login: MagicMock, mock_plex_account: MagicMock) -> dict[str, object]:
    """Mock successful OAuth flow from start to finish."""
    # Configure successful OAuth login
    mock_plex_pin_login.waitForLogin.return_value = True  # pyright: ignore[reportAny]
    mock_plex_pin_login.finished = True
    mock_plex_pin_login.username = "testuser"
    mock_plex_pin_login.token = "test-token-success"
    
    return {
        "pin_login": mock_plex_pin_login,
        "account": mock_plex_account,
        "oauth_url": "https://app.plex.tv/auth/#!?clientID=test&code=test-code-12345",
        "code": "test-code-12345",
        "token": "test-token-success"
    }


@pytest.fixture
def mock_oauth_flow_failure(mock_plex_pin_login: MagicMock) -> dict[str, object]:
    """Mock failed OAuth flow scenarios."""
    # Configure failed OAuth login
    mock_plex_pin_login.waitForLogin.side_effect = Unauthorized("Invalid authorization code")  # pyright: ignore[reportAny]
    mock_plex_pin_login.finished = False
    mock_plex_pin_login.username = None
    mock_plex_pin_login.token = None
    
    return {
        "pin_login": mock_plex_pin_login,
        "error": "Invalid authorization code"
    }


@pytest.fixture
def mock_plex_api_errors() -> dict[str, Callable[..., None]]:
    """Mock various Plex API error scenarios for testing error handling."""
    def raise_unauthorized(*_args: object, **_kwargs: object) -> None:
        raise Unauthorized("Invalid authentication token")
    
    def raise_not_found(*_args: object, **_kwargs: object) -> None:
        raise NotFound("Resource not found")
    
    def raise_bad_request(*_args: object, **_kwargs: object) -> None:
        raise BadRequest("Invalid request parameters")
    
    return {
        "unauthorized": raise_unauthorized,
        "not_found": raise_not_found,
        "bad_request": raise_bad_request
    }


# Authentication Test Fixtures

@pytest.fixture
def valid_auth_token() -> str:
    """Provide a valid test authentication token."""
    return "test-token-valid-12345"


@pytest.fixture
def invalid_auth_token() -> str:
    """Provide an invalid test authentication token."""
    return "test-token-invalid-54321"


@pytest.fixture
def expired_auth_token() -> str:
    """Provide an expired test authentication token."""
    return "test-token-expired-99999"


@pytest.fixture
def auth_headers(valid_auth_token: str) -> dict[str, str]:
    """Provide authentication headers for API requests."""
    return {
        "Authorization": f"Bearer {valid_auth_token}",
        "Content-Type": "application/json"
    }


@pytest.fixture
def test_user_data() -> dict[str, str | int]:
    """Provide test user data for authentication tests."""
    return {
        "id": 12345,
        "uuid": "test-uuid-12345",
        "username": "testuser",
        "email": "test@example.com",
        "thumb": "https://plex.tv/users/test/avatar",
        "authenticationToken": "test-token-valid-12345"
    }


# Media Sources Test Fixtures

@pytest.fixture
def sample_media_sources() -> list[dict[str, str | list[str] | bool]]:
    """Provide sample online media sources data for testing."""
    return [
        {
            "identifier": "tidal",
            "title": "TIDAL",
            "scrobbleTypes": ["track"],
            "enabled": True
        },
        {
            "identifier": "youtube",
            "title": "YouTube",
            "scrobbleTypes": ["track"],
            "enabled": True
        },
        {
            "identifier": "spotify",
            "title": "Spotify",
            "scrobbleTypes": ["track"],
            "enabled": False
        },
        {
            "identifier": "lastfm",
            "title": "Last.fm",
            "scrobbleTypes": ["track"],
            "enabled": True
        }
    ]


@pytest.fixture
def empty_media_sources() -> list[dict[str, str | list[str] | bool]]:
    """Provide empty media sources list for testing edge cases."""
    return []


# Database Test Fixtures (if database is used in future)

@pytest.fixture
def test_db_config() -> dict[str, str | bool]:
    """Provide test database configuration."""
    return {
        "database_url": "sqlite:///test.db",
        "echo": False,
        "pool_pre_ping": True
    }


# Security Test Fixtures

@pytest.fixture
def csrf_token() -> str:
    """Provide test CSRF token."""
    return "test-csrf-token-12345"


@pytest.fixture
def security_headers() -> dict[str, str]:
    """Provide security headers for testing."""
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'"
    }


# Test Configuration Fixtures

@pytest.fixture
def test_config() -> dict[str, str | bool | list[str]]:
    """Provide test configuration overrides."""
    return {
        "TESTING": True,
        "PLEX_CLIENT_ID": "test-client-id",
        "PLEX_CLIENT_SECRET": "test-client-secret",
        "SECRET_KEY": "test-secret-key-for-testing-only",
        "CORS_ORIGINS": ["http://localhost:3000", "http://testserver"],
        "RATE_LIMIT_ENABLED": False  # Disable for testing
    }


# Async Mock Helpers

@pytest.fixture
def async_mock() -> AsyncMock:
    """Create AsyncMock for testing async functions."""
    return AsyncMock()


@pytest.fixture
def mock_httpx_client() -> AsyncMock:
    """Mock httpx AsyncClient for external API calls."""
    mock_client = AsyncMock()
    mock_client.get = AsyncMock()
    mock_client.post = AsyncMock()
    mock_client.patch = AsyncMock()
    mock_client.delete = AsyncMock()
    return mock_client 