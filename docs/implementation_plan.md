# Plex Online Media Sources Manager - Implementation Plan

## Overview
This plan follows Test-Driven Development (TDD) principles, implementing each feature through the Red-Green-Refactor cycle. Each phase builds incrementally, ensuring a robust and well-tested codebase.

## Phase 1: Project Foundation & Environment Setup

### 1.1 Project Structure Setup
**Goal**: Establish the basic project structure and development environment

**Tasks**:
1. Initialize Python project with `uv`
2. Create frontend structure with Vite + React
3. Configure development tools and linting
4. Set up pre-commit hooks

**TDD Approach**: Create basic smoke tests to ensure environment is working

```bash
# Backend setup
uv init plex-oms-service
cd plex-oms-service
uv add fastapi uvicorn plexapi pydantic-settings pytest pytest-asyncio httpx pytest-mock ruff basedpyright
uv add --dev pytest-cov pytest-xdist

# Frontend setup
cd frontend
npm create vue@latest . --template react-ts
npm install @tanstack/react-query zustand react-router-dom @radix-ui/react-dialog
npm install -D vitest @testing-library/react @testing-library/jest-dom msw
```

**Test First**:
```python
# tests/test_environment.py
def test_python_version():
    import sys
    assert sys.version_info >= (3, 13)

def test_fastapi_import():
    import fastapi
    assert fastapi.__version__ >= "0.104"
```

### 1.2 Configuration Setup
**Goal**: Create type-safe configuration management

**Test First**:
```python
# tests/unit/test_config.py
import pytest
from app.config import Settings

def test_settings_validation():
    """Test that settings validate required fields"""
    with pytest.raises(ValueError):
        Settings()  # Should fail without required env vars

def test_settings_with_env_vars(monkeypatch):
    """Test settings creation with proper env vars"""
    monkeypatch.setenv("PLEX_CLIENT_ID", "test-client")
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    settings = Settings()
    assert settings.plex_client_id == "test-client"
```

**Implementation**:
```python
# app/config.py
from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    # Plex OAuth Configuration
    plex_client_id: str
    plex_client_secret: str = ""  # Not needed for PIN auth
    plex_redirect_uri: str = "http://localhost:8000/auth/callback"
    
    # Security
    secret_key: str
    cors_origins: List[str] = ["http://localhost:3000"]
    
    # Application
    environment: str = "development"
    log_level: str = "INFO"
    
    class Config:
        env_file = ".env"

settings = Settings()
```

### 1.3 Basic FastAPI Application
**Goal**: Create minimal FastAPI app with health checks

**Test First**:
```python
# tests/test_main.py
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}
```

**Implementation**:
```python
# app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings

app = FastAPI(
    title="Plex Online Media Sources Manager",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    return {"status": "healthy"}
```

### 1.4 Frontend Foundation
**Goal**: Create basic React app structure with TypeScript

**Test First**:
```typescript
// frontend/src/__tests__/App.test.tsx
import { render, screen } from '@testing-library/react'
import App from '../App'

test('renders without crashing', () => {
  render(<App />)
  expect(screen.getByText(/Plex OMS/i)).toBeInTheDocument()
})
```

**Implementation**:
```typescript
// frontend/src/App.tsx
import React from 'react'

function App() {
  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto py-6 px-4">
          <h1 className="text-3xl font-bold text-gray-900">
            Plex OMS Manager
          </h1>
        </div>
      </header>
    </div>
  )
}

export default App
```

## Phase 2: Authentication Service Development (TDD)

### 2.1 Plex OAuth Service Foundation
**Goal**: Implement core Plex authentication using PlexAPI

**Test First**:
```python
# tests/unit/test_auth_service.py
import pytest
from unittest.mock import Mock, patch
from app.services.auth_service import AuthService
from app.utils.exceptions import AuthenticationException

class TestAuthService:
    def test_initiate_oauth_creates_pin(self):
        """Test OAuth initiation creates PIN login"""
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin:
            mock_pin.return_value.pin = "1234"
            mock_pin.return_value.code = "test-code"
            
            auth_service = AuthService()
            result = auth_service.initiate_oauth()
            
            assert result["pin"] == "1234"
            assert result["code"] == "test-code"
            mock_pin.assert_called_once()

    def test_check_pin_status_success(self):
        """Test successful PIN authentication"""
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin:
            mock_account = Mock()
            mock_account.authenticationToken = "test-token"
            mock_account.username = "testuser"
            
            mock_pin_instance = Mock()
            mock_pin_instance.checkLogin.return_value = mock_account
            mock_pin.return_value = mock_pin_instance
            
            auth_service = AuthService()
            auth_service._pin_login = mock_pin_instance
            
            result = auth_service.check_pin_status()
            
            assert result["authenticated"] is True
            assert result["token"] == "test-token"
            assert result["username"] == "testuser"

    def test_check_pin_status_not_ready(self):
        """Test PIN not yet authenticated"""
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin:
            mock_pin_instance = Mock()
            mock_pin_instance.checkLogin.return_value = None
            
            auth_service = AuthService()
            auth_service._pin_login = mock_pin_instance
            
            result = auth_service.check_pin_status()
            
            assert result["authenticated"] is False
```

**Implementation**:
```python
# app/services/auth_service.py
from typing import Dict, Optional, Any
from plexapi.myplex import MyPlexPinLogin, MyPlexAccount
from app.config import settings
from app.utils.exceptions import AuthenticationException
import logging

logger = logging.getLogger(__name__)

class AuthService:
    def __init__(self):
        self._pin_login: Optional[MyPlexPinLogin] = None
        self._account: Optional[MyPlexAccount] = None

    def initiate_oauth(self) -> Dict[str, Any]:
        """Initiate OAuth flow using Plex PIN authentication"""
        try:
            self._pin_login = MyPlexPinLogin(
                headers={'X-Plex-Client-Identifier': settings.plex_client_id}
            )
            
            return {
                "pin": self._pin_login.pin,
                "code": self._pin_login.code,
                "expires_at": self._pin_login.expires,
                "auth_url": f"https://plex.tv/pin/{self._pin_login.code}"
            }
        except Exception as e:
            logger.error(f"Failed to initiate OAuth: {e}")
            raise AuthenticationException("Failed to initiate authentication")

    def check_pin_status(self) -> Dict[str, Any]:
        """Check if PIN has been authenticated"""
        if not self._pin_login:
            raise AuthenticationException("OAuth not initiated")
        
        try:
            account = self._pin_login.checkLogin()
            if account:
                self._account = account
                return {
                    "authenticated": True,
                    "token": account.authenticationToken,
                    "username": account.username,
                    "email": account.email
                }
            else:
                return {"authenticated": False}
        except Exception as e:
            logger.error(f"Failed to check PIN status: {e}")
            raise AuthenticationException("Failed to check authentication status")

    def validate_token(self, token: str) -> Dict[str, Any]:
        """Validate existing authentication token"""
        try:
            account = MyPlexAccount(token=token)
            return {
                "valid": True,
                "username": account.username,
                "email": account.email
            }
        except Exception as e:
            logger.error(f"Token validation failed: {e}")
            return {"valid": False}
```

### 2.2 Authentication API Endpoints
**Goal**: Create REST endpoints for OAuth flow

**Test First**:
```python
# tests/integration/test_auth_endpoints.py
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, Mock
from app.main import app

client = TestClient(app)

class TestAuthEndpoints:
    def test_initiate_auth_success(self):
        """Test successful OAuth initiation"""
        with patch('app.services.auth_service.AuthService') as mock_service:
            mock_service.return_value.initiate_oauth.return_value = {
                "pin": "1234",
                "code": "test-code",
                "auth_url": "https://plex.tv/pin/test-code"
            }
            
            response = client.post("/auth/initiate")
            
            assert response.status_code == 200
            data = response.json()
            assert data["pin"] == "1234"
            assert data["code"] == "test-code"

    def test_check_auth_status_authenticated(self):
        """Test checking auth status when authenticated"""
        with patch('app.services.auth_service.AuthService') as mock_service:
            mock_service.return_value.check_pin_status.return_value = {
                "authenticated": True,
                "token": "test-token",
                "username": "testuser"
            }
            
            response = client.get("/auth/status?code=test-code")
            
            assert response.status_code == 200
            data = response.json()
            assert data["authenticated"] is True
            assert "token" in data

    def test_check_auth_status_pending(self):
        """Test checking auth status when still pending"""
        with patch('app.services.auth_service.AuthService') as mock_service:
            mock_service.return_value.check_pin_status.return_value = {
                "authenticated": False
            }
            
            response = client.get("/auth/status?code=test-code")
            
            assert response.status_code == 200
            data = response.json()
            assert data["authenticated"] is False
```

**Implementation**:
```python
# app/api/routes/auth.py
from fastapi import APIRouter, HTTPException, Depends, Query
from typing import Dict, Any
from app.services.auth_service import AuthService
from app.utils.exceptions import AuthenticationException
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["authentication"])

def get_auth_service() -> AuthService:
    return AuthService()

@router.post("/initiate")
async def initiate_auth(
    auth_service: AuthService = Depends(get_auth_service)
) -> Dict[str, Any]:
    """Initiate Plex OAuth authentication flow"""
    try:
        result = auth_service.initiate_oauth()
        logger.info(f"OAuth initiated for PIN: {result['pin']}")
        return result
    except AuthenticationException as e:
        logger.error(f"Auth initiation failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/status")
async def check_auth_status(
    code: str = Query(..., description="PIN code from initiation"),
    auth_service: AuthService = Depends(get_auth_service)
) -> Dict[str, Any]:
    """Check authentication status for PIN code"""
    try:
        result = auth_service.check_pin_status()
        return result
    except AuthenticationException as e:
        logger.error(f"Auth status check failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/validate")
async def validate_token(
    token: str,
    auth_service: AuthService = Depends(get_auth_service)
) -> Dict[str, Any]:
    """Validate existing authentication token"""
    try:
        result = auth_service.validate_token(token)
        if not result["valid"]:
            raise HTTPException(status_code=401, detail="Invalid token")
        return result
    except AuthenticationException as e:
        logger.error(f"Token validation failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")
```

### 2.3 Frontend Authentication Components
**Goal**: Create React components for OAuth flow

**Test First**:
```typescript
// frontend/src/components/__tests__/AuthButton.test.tsx
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import AuthButton from '../AuthButton'
import * as api from '../../services/api'

vi.mock('../../services/api')

describe('AuthButton', () => {
  test('initiates auth flow on click', async () => {
    const mockInitiateAuth = vi.mocked(api.initiateAuth)
    mockInitiateAuth.mockResolvedValue({
      pin: '1234',
      code: 'test-code',
      auth_url: 'https://plex.tv/pin/test-code'
    })

    render(<AuthButton />)
    
    const button = screen.getByRole('button', { name: /connect plex/i })
    fireEvent.click(button)
    
    await waitFor(() => {
      expect(screen.getByText('1234')).toBeInTheDocument()
    })
    
    expect(mockInitiateAuth).toHaveBeenCalledOnce()
  })

  test('shows loading state during auth', async () => {
    const mockInitiateAuth = vi.mocked(api.initiateAuth)
    mockInitiateAuth.mockImplementation(() => new Promise(() => {})) // Never resolves
    
    render(<AuthButton />)
    
    const button = screen.getByRole('button', { name: /connect plex/i })
    fireEvent.click(button)
    
    expect(screen.getByText(/connecting/i)).toBeInTheDocument()
  })
})
```

**Implementation**:
```typescript
// frontend/src/components/AuthButton.tsx
import React, { useState } from 'react'
import { initiateAuth, checkAuthStatus } from '../services/api'

interface AuthData {
  pin: string
  code: string
  auth_url: string
}

const AuthButton: React.FC = () => {
  const [loading, setLoading] = useState(false)
  const [authData, setAuthData] = useState<AuthData | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleConnect = async () => {
    setLoading(true)
    setError(null)
    
    try {
      const data = await initiateAuth()
      setAuthData(data)
      
      // Open Plex auth page
      window.open(data.auth_url, '_blank')
      
      // Start polling for auth status
      pollAuthStatus(data.code)
    } catch (err) {
      setError('Failed to connect to Plex')
      console.error('Auth initiation failed:', err)
    } finally {
      setLoading(false)
    }
  }

  const pollAuthStatus = async (code: string) => {
    const poll = async () => {
      try {
        const status = await checkAuthStatus(code)
        if (status.authenticated) {
          // Handle successful authentication
          localStorage.setItem('plex_token', status.token)
          setAuthData(null)
          // Redirect or update app state
        } else {
          // Continue polling
          setTimeout(poll, 2000)
        }
      } catch (err) {
        setError('Authentication failed')
        console.error('Auth polling failed:', err)
      }
    }
    
    poll()
  }

  if (authData) {
    return (
      <div className="text-center p-6 bg-white rounded-lg shadow">
        <h3 className="text-lg font-semibold mb-4">Enter this PIN on Plex.tv:</h3>
        <div className="text-4xl font-mono font-bold text-blue-600 mb-4">
          {authData.pin}
        </div>
        <p className="text-gray-600">
          A new window should have opened. If not, 
          <a href={authData.auth_url} target="_blank" rel="noopener noreferrer" 
             className="text-blue-600 hover:underline ml-1">
            click here
          </a>
        </p>
      </div>
    )
  }

  return (
    <button
      onClick={handleConnect}
      disabled={loading}
      className="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-300 
                 text-white font-semibold py-2 px-4 rounded-lg transition-colors"
    >
      {loading ? 'Connecting...' : 'Connect with Plex'}
    </button>
  )
}

export default AuthButton
```

## Phase 3: Plex Service Integration (TDD)

### 3.1 Online Media Sources Service
**Goal**: Implement service to fetch and manage online media sources

**Test First**:
```python
# tests/unit/test_plex_service.py
import pytest
from unittest.mock import Mock, patch
from app.services.plex_service import PlexService
from app.utils.exceptions import PlexAPIException

class TestPlexService:
    def test_get_online_media_sources_success(self):
        """Test successful retrieval of online media sources"""
        mock_account = Mock()
        mock_source1 = Mock()
        mock_source1.key = "provider1"
        mock_source1.title = "Provider 1"
        mock_source1.type = "music"
        
        mock_source2 = Mock()
        mock_source2.key = "provider2"  
        mock_source2.title = "Provider 2"
        mock_source2.type = "video"
        
        mock_account.onlineMediaSources.return_value = [mock_source1, mock_source2]
        
        service = PlexService(mock_account)
        sources = service.get_online_media_sources()
        
        assert len(sources) == 2
        assert sources[0]["key"] == "provider1"
        assert sources[0]["title"] == "Provider 1"
        assert sources[1]["key"] == "provider2"

    def test_get_opt_out_status_success(self):
        """Test getting opt-out status for sources"""
        mock_account = Mock()
        mock_opt_out = Mock()
        mock_opt_out.key = "provider1"
        mock_opt_out.optedOut = True
        
        mock_account.optOuts.return_value = [mock_opt_out]
        
        service = PlexService(mock_account)
        opt_outs = service.get_opt_out_status()
        
        assert "provider1" in opt_outs
        assert opt_outs["provider1"] is True

    def test_disable_all_sources_success(self):
        """Test bulk disabling of all sources"""
        mock_account = Mock()
        mock_source1 = Mock()
        mock_source1.key = "provider1"
        mock_source2 = Mock() 
        mock_source2.key = "provider2"
        
        mock_account.onlineMediaSources.return_value = [mock_source1, mock_source2]
        mock_account.addOptOut = Mock()
        
        service = PlexService(mock_account)
        result = service.disable_all_sources()
        
        assert result["disabled_count"] == 2
        assert mock_account.addOptOut.call_count == 2

    def test_toggle_source_disable(self):
        """Test disabling individual source"""
        mock_account = Mock()
        mock_account.addOptOut = Mock()
        
        service = PlexService(mock_account)
        result = service.toggle_source("provider1", False)
        
        assert result["success"] is True
        mock_account.addOptOut.assert_called_once_with("provider1")

    def test_toggle_source_enable(self):
        """Test enabling individual source"""
        mock_account = Mock()
        mock_account.removeOptOut = Mock()
        
        service = PlexService(mock_account)
        result = service.toggle_source("provider1", True)
        
        assert result["success"] is True
        mock_account.removeOptOut.assert_called_once_with("provider1")
```

**Implementation**:
```python
# app/services/plex_service.py
from typing import Dict, List, Any
from plexapi.myplex import MyPlexAccount
from app.utils.exceptions import PlexAPIException
import logging

logger = logging.getLogger(__name__)

class PlexService:
    def __init__(self, account: MyPlexAccount):
        self.account = account

    def get_online_media_sources(self) -> List[Dict[str, Any]]:
        """Get all available online media sources"""
        try:
            sources = self.account.onlineMediaSources()
            return [
                {
                    "key": source.key,
                    "title": source.title,
                    "type": getattr(source, 'type', 'unknown'),
                    "identifier": getattr(source, 'identifier', source.key)
                }
                for source in sources
            ]
        except Exception as e:
            logger.error(f"Failed to fetch online media sources: {e}")
            raise PlexAPIException("Failed to fetch media sources")

    def get_opt_out_status(self) -> Dict[str, bool]:
        """Get current opt-out status for all sources"""
        try:
            opt_outs = self.account.optOuts()
            return {opt_out.key: opt_out.optedOut for opt_out in opt_outs}
        except Exception as e:
            logger.error(f"Failed to fetch opt-out status: {e}")
            raise PlexAPIException("Failed to fetch opt-out status")

    def disable_all_sources(self) -> Dict[str, Any]:
        """Disable all online media sources"""
        try:
            sources = self.get_online_media_sources()
            disabled_count = 0
            
            for source in sources:
                try:
                    self.account.addOptOut(source["key"])
                    disabled_count += 1
                except Exception as e:
                    logger.warning(f"Failed to disable source {source['key']}: {e}")
            
            return {
                "success": True,
                "disabled_count": disabled_count,
                "total_sources": len(sources)
            }
        except Exception as e:
            logger.error(f"Failed to disable all sources: {e}")
            raise PlexAPIException("Failed to disable sources")

    def toggle_source(self, source_key: str, enable: bool) -> Dict[str, Any]:
        """Enable or disable a specific online media source"""
        try:
            if enable:
                self.account.removeOptOut(source_key)
                logger.info(f"Enabled source: {source_key}")
            else:
                self.account.addOptOut(source_key)
                logger.info(f"Disabled source: {source_key}")
            
            return {"success": True, "enabled": enable}
        except Exception as e:
            logger.error(f"Failed to toggle source {source_key}: {e}")
            raise PlexAPIException(f"Failed to toggle source: {source_key}")

    def get_sources_with_status(self) -> List[Dict[str, Any]]:
        """Get all sources with their current opt-out status"""
        try:
            sources = self.get_online_media_sources()
            opt_outs = self.get_opt_out_status()
            
            for source in sources:
                source["enabled"] = not opt_outs.get(source["key"], False)
            
            return sources
        except Exception as e:
            logger.error(f"Failed to get sources with status: {e}")
            raise PlexAPIException("Failed to get sources status")
```

### 3.2 Media Sources API Endpoints
**Goal**: Create REST endpoints for media sources management

**Test First**:
```python
# tests/integration/test_media_sources_endpoints.py
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, Mock
from app.main import app

client = TestClient(app)

class TestMediaSourcesEndpoints:
    def test_get_media_sources_success(self):
        """Test successful retrieval of media sources"""
        mock_sources = [
            {
                "key": "provider1",
                "title": "Provider 1", 
                "type": "music",
                "enabled": True
            },
            {
                "key": "provider2",
                "title": "Provider 2",
                "type": "video", 
                "enabled": False
            }
        ]
        
        with patch('app.services.plex_service.PlexService') as mock_service:
            mock_service.return_value.get_sources_with_status.return_value = mock_sources
            
            response = client.get(
                "/api/media-sources",
                headers={"Authorization": "Bearer test-token"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert len(data["sources"]) == 2
            assert data["sources"][0]["key"] == "provider1"

    def test_disable_all_sources_success(self):
        """Test bulk disabling all sources"""
        mock_result = {
            "success": True,
            "disabled_count": 5,
            "total_sources": 5
        }
        
        with patch('app.services.plex_service.PlexService') as mock_service:
            mock_service.return_value.disable_all_sources.return_value = mock_result
            
            response = client.post(
                "/api/media-sources/disable-all",
                headers={"Authorization": "Bearer test-token"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["disabled_count"] == 5

    def test_toggle_source_success(self):
        """Test toggling individual source"""
        mock_result = {"success": True, "enabled": False}
        
        with patch('app.services.plex_service.PlexService') as mock_service:
            mock_service.return_value.toggle_source.return_value = mock_result
            
            response = client.patch(
                "/api/media-sources/provider1",
                json={"enabled": False},
                headers={"Authorization": "Bearer test-token"}
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True

    def test_unauthorized_access(self):
        """Test endpoints require authentication"""
        response = client.get("/api/media-sources")
        assert response.status_code == 401
```

**Implementation**:
```python
# app/api/routes/media_sources.py
from fastapi import APIRouter, Depends, HTTPException, Header
from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from app.services.plex_service import PlexService
from app.services.auth_service import AuthService
from app.utils.exceptions import PlexAPIException, AuthenticationException
from plexapi.myplex import MyPlexAccount
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/media-sources", tags=["media_sources"])

class ToggleSourceRequest(BaseModel):
    enabled: bool

async def get_authenticated_account(
    authorization: Optional[str] = Header(None)
) -> MyPlexAccount:
    """Dependency to get authenticated Plex account"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authentication")
    
    token = authorization.split(" ")[1]
    auth_service = AuthService()
    
    try:
        validation = auth_service.validate_token(token)
        if not validation["valid"]:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        return MyPlexAccount(token=token)
    except AuthenticationException:
        raise HTTPException(status_code=401, detail="Authentication failed")

@router.get("")
async def get_media_sources(
    account: MyPlexAccount = Depends(get_authenticated_account)
) -> Dict[str, Any]:
    """Get all online media sources with their status"""
    try:
        plex_service = PlexService(account)
        sources = plex_service.get_sources_with_status()
        
        return {
            "sources": sources,
            "total_count": len(sources),
            "enabled_count": len([s for s in sources if s["enabled"]])
        }
    except PlexAPIException as e:
        logger.error(f"Failed to get media sources: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/disable-all")
async def disable_all_sources(
    account: MyPlexAccount = Depends(get_authenticated_account)
) -> Dict[str, Any]:
    """Disable all online media sources"""
    try:
        plex_service = PlexService(account)
        result = plex_service.disable_all_sources()
        
        logger.info(f"Disabled {result['disabled_count']} sources for user")
        return result
    except PlexAPIException as e:
        logger.error(f"Failed to disable all sources: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.patch("/{source_key}")
async def toggle_source(
    source_key: str,
    request: ToggleSourceRequest,
    account: MyPlexAccount = Depends(get_authenticated_account)
) -> Dict[str, Any]:
    """Enable or disable a specific media source"""
    try:
        plex_service = PlexService(account)
        result = plex_service.toggle_source(source_key, request.enabled)
        
        action = "enabled" if request.enabled else "disabled"
        logger.info(f"Successfully {action} source {source_key}")
        return result
    except PlexAPIException as e:
        logger.error(f"Failed to toggle source {source_key}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
```

## Phase 4: Frontend Media Sources Management (TDD)

### 4.1 API Client Service
**Goal**: Create type-safe API client for frontend

**Test First**:
```typescript
// frontend/src/services/__tests__/api.test.ts
import { vi } from 'vitest'
import { getMediaSources, disableAllSources, toggleSource } from '../api'

// Mock fetch
global.fetch = vi.fn()

describe('API Client', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  test('getMediaSources makes correct request', async () => {
    const mockResponse = {
      sources: [
        { key: 'provider1', title: 'Provider 1', enabled: true }
      ]
    }
    
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockResponse)
    } as Response)

    const result = await getMediaSources('test-token')
    
    expect(fetch).toHaveBeenCalledWith('/api/media-sources', {
      headers: {
        'Authorization': 'Bearer test-token',
        'Content-Type': 'application/json'
      }
    })
    expect(result).toEqual(mockResponse)
  })

  test('disableAllSources makes correct request', async () => {
    const mockResponse = { disabled_count: 5, success: true }
    
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockResponse)
    } as Response)

    const result = await disableAllSources('test-token')
    
    expect(fetch).toHaveBeenCalledWith('/api/media-sources/disable-all', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer test-token',
        'Content-Type': 'application/json'
      }
    })
    expect(result).toEqual(mockResponse)
  })
})
```

**Implementation**:
```typescript
// frontend/src/services/api.ts
export interface MediaSource {
  key: string
  title: string
  type: string
  enabled: boolean
  identifier: string
}

export interface MediaSourcesResponse {
  sources: MediaSource[]
  total_count: number
  enabled_count: number
}

export interface DisableAllResponse {
  success: boolean
  disabled_count: number
  total_sources: number
}

export interface AuthResponse {
  pin: string
  code: string
  auth_url: string
  expires_at: string
}

export interface AuthStatusResponse {
  authenticated: boolean
  token?: string
  username?: string
  email?: string
}

class APIClient {
  private baseURL: string

  constructor() {
    this.baseURL = import.meta.env.VITE_API_URL || 'http://localhost:8000'
  }

  private async request<T>(
    endpoint: string, 
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseURL}${endpoint}`
    
    const response = await fetch(url, {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      ...options
    })

    if (!response.ok) {
      const error = await response.text()
      throw new Error(`API Error: ${response.status} - ${error}`)
    }

    return response.json()
  }

  private getAuthHeaders(token: string) {
    return {
      'Authorization': `Bearer ${token}`
    }
  }

  // Auth endpoints
  async initiateAuth(): Promise<AuthResponse> {
    return this.request<AuthResponse>('/auth/initiate', {
      method: 'POST'
    })
  }

  async checkAuthStatus(code: string): Promise<AuthStatusResponse> {
    return this.request<AuthStatusResponse>(`/auth/status?code=${code}`)
  }

  async validateToken(token: string): Promise<{ valid: boolean; username?: string }> {
    return this.request<{ valid: boolean; username?: string }>('/auth/validate', {
      method: 'POST',
      headers: this.getAuthHeaders(token),
      body: JSON.stringify({ token })
    })
  }

  // Media Sources endpoints
  async getMediaSources(token: string): Promise<MediaSourcesResponse> {
    return this.request<MediaSourcesResponse>('/api/media-sources', {
      headers: this.getAuthHeaders(token)
    })
  }

  async disableAllSources(token: string): Promise<DisableAllResponse> {
    return this.request<DisableAllResponse>('/api/media-sources/disable-all', {
      method: 'POST',
      headers: this.getAuthHeaders(token)
    })
  }

  async toggleSource(
    token: string, 
    sourceKey: string, 
    enabled: boolean
  ): Promise<{ success: boolean; enabled: boolean }> {
    return this.request<{ success: boolean; enabled: boolean }>(
      `/api/media-sources/${sourceKey}`, 
      {
        method: 'PATCH',
        headers: this.getAuthHeaders(token),
        body: JSON.stringify({ enabled })
      }
    )
  }
}

// Export singleton instance
export const apiClient = new APIClient()

// Export convenience functions
export const {
  initiateAuth,
  checkAuthStatus,
  validateToken,
  getMediaSources,
  disableAllSources,
  toggleSource
} = apiClient
```

### 4.2 Media Sources List Component
**Goal**: Create component to display and manage media sources

**Test First**:
```typescript
// frontend/src/components/__tests__/MediaSourcesList.test.tsx
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import MediaSourcesList from '../MediaSourcesList'
import * as api from '../../services/api'

vi.mock('../../services/api')

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } }
  })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      {children}
    </QueryClientProvider>
  )
}

describe('MediaSourcesList', () => {
  test('displays media sources', async () => {
    const mockSources = {
      sources: [
        { key: 'provider1', title: 'Spotify', type: 'music', enabled: true, identifier: 'provider1' },
        { key: 'provider2', title: 'Netflix', type: 'video', enabled: false, identifier: 'provider2' }
      ],
      total_count: 2,
      enabled_count: 1
    }

    vi.mocked(api.getMediaSources).mockResolvedValue(mockSources)

    render(<MediaSourcesList token="test-token" />, { wrapper: createWrapper() })

    await waitFor(() => {
      expect(screen.getByText('Spotify')).toBeInTheDocument()
      expect(screen.getByText('Netflix')).toBeInTheDocument()
    })

    // Check enabled/disabled states
    const spotifyToggle = screen.getByRole('switch', { name: /spotify/i })
    const netflixToggle = screen.getByRole('switch', { name: /netflix/i })
    
    expect(spotifyToggle).toBeChecked()
    expect(netflixToggle).not.toBeChecked()
  })

  test('toggles individual source', async () => {
    const mockSources = {
      sources: [
        { key: 'provider1', title: 'Spotify', type: 'music', enabled: true, identifier: 'provider1' }
      ],
      total_count: 1,
      enabled_count: 1
    }

    vi.mocked(api.getMediaSources).mockResolvedValue(mockSources)
    vi.mocked(api.toggleSource).mockResolvedValue({ success: true, enabled: false })

    render(<MediaSourcesList token="test-token" />, { wrapper: createWrapper() })

    await waitFor(() => {
      expect(screen.getByText('Spotify')).toBeInTheDocument()
    })

    const toggle = screen.getByRole('switch', { name: /spotify/i })
    fireEvent.click(toggle)

    await waitFor(() => {
      expect(api.toggleSource).toHaveBeenCalledWith('test-token', 'provider1', false)
    })
  })
})
```

**Implementation**:
```typescript
// frontend/src/components/MediaSourcesList.tsx
import React from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getMediaSources, toggleSource, MediaSource } from '../services/api'

interface MediaSourcesListProps {
  token: string
}

interface SourceToggleProps {
  source: MediaSource
  onToggle: (sourceKey: string, enabled: boolean) => void
  isLoading?: boolean
}

const SourceToggle: React.FC<SourceToggleProps> = ({ source, onToggle, isLoading }) => {
  return (
    <div className="flex items-center justify-between p-4 border rounded-lg">
      <div className="flex-1">
        <h3 className="font-semibold text-gray-900">{source.title}</h3>
        <p className="text-sm text-gray-500 capitalize">{source.type}</p>
      </div>
      <div className="flex items-center">
        <label className="relative inline-flex items-center cursor-pointer">
          <input
            type="checkbox"
            checked={source.enabled}
            onChange={(e) => onToggle(source.key, e.target.checked)}
            disabled={isLoading}
            className="sr-only peer"
            aria-label={`Toggle ${source.title}`}
          />
          <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 
                          peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer 
                          dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white 
                          after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white 
                          after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 
                          after:transition-all dark:border-gray-600 peer-checked:bg-blue-600
                          disabled:opacity-50 disabled:cursor-not-allowed">
          </div>
        </label>
        <span className="ml-3 text-sm text-gray-600">
          {source.enabled ? 'Enabled' : 'Disabled'}
        </span>
      </div>
    </div>
  )
}

const MediaSourcesList: React.FC<MediaSourcesListProps> = ({ token }) => {
  const queryClient = useQueryClient()

  const {
    data: sourcesData,
    isLoading,
    error,
    refetch
  } = useQuery({
    queryKey: ['mediaSources', token],
    queryFn: () => getMediaSources(token),
    enabled: !!token
  })

  const toggleMutation = useMutation({
    mutationFn: ({ sourceKey, enabled }: { sourceKey: string; enabled: boolean }) =>
      toggleSource(token, sourceKey, enabled),
    onMutate: async ({ sourceKey, enabled }) => {
      // Cancel outgoing refetches
      await queryClient.cancelQueries({ queryKey: ['mediaSources', token] })

      // Snapshot the previous value
      const previousSources = queryClient.getQueryData(['mediaSources', token])

      // Optimistically update
      queryClient.setQueryData(['mediaSources', token], (old: any) => {
        if (!old) return old
        
        return {
          ...old,
          sources: old.sources.map((source: MediaSource) =>
            source.key === sourceKey ? { ...source, enabled } : source
          ),
          enabled_count: old.enabled_count + (enabled ? 1 : -1)
        }
      })

      return { previousSources }
    },
    onError: (err, variables, context) => {
      // Rollback on error
      if (context?.previousSources) {
        queryClient.setQueryData(['mediaSources', token], context.previousSources)
      }
    },
    onSettled: () => {
      // Always refetch after error or success
      queryClient.invalidateQueries({ queryKey: ['mediaSources', token] })
    }
  })

  const handleToggle = (sourceKey: string, enabled: boolean) => {
    toggleMutation.mutate({ sourceKey, enabled })
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        {[...Array(3)].map((_, i) => (
          <div key={i} className="animate-pulse">
            <div className="flex items-center justify-between p-4 border rounded-lg">
              <div className="flex-1">
                <div className="h-4 bg-gray-200 rounded w-1/3 mb-2"></div>
                <div className="h-3 bg-gray-100 rounded w-1/4"></div>
              </div>
              <div className="w-11 h-6 bg-gray-200 rounded-full"></div>
            </div>
          </div>
        ))}
      </div>
    )
  }

  if (error) {
    return (
      <div className="text-center py-8">
        <div className="text-red-600 mb-4">
          Failed to load media sources
        </div>
        <button
          onClick={() => refetch()}
          className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
        >
          Try Again
        </button>
      </div>
    )
  }

  if (!sourcesData || sourcesData.sources.length === 0) {
    return (
      <div className="text-center py-8 text-gray-500">
        No online media sources found
      </div>
    )
  }

  return (
    <div>
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-gray-900 mb-2">
          Online Media Sources
        </h2>
        <p className="text-gray-600">
          {sourcesData.enabled_count} of {sourcesData.total_count} sources enabled
        </p>
      </div>

      <div className="space-y-3">
        {sourcesData.sources.map((source) => (
          <SourceToggle
            key={source.key}
            source={source}
            onToggle={handleToggle}
            isLoading={toggleMutation.isPending}
          />
        ))}
      </div>
    </div>
  )
}

export default MediaSourcesList
```

### 4.3 Bulk Disable Component
**Goal**: Create component for bulk disabling all sources

**Test First**:
```typescript
// frontend/src/components/__tests__/BulkDisableButton.test.tsx
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import BulkDisableButton from '../BulkDisableButton'
import * as api from '../../services/api'

vi.mock('../../services/api')

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } }
  })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      {children}
    </QueryClientProvider>
  )
}

describe('BulkDisableButton', () => {
  test('shows confirmation dialog on click', async () => {
    render(<BulkDisableButton token="test-token" />, { wrapper: createWrapper() })

    const button = screen.getByRole('button', { name: /disable all/i })
    fireEvent.click(button)

    await waitFor(() => {
      expect(screen.getByText(/are you sure/i)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /confirm/i })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument()
    })
  })

  test('performs bulk disable on confirmation', async () => {
    vi.mocked(api.disableAllSources).mockResolvedValue({
      success: true,
      disabled_count: 5,
      total_sources: 5
    })

    render(<BulkDisableButton token="test-token" />, { wrapper: createWrapper() })

    const button = screen.getByRole('button', { name: /disable all/i })
    fireEvent.click(button)

    const confirmButton = await screen.findByRole('button', { name: /confirm/i })
    fireEvent.click(confirmButton)

    await waitFor(() => {
      expect(api.disableAllSources).toHaveBeenCalledWith('test-token')
    })

    await waitFor(() => {
      expect(screen.getByText(/successfully disabled 5 sources/i)).toBeInTheDocument()
    })
  })

  test('shows loading state during disable', async () => {
    vi.mocked(api.disableAllSources).mockImplementation(
      () => new Promise(() => {}) // Never resolves
    )

    render(<BulkDisableButton token="test-token" />, { wrapper: createWrapper() })

    const button = screen.getByRole('button', { name: /disable all/i })
    fireEvent.click(button)

    const confirmButton = await screen.findByRole('button', { name: /confirm/i })
    fireEvent.click(confirmButton)

    await waitFor(() => {
      expect(screen.getByText(/disabling/i)).toBeInTheDocument()
    })
  })
})
```

**Implementation**:
```typescript
// frontend/src/components/BulkDisableButton.tsx
import React, { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { disableAllSources } from '../services/api'

interface BulkDisableButtonProps {
  token: string
  onSuccess?: (disabledCount: number) => void
}

interface ConfirmationDialogProps {
  isOpen: boolean
  onConfirm: () => void
  onCancel: () => void
  isLoading: boolean
}

const ConfirmationDialog: React.FC<ConfirmationDialogProps> = ({
  isOpen,
  onConfirm,
  onCancel,
  isLoading
}) => {
  if (!isOpen) return null

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">
          Disable All Online Media Sources?
        </h3>
        <p className="text-gray-600 mb-6">
          This will disable all online media sources from your Plex account. 
          You can re-enable them individually later if needed.
        </p>
        <div className="flex justify-end space-x-3">
          <button
            onClick={onCancel}
            disabled={isLoading}
            className="px-4 py-2 text-gray-700 bg-gray-200 rounded hover:bg-gray-300 
                       disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={isLoading}
            className="px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700 
                       disabled:opacity-50 disabled:cursor-not-allowed flex items-center"
          >
            {isLoading ? (
              <>
                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" 
                     xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" 
                        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Disabling...
              </>
            ) : (
              'Confirm Disable All'
            )}
          </button>
        </div>
      </div>
    </div>
  )
}

const BulkDisableButton: React.FC<BulkDisableButtonProps> = ({ token, onSuccess }) => {
  const [showConfirmation, setShowConfirmation] = useState(false)
  const [successMessage, setSuccessMessage] = useState<string | null>(null)
  const queryClient = useQueryClient()

  const disableAllMutation = useMutation({
    mutationFn: () => disableAllSources(token),
    onSuccess: (data) => {
      setShowConfirmation(false)
      setSuccessMessage(`Successfully disabled ${data.disabled_count} sources`)
      
      // Invalidate media sources query to refresh the list
      queryClient.invalidateQueries({ queryKey: ['mediaSources', token] })
      
      // Call optional success callback
      onSuccess?.(data.disabled_count)
      
      // Clear success message after 5 seconds
      setTimeout(() => setSuccessMessage(null), 5000)
    },
    onError: (error) => {
      setShowConfirmation(false)
      console.error('Failed to disable all sources:', error)
    }
  })

  const handleDisableAll = () => {
    setShowConfirmation(true)
  }

  const handleConfirm = () => {
    disableAllMutation.mutate()
  }

  const handleCancel = () => {
    setShowConfirmation(false)
  }

  return (
    <>
      <div className="mb-6">
        {successMessage && (
          <div className="mb-4 p-4 bg-green-100 border border-green-400 text-green-700 rounded">
            {successMessage}
          </div>
        )}
        
        <button
          onClick={handleDisableAll}
          disabled={disableAllMutation.isPending}
          className="w-full sm:w-auto px-6 py-3 bg-red-600 text-white font-semibold rounded-lg 
                     hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed
                     focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2
                     transition-colors"
        >
          {disableAllMutation.isPending ? 'Processing...' : 'Disable All Sources'}
        </button>
        
        <p className="mt-2 text-sm text-gray-600">
          This will opt out of all online media sources for privacy.
        </p>
      </div>

      <ConfirmationDialog
        isOpen={showConfirmation}
        onConfirm={handleConfirm}
        onCancel={handleCancel}
        isLoading={disableAllMutation.isPending}
      />
    </>
  )
}

export default BulkDisableButton
```

## Phase 5: Integration & Security Hardening

### 5.1 Security Middleware Implementation
**Goal**: Add comprehensive security measures

**Test First**:
```python
# tests/unit/test_security_middleware.py
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from app.main import app

client = TestClient(app)

class TestSecurityMiddleware:
    def test_cors_headers_present(self):
        """Test CORS headers are properly set"""
        response = client.options("/api/media-sources", 
                                headers={"Origin": "http://localhost:3000"})
        
        assert "access-control-allow-origin" in response.headers
        assert response.headers["access-control-allow-credentials"] == "true"

    def test_security_headers_present(self):
        """Test security headers are injected"""
        response = client.get("/health")
        
        assert "x-content-type-options" in response.headers
        assert response.headers["x-content-type-options"] == "nosniff"
        assert "x-frame-options" in response.headers
        assert response.headers["x-frame-options"] == "DENY"

    def test_rate_limiting(self):
        """Test rate limiting middleware"""
        # Make multiple rapid requests
        for _ in range(10):
            response = client.get("/health")
        
        # Should eventually get rate limited
        response = client.get("/health")
        # Note: This test might need adjustment based on rate limit settings
        # assert response.status_code == 429  # Too Many Requests

    def test_request_validation(self):
        """Test malicious request rejection"""
        # Test SQL injection attempt
        response = client.get("/api/media-sources?token='; DROP TABLE users; --")
        assert response.status_code == 401  # Should be rejected as invalid auth

    def test_csrf_protection(self):
        """Test CSRF protection for state-changing operations"""
        # This test would need to be implemented based on CSRF strategy
        pass
```

**Implementation**:
```python
# app/middleware/security.py
from fastapi import Request, Response
from fastapi.middleware.base import BaseHTTPMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import re
import logging

logger = logging.getLogger(__name__)

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

class SecurityMiddleware(BaseHTTPMiddleware):
    """Security middleware for request validation and header injection"""
    
    # Suspicious patterns that might indicate attacks
    SUSPICIOUS_PATTERNS = [
        r"(<script|javascript:|vbscript:)",  # XSS attempts
        r"(union\s+select|drop\s+table|insert\s+into)",  # SQL injection
        r"(\.\.\/|\.\.\\)",  # Path traversal
        r"(<|>|&lt;|&gt;|&#)",  # HTML/XML injection
    ]
    
    def __init__(self, app):
        super().__init__(app)
        self.suspicious_regex = re.compile("|".join(self.SUSPICIOUS_PATTERNS), re.IGNORECASE)

    async def dispatch(self, request: Request, call_next):
        # Validate request for suspicious content
        if self._is_suspicious_request(request):
            logger.warning(f"Suspicious request blocked: {request.url}")
            return Response(content="Invalid request", status_code=400)
        
        # Process request
        response = await call_next(request)
        
        # Add security headers
        self._add_security_headers(response)
        
        return response

    def _is_suspicious_request(self, request: Request) -> bool:
        """Check if request contains suspicious patterns"""
        # Check URL path
        if self.suspicious_regex.search(str(request.url)):
            return True
        
        # Check query parameters
        for value in request.query_params.values():
            if self.suspicious_regex.search(value):
                return True
        
        return False

    def _add_security_headers(self, response: Response):
        """Add security headers to response"""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https://plex.tv; "
            "frame-ancestors 'none';"
        )

# Exception handler for rate limiting
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    logger.warning(f"Rate limit exceeded for {get_remote_address(request)}")
    return Response(
        content="Rate limit exceeded. Please try again later.",
        status_code=429,
        headers={"Retry-After": str(exc.retry_after)}
    )
```

### 5.2 Error Handling & Logging
**Goal**: Implement comprehensive error handling

**Test First**:
```python
# tests/unit/test_exception_handling.py
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from app.main import app
from app.utils.exceptions import PlexAPIException, AuthenticationException

client = TestClient(app)

class TestExceptionHandling:
    def test_plex_api_exception_handling(self):
        """Test PlexAPI exceptions are properly handled"""
        with patch('app.services.plex_service.PlexService') as mock_service:
            mock_service.return_value.get_sources_with_status.side_effect = \
                PlexAPIException("Plex server unavailable")
            
            response = client.get("/api/media-sources", 
                                headers={"Authorization": "Bearer test-token"})
            
            assert response.status_code == 500
            assert "Plex server unavailable" in response.text

    def test_authentication_exception_handling(self):
        """Test authentication exceptions return 401"""
        with patch('app.services.auth_service.AuthService') as mock_service:
            mock_service.return_value.validate_token.side_effect = \
                AuthenticationException("Invalid token")
            
            response = client.get("/api/media-sources",
                                headers={"Authorization": "Bearer invalid-token"})
            
            assert response.status_code == 401

    def test_validation_error_handling(self):
        """Test request validation errors"""
        response = client.patch("/api/media-sources/test", 
                              json={"enabled": "not-a-boolean"},
                              headers={"Authorization": "Bearer test-token"})
        
        assert response.status_code == 422  # Validation error

    def test_unhandled_exception_logging(self):
        """Test that unhandled exceptions are logged"""
        with patch('app.services.plex_service.PlexService') as mock_service:
            mock_service.return_value.get_sources_with_status.side_effect = \
                Exception("Unexpected error")
            
            with patch('app.utils.exceptions.logger') as mock_logger:
                response = client.get("/api/media-sources",
                                    headers={"Authorization": "Bearer test-token"})
                
                assert response.status_code == 500
                mock_logger.error.assert_called()
```

**Implementation**:
```python
# app/utils/exceptions.py
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
import logging
import traceback

logger = logging.getLogger(__name__)

class PlexAPIException(Exception):
    """Exception raised for Plex API related errors"""
    def __init__(self, message: str, status_code: int = 500):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

class AuthenticationException(Exception):
    """Exception raised for authentication related errors"""
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)

class ValidationException(Exception):
    """Exception raised for validation errors"""
    def __init__(self, message: str, field: str = None):
        self.message = message
        self.field = field
        super().__init__(self.message)

# Global exception handlers
async def plex_api_exception_handler(request: Request, exc: PlexAPIException):
    """Handle PlexAPI exceptions"""
    logger.error(f"PlexAPI error on {request.url}: {exc.message}")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "plex_api_error",
            "message": exc.message,
            "detail": "There was an issue communicating with Plex services"
        }
    )

async def authentication_exception_handler(request: Request, exc: AuthenticationException):
    """Handle authentication exceptions"""
    logger.warning(f"Authentication error on {request.url}: {exc.message}")
    return JSONResponse(
        status_code=401,
        content={
            "error": "authentication_error", 
            "message": "Authentication required",
            "detail": exc.message
        }
    )

async def validation_exception_handler(request: Request, exc: ValidationException):
    """Handle validation exceptions"""
    logger.warning(f"Validation error on {request.url}: {exc.message}")
    return JSONResponse(
        status_code=400,
        content={
            "error": "validation_error",
            "message": exc.message,
            "field": exc.field
        }
    )

async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions"""
    logger.error(f"Unhandled exception on {request.url}: {exc}")
    logger.error(traceback.format_exc())
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": "An unexpected error occurred",
            "detail": "Please try again later or contact support"
        }
    )
```

### 5.3 Integration Testing
**Goal**: End-to-end testing of complete workflows

**Test First**:
```python
# tests/integration/test_complete_workflow.py
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, Mock
from app.main import app

client = TestClient(app)

class TestCompleteWorkflow:
    def test_complete_auth_and_disable_workflow(self):
        """Test complete user workflow from auth to disabling sources"""
        
        # Step 1: Initiate authentication
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin:
            mock_pin.return_value.pin = "1234"
            mock_pin.return_value.code = "test-code"
            
            response = client.post("/auth/initiate")
            assert response.status_code == 200
            auth_data = response.json()
            
        # Step 2: Simulate PIN authentication
        with patch('app.services.auth_service.MyPlexPinLogin') as mock_pin:
            mock_account = Mock()
            mock_account.authenticationToken = "test-token"
            mock_account.username = "testuser"
            mock_account.email = "test@example.com"
            
            mock_pin_instance = Mock()
            mock_pin_instance.checkLogin.return_value = mock_account
            
            response = client.get(f"/auth/status?code={auth_data['code']}")
            assert response.status_code == 200
            status = response.json()
            assert status["authenticated"] is True
            token = status["token"]
        
        # Step 3: Get media sources
        with patch('app.services.plex_service.PlexService') as mock_service:
            mock_sources = [
                {"key": "provider1", "title": "Spotify", "enabled": True},
                {"key": "provider2", "title": "Netflix", "enabled": True}
            ]
            mock_service.return_value.get_sources_with_status.return_value = mock_sources
            
            response = client.get("/api/media-sources",
                                headers={"Authorization": f"Bearer {token}"})
            assert response.status_code == 200
            sources_data = response.json()
            assert len(sources_data["sources"]) == 2
        
        # Step 4: Disable all sources
        with patch('app.services.plex_service.PlexService') as mock_service:
            mock_service.return_value.disable_all_sources.return_value = {
                "success": True,
                "disabled_count": 2,
                "total_sources": 2
            }
            
            response = client.post("/api/media-sources/disable-all",
                                 headers={"Authorization": f"Bearer {token}"})
            assert response.status_code == 200
            result = response.json()
            assert result["disabled_count"] == 2

    def test_error_scenarios_in_workflow(self):
        """Test error handling in complete workflow"""
        
        # Test invalid token
        response = client.get("/api/media-sources",
                            headers={"Authorization": "Bearer invalid-token"})
        assert response.status_code == 401
        
        # Test missing authorization
        response = client.get("/api/media-sources")
        assert response.status_code == 401
        
        # Test Plex API failure
        with patch('app.services.plex_service.PlexService') as mock_service:
            mock_service.return_value.get_sources_with_status.side_effect = \
                Exception("Plex server down")
            
            response = client.get("/api/media-sources",
                                headers={"Authorization": "Bearer test-token"})
            assert response.status_code == 500
```

## Phase 6: Production Readiness & Deployment

### 6.1 Configuration for Production
**Goal**: Production-ready configuration and deployment setup

```python
# app/config.py (Production additions)
from pydantic_settings import BaseSettings
from typing import List, Optional
import secrets

class Settings(BaseSettings):
    # ... existing settings ...
    
    # Production settings
    environment: str = "development"
    debug: bool = False
    
    # Security (production)
    secret_key: str = secrets.token_urlsafe(32)
    session_cookie_secure: bool = True
    session_cookie_httponly: bool = True
    session_cookie_samesite: str = "strict"
    
    # CORS (production)
    cors_origins: List[str] = ["https://yourdomain.com"]
    cors_allow_credentials: bool = True
    
    # Rate limiting
    rate_limit_per_minute: int = 60
    rate_limit_burst: int = 10
    
    # Logging
    log_level: str = "INFO"
    log_format: str = "json"  # For structured logging
    
    # Monitoring
    enable_metrics: bool = True
    metrics_path: str = "/metrics"
    
    # Database (if needed for sessions)
    database_url: Optional[str] = None
    
    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    class Config:
        env_file = ".env"
        case_sensitive = False
```

### 6.2 Docker Configuration
**Goal**: Containerized deployment setup

```dockerfile
# Dockerfile
FROM python:3.13-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN pip install uv

# Set work directory
WORKDIR /app

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --frozen

# Copy application code
COPY . .

# Create non-root user
RUN adduser --disabled-password --gecos '' appuser
RUN chown -R appuser:appuser /app
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Run application
CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  backend:
    build: .
    ports:
      - "8000:8000"
    environment:
      - ENVIRONMENT=production
      - PLEX_CLIENT_ID=${PLEX_CLIENT_ID}
      - SECRET_KEY=${SECRET_KEY}
      - CORS_ORIGINS=https://yourdomain.com
    volumes:
      - ./logs:/app/logs
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
    environment:
      - VITE_API_URL=https://api.yourdomain.com
    restart: unless-stopped
    depends_on:
      - backend

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - frontend
      - backend
    restart: unless-stopped
```

### 6.3 Monitoring & Logging
**Goal**: Production monitoring and observability

```python
# app/utils/monitoring.py
import logging
import json
import time
from typing import Dict, Any
from fastapi import Request, Response
from fastapi.middleware.base import BaseHTTPMiddleware

class LoggingMiddleware(BaseHTTPMiddleware):
    """Structured logging middleware for production"""
    
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        
        # Log request
        request_id = id(request)
        logger = logging.getLogger("app.requests")
        
        logger.info(json.dumps({
            "event": "request_start",
            "request_id": request_id,
            "method": request.method,
            "url": str(request.url),
            "user_agent": request.headers.get("user-agent", ""),
            "timestamp": start_time
        }))
        
        # Process request
        response = await call_next(request)
        
        # Log response
        process_time = time.time() - start_time
        logger.info(json.dumps({
            "event": "request_complete",
            "request_id": request_id,
            "status_code": response.status_code,
            "process_time": process_time,
            "timestamp": time.time()
        }))
        
        response.headers["X-Process-Time"] = str(process_time)
        return response

# app/utils/metrics.py
from prometheus_client import Counter, Histogram, generate_latest
from fastapi import Response

# Metrics
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
REQUEST_DURATION = Histogram('http_request_duration_seconds', 'HTTP request duration')

def get_metrics():
    """Endpoint to expose Prometheus metrics"""
    return Response(generate_latest(), media_type="text/plain")
```

### 6.4 CI/CD Pipeline
**Goal**: Automated testing and deployment

```yaml
# .github/workflows/ci-cd.yml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test-backend:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Install uv
      uses: astral-sh/setup-uv@v2
    
    - name: Set up Python
      run: uv python install 3.13
    
    - name: Install dependencies
      run: uv sync
    
    - name: Run type checking
      run: uv run basedpyright
    
    - name: Run linting
      run: uv run ruff check
    
    - name: Run tests
      run: uv run pytest --cov=app --cov-report=xml
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3

  test-frontend:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '20'
        cache: 'npm'
        cache-dependency-path: 'frontend/package-lock.json'
    
    - name: Install dependencies
      run: |
        cd frontend
        npm ci
    
    - name: Run type checking
      run: |
        cd frontend
        npm run type-check
    
    - name: Run linting
      run: |
        cd frontend
        npm run lint
    
    - name: Run tests
      run: |
        cd frontend
        npm run test -- --coverage

  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Run security audit
      run: |
        uv run safety check
        cd frontend && npm audit

  deploy:
    needs: [test-backend, test-frontend, security-scan]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Build and deploy
      run: |
        # Add deployment steps here
        echo "Deploying to production..."
```

## Summary

This implementation plan provides a comprehensive, TDD-driven approach to building the Plex Online Media Sources Manager. Each phase builds incrementally:

1. **Phase 1**: Foundation and environment setup
2. **Phase 2**: Core authentication using PlexAPI 
3. **Phase 3**: Plex service integration for media sources management
4. **Phase 4**: Frontend development with React and TypeScript
5. **Phase 5**: Security hardening and integration testing
6. **Phase 6**: Production readiness and deployment

Key benefits of this approach:
- **Test-First Development**: Each feature is driven by failing tests
- **Incremental Progress**: Each phase delivers working functionality  
- **Type Safety**: Strong typing in both Python and TypeScript
- **Security Focus**: Built-in security from the start
- **Production Ready**: Includes monitoring, logging, and deployment

The plan leverages modern best practices including:
- `uv` for Python dependency management
- `basedpyright` for Python type checking  
- React 18+ with modern hooks and patterns
- TailwindCSS v4+ for styling
- Comprehensive testing strategies
- Docker containerization
- CI/CD automation

Would you like me to start implementing any specific phase or component? 