# Plex Online Media Sources Manager - Project Overview

## Project Description
A privacy-first web application that allows Plex users to authenticate via OAuth and manage their Online Media Sources settings, with a focus on providing an easy "opt-out all" functionality while maintaining GDPR compliance.

## Technology Stack
- **Backend**: Python 3.13+ with FastAPI 0.104+
- **Plex Integration**: python-plexapi 4.15+ for OAuth and MyPlex API
- **Frontend**: TypeScript 5.3+ with React 18.2+ and TailwindCSS v4.0+
- **Authentication**: Plex OAuth 2.0 via MyPlexPinLogin
- **Testing**: pytest 7.4+ with pytest-asyncio, React Testing Library 14+
- **Type Checking**: basedpyright for Python, strict TypeScript config
- **Package Management**: uv for Python dependencies
- **Security**: FastAPI security features, CORS protection, input validation

## TDD Methodology

### Testing Strategy
1. **Red-Green-Refactor Cycle**: Write failing tests first, implement minimal code to pass, then refactor
2. **Test Pyramid**: Unit tests (70%), Integration tests (20%), E2E tests (10%)
3. **Mocking Strategy**: Mock external Plex API calls using pytest-mock and httpx-mock
4. **Frontend Testing**: Component tests with React Testing Library, API mocking with MSW
5. **Type Safety**: Use basedpyright for Python and strict TypeScript for compile-time error catching

### Test Coverage Requirements
- Minimum 90% code coverage for backend services
- 85% coverage for API endpoints
- 80% coverage for frontend components
- 100% coverage for authentication and security modules

## PlexAPI Integration Details

### Authentication Flow
- Use `plexapi.myplex.MyPlexPinLogin(oauth=True)` for OAuth flow initiation with direct Plex account login
- Implement `MyPlexAccount` for authenticated user operations
- Leverage `MyPlexAccount.onlineMediaSources()` for media source management
- Use `AccountOptOut.optOut()` for bulk disable functionality

### Key PlexAPI Classes
- `MyPlexPinLogin`: OAuth 2.0 authentication (always use oauth=True for better UX)
- `MyPlexAccount`: Authenticated user account operations
- `AccountOptOut`: Online media sources opt-out management
- `PlexServer`: Server connection and operations (if needed)

## Project Structure

### Backend Files

#### `pyproject.toml`
**Purpose**: Modern Python project configuration
- Project metadata and dependencies via uv
- Development tool configuration (basedpyright, pytest, ruff)
- Build system configuration
- Version management and scripts

#### `app/main.py`
**Purpose**: FastAPI application entry point and configuration
- Initializes FastAPI app with security headers and CORS middleware
- Configures routes and exception handlers
- Sets up logging and monitoring
- Implements security middleware for XSS/SSRF protection

#### `app/config.py`
**Purpose**: Pydantic Settings-based configuration management
- Environment variable handling with BaseSettings
- OAuth configuration (client ID, secret, redirect URIs)
- Security settings (CORS origins, session secrets)
- Type-safe configuration with validation

#### `app/models/plex_models.py`
**Purpose**: Pydantic v2 models for Plex API data structures
- PlexUser model for authenticated user data
- OnlineMediaSource model representing individual media sources
- OAuth token models for secure token handling
- Response models for API endpoints with Field validators

#### `app/services/plex_service.py`
**Purpose**: Core Plex API integration service using python-plexapi
- PlexAPI wrapper using MyPlexAccount and MyPlexPinLogin
- Methods for fetching user's online media sources via onlineMediaSources()
- Bulk operations using AccountOptOut.optOut() method
- Async/await pattern with proper error handling and retry logic

#### `app/services/auth_service.py`
**Purpose**: OAuth authentication flow management
- Plex OAuth 2.0 implementation using MyPlexPinLogin(oauth=True) for direct login
- Token validation and refresh mechanisms using MyPlexAccount
- Session management with secure cookie handling
- Type-safe authentication state management

#### `app/api/routes/auth.py`
**Purpose**: Authentication endpoint definitions
- OAuth initiation endpoint (`/auth/login`) using MyPlexPinLogin(oauth=True)
- OAuth callback handler (`/auth/callback`) with authorization code verification
- Token refresh endpoint (`/auth/refresh`) with MyPlexAccount
- Logout endpoint with session cleanup

#### `app/api/routes/media_sources.py`
**Purpose**: Online Media Sources management endpoints
- Get current media sources status (`GET /api/media-sources`)
- Bulk disable all sources (`POST /api/media-sources/disable-all`)
- Individual source toggle (`PATCH /api/media-sources/{source_id}`)
- Privacy-compliant data handling with minimal data retention

#### `app/middleware/security.py`
**Purpose**: Security middleware implementation
- CSRF protection for state-changing operations
- Rate limiting to prevent abuse (using slowapi)
- Request validation and sanitization
- Security headers injection (HSTS, CSP, etc.)

#### `app/utils/exceptions.py`
**Purpose**: Custom exception classes and error handling
- PlexAPIException for API-related errors with PlexAPI integration
- AuthenticationException for auth failures
- ValidationException for input validation
- Global exception handlers with user-friendly messages

#### `app/utils/validators.py`
**Purpose**: Input validation utilities
- OAuth state parameter validation
- Plex token format validation using PlexAPI patterns
- Request payload sanitization
- Security-focused validation rules

### Frontend Files

#### `frontend/package.json`
**Purpose**: Modern Node.js project configuration
- React 18.2+, TypeScript 5.3+, TailwindCSS v4.0+
- Vite for build tooling with HMR
- ESLint with strict TypeScript rules
- Testing setup with Vitest and React Testing Library

#### `frontend/tailwind.config.ts`
**Purpose**: TailwindCSS v4+ configuration
- Design system tokens and custom utilities
- Dark mode support with CSS variables
- Responsive design configuration
- Custom component classes for consistency

#### `frontend/src/App.tsx`
**Purpose**: Main React application component
- Application routing with React Router v6
- Global state management with Zustand
- Authentication context provider with proper TypeScript types
- Error boundary implementation with proper error handling

#### `frontend/src/components/AuthButton.tsx`
**Purpose**: Plex OAuth authentication button component
- Initiates OAuth flow with proper error handling
- Loading states with accessible loading indicators
- User authentication status display
- Responsive design with TailwindCSS v4 utilities

#### `frontend/src/components/MediaSourcesList.tsx`
**Purpose**: Display component for online media sources
- Lists all available online media sources with virtualization
- Shows current enabled/disabled status with proper state management
- Individual toggle controls with optimistic updates
- Loading and error state handling with proper UX patterns

#### `frontend/src/components/BulkDisableButton.tsx`
**Purpose**: Bulk action component for disabling all sources
- Prominent "Disable All" button with confirmation dialog
- Progress indication during bulk operations
- Success/error feedback with toast notifications
- Accessibility-compliant design with proper ARIA labels

#### `frontend/src/hooks/useAuth.tsx`
**Purpose**: Custom React hook for authentication state
- Type-safe authentication state management
- Token storage with proper security considerations
- Authentication methods with proper error handling
- Automatic token refresh with exponential backoff

#### `frontend/src/hooks/useMediaSources.tsx`
**Purpose**: Custom hook for media sources data management
- React Query integration for caching and synchronization
- Optimistic updates for better UX
- Error handling with retry logic
- Type-safe API integration

#### `frontend/src/services/api.ts`
**Purpose**: Type-safe API client for backend communication
- Fetch-based HTTP client with proper TypeScript types
- Authentication token injection middleware
- Request/response transformation with zod validation
- Error handling and retry mechanisms with exponential backoff

#### `frontend/src/types/index.ts`
**Purpose**: Comprehensive TypeScript type definitions
- API response interfaces with proper validation
- User and media source type definitions
- Authentication state types with proper state management
- Component prop type definitions with strict typing

#### `frontend/src/utils/constants.ts`
**Purpose**: Type-safe application constants
- API endpoint URLs with proper environment handling
- OAuth configuration constants
- UI text constants with i18n considerations
- Feature flags with proper TypeScript enums

### Testing Files

#### `tests/conftest.py`
**Purpose**: Pytest configuration and shared fixtures
- AsyncIO event loop configuration
- Mock Plex API server fixtures
- Database/session fixtures for integration tests
- Authentication fixtures with proper mocking

#### `tests/unit/test_auth_service.py`
**Purpose**: Unit tests for authentication service
- OAuth flow testing with mocked MyPlexPinLogin
- Token validation and refresh testing
- Error scenario testing with proper exception handling
- Security vulnerability testing

#### `tests/unit/test_plex_service.py`
**Purpose**: Unit tests for Plex API integration
- Media sources retrieval testing with mocked responses
- Bulk operations testing using AccountOptOut mocks
- API error handling testing
- Rate limiting and retry logic testing

#### `tests/integration/test_api_endpoints.py`
**Purpose**: Integration tests for API endpoints
- End-to-end authentication flow testing
- Media sources CRUD operations testing
- Security middleware testing
- Error response validation with proper status codes

#### `tests/frontend/components.test.tsx`
**Purpose**: Frontend component testing
- React component unit tests with React Testing Library
- User interaction testing with proper accessibility considerations
- Authentication flow testing with MSW mocking
- Visual regression testing considerations

### Configuration Files

#### `pyproject.toml`
**Purpose**: Modern Python project configuration
- uv-based dependency management with lock file
- Development dependencies (pytest, basedpyright, ruff)
- Tool configuration for linting and type checking
- Build system configuration

#### `frontend/tsconfig.json`
**Purpose**: Strict TypeScript configuration
- Strict mode enabled with proper compiler options
- Path mapping for clean imports
- Type checking configuration for React
- Build optimization settings

#### `frontend/vite.config.ts`
**Purpose**: Modern build tool configuration
- Development server configuration with HMR
- Build optimization and code splitting
- Testing configuration with Vitest
- Environment variable handling

## Key Features Implementation

### 1. Plex OAuth Authentication
- Uses PlexAPI's `MyPlexPinLogin(oauth=True)` class for direct Plex account login
- Implements secure token storage using MyPlexAccount methods
- Provides seamless authentication experience with proper error handling

### 2. Online Media Sources Management
- Leverages `MyPlexAccount.onlineMediaSources()` method for source listing
- Uses `AccountOptOut` class for individual source management
- Implements bulk disable functionality using `optOut()` method with progress tracking

### 3. Privacy-First Architecture
- Minimal data collection with explicit user consent
- GDPR-compliant data handling with data retention policies
- Secure token management with automatic expiration
- No persistent user data storage beyond session requirements

### 4. Modern Security Implementation
- FastAPI's built-in security features with proper configuration
- CORS protection and CSRF prevention
- Input validation using Pydantic v2 with custom validators
- Rate limiting and request throttling with proper error responses

### 5. Comprehensive Test-Driven Development
- Unit, integration, and E2E tests with proper coverage
- Mocked external dependencies using pytest-mock
- Security vulnerability testing with proper test scenarios
- Frontend component testing with accessibility considerations

### 6. Type Safety & Code Quality
- basedpyright for Python with strict configuration
- TypeScript strict mode for frontend
- Comprehensive linting with ruff (Python) and ESLint (TypeScript)
- Pre-commit hooks for code quality enforcement
