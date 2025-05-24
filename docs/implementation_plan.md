
# Plex Online Media Sources Manager - Implementation Plan

## Overview
This implementation plan follows strict Test-Driven Development (TDD) methodology, ensuring robust, secure, and privacy-first implementation of the Plex Online Media Sources Manager.

## Architecture Improvements Suggested
- Add `app/core/` directory for shared utilities and base classes
- Include `app/schemas/` for request/response schemas separate from models
- Add `frontend/src/contexts/` for React context providers
- Include `scripts/` directory for development and deployment scripts

---

## Phase 1: Project Setup & Configuration

### 1.1 Python Environment Setup
- [ ] Initialize Python 3.13+ environment using `uv`
- [ ] Create virtual environment: `uv venv`
- [ ] Activate environment and verify Python version

### 1.2 Backend Project Structure
- [ ] **Create `pyproject.toml`**
  - Configure uv-based dependency management
  - Set up development dependencies (pytest, basedpyright, ruff)
  - Configure tool settings for linting and type checking
  - Define project metadata and entry points

- [ ] **Create basic project directories**
  ```
  app/
  ├── __init__.py
  ├── core/
  ├── models/
  ├── schemas/
  ├── services/
  ├── api/
  │   └── routes/
  ├── middleware/
  └── utils/
  tests/
  ├── unit/
  ├── integration/
  └── fixtures/
  ```

### 1.3 Frontend Project Structure
- [ ] **Create `frontend/package.json`**
  - Configure React 18.2+, TypeScript 5.3+, TailwindCSS v4.0+
  - Set up Vite build tooling with HMR
  - Configure ESLint with strict TypeScript rules
  - Include testing dependencies (Vitest, React Testing Library)

- [ ] **Create `frontend/tsconfig.json`**
  - Enable strict TypeScript mode
  - Configure path mapping for clean imports
  - Set up React and DOM type definitions

- [ ] **Create `frontend/tailwind.config.ts`**
  - Configure TailwindCSS v4+ with design tokens
  - Set up dark mode support with CSS variables
  - Define custom component classes

- [ ] **Create `frontend/vite.config.ts`**
  - Configure development server with HMR
  - Set up build optimization and code splitting
  - Configure environment variable handling

### 1.4 Development Tools Configuration
- [ ] **Create `.gitignore`** (already exists - verify completeness)
- [ ] **Create development scripts in `scripts/`**
  - `scripts/dev.sh` - Start development servers
  - `scripts/test.sh` - Run all tests
  - `scripts/lint.sh` - Run linting and type checking

---

## Phase 2: Core Backend Development (TDD)

### 2.1 Configuration & Models (TDD)

#### Tests First
- [ ] **Create `tests/conftest.py`**
  - Set up pytest fixtures for FastAPI testing
  - Configure async test client
  - Create mock Plex API fixtures
  - Set up temporary database fixtures

- [ ] **Create `tests/unit/test_config.py`**
  - Test environment variable loading
  - Test configuration validation
  - Test security settings validation
  - Test OAuth configuration

- [ ] **Create `tests/unit/test_plex_models.py`**
  - Test Pydantic model validation
  - Test serialization/deserialization
  - Test field validators
  - Test error handling for invalid data

#### Implementation
- [ ] **Create `app/config.py`**
  - Implement Pydantic BaseSettings for configuration
  - Define environment variables for OAuth (PLEX_CLIENT_ID, PLEX_CLIENT_SECRET)
  - Configure CORS origins and security settings
  - Add validation for required configuration values

- [ ] **Create `app/models/plex_models.py`**
  - Implement PlexUser model with proper field validation
  - Create OnlineMediaSource model with source metadata
  - Define OAuth token models with expiration handling
  - Add response models for API endpoints

- [ ] **Create `app/schemas/`** (New - Improvement)
  - `auth_schemas.py` - Request/response schemas for authentication
  - `media_source_schemas.py` - Schemas for media source operations
  - Separate concerns between data models and API schemas

### 2.2 Authentication Service (TDD)

#### Tests First
- [ ] **Create `tests/unit/test_auth_service.py`**
  - Test MyPlexPinLogin integration
  - Test OAuth flow initiation and completion
  - Test token validation and refresh
  - Test error scenarios (invalid PIN, expired tokens)
  - Mock PlexAPI calls using pytest-mock

#### Implementation
- [ ] **Create `app/services/auth_service.py`**
  - Implement PlexAuthService class using MyPlexPinLogin
  - Create methods for OAuth flow initiation
  - Implement token validation using MyPlexAccount
  - Add secure session management
  - Handle PlexAPI exceptions gracefully

### 2.3 Plex API Service (TDD)

#### Tests First
- [ ] **Create `tests/unit/test_plex_service.py`**
  - Test media sources retrieval using mocked onlineMediaSources()
  - Test bulk disable functionality with AccountOptOut mocks
  - Test individual source management
  - Test API rate limiting and retry logic
  - Mock external PlexAPI calls

#### Implementation
- [ ] **Create `app/services/plex_service.py`**
  - Implement PlexMediaSourceService class
  - Use MyPlexAccount.onlineMediaSources() for source listing
  - Implement bulk operations using AccountOptOut.optOut()
  - Add retry logic with exponential backoff
  - Handle PlexAPI rate limits and errors

### 2.4 API Routes (TDD)

#### Tests First
- [ ] **Create `tests/integration/test_auth_routes.py`**
  - Test OAuth initiation endpoint
  - Test OAuth callback handling
  - Test token refresh endpoint
  - Test logout functionality
  - Test security measures (CSRF, rate limiting)

- [ ] **Create `tests/integration/test_media_source_routes.py`**
  - Test media sources listing endpoint
  - Test bulk disable endpoint
  - Test individual source toggle
  - Test error responses and status codes

#### Implementation
- [ ] **Create `app/api/routes/auth.py`**
  - Implement `/auth/login` endpoint using MyPlexPinLogin
  - Create `/auth/callback` for OAuth completion
  - Add `/auth/refresh` for token renewal
  - Implement `/auth/logout` with session cleanup

- [ ] **Create `app/api/routes/media_sources.py`**
  - Implement `GET /api/media-sources` for listing
  - Create `POST /api/media-sources/disable-all` for bulk operations
  - Add `PATCH /api/media-sources/{source_id}` for individual control
  - Ensure privacy-compliant data handling

### 2.5 Security & Middleware (TDD)

#### Tests First
- [ ] **Create `tests/unit/test_security_middleware.py`**
  - Test CSRF protection
  - Test rate limiting functionality
  - Test security headers injection
  - Test request validation and sanitization

#### Implementation
- [ ] **Create `app/middleware/security.py`**
  - Implement CSRF protection middleware
  - Add rate limiting using slowapi
  - Create security headers injection
  - Implement request validation

- [ ] **Create `app/utils/exceptions.py`**
  - Define custom exception classes for PlexAPI errors
  - Create authentication-specific exceptions
  - Implement global exception handlers
  - Add user-friendly error messages

- [ ] **Create `app/utils/validators.py`**
  - Implement OAuth state validation
  - Add Plex token format validation
  - Create request payload sanitization
  - Add security-focused validation rules

### 2.6 Main Application (TDD)

#### Tests First
- [ ] **Create `tests/integration/test_main.py`**
  - Test FastAPI application startup
  - Test middleware integration
  - Test route registration
  - Test CORS configuration

#### Implementation
- [ ] **Create `app/main.py`**
  - Initialize FastAPI application with security settings
  - Configure CORS middleware
  - Register route modules
  - Set up exception handlers and logging

---

## Phase 3: Frontend Development (TDD)

### 3.1 Core Infrastructure & Types

#### Tests First
- [ ] **Create `frontend/src/__tests__/setup.ts`**
  - Configure testing environment
  - Set up MSW (Mock Service Worker) for API mocking
  - Create test utilities and custom render functions

#### Implementation
- [ ] **Create `frontend/src/types/index.ts`**
  - Define TypeScript interfaces for API responses
  - Create user and media source type definitions
  - Add authentication state types
  - Define component prop interfaces

- [ ] **Create `frontend/src/utils/constants.ts`**
  - Define API endpoint URLs with environment handling
  - Set OAuth configuration constants
  - Add UI text constants for i18n readiness
  - Create feature flag enums

### 3.2 API Service Layer (TDD)

#### Tests First
- [ ] **Create `frontend/src/services/__tests__/api.test.ts`**
  - Test HTTP client functionality
  - Test authentication token injection
  - Test error handling and retry mechanisms
  - Mock fetch calls and responses

#### Implementation
- [ ] **Create `frontend/src/services/api.ts`**
  - Implement type-safe HTTP client using fetch
  - Add authentication token injection middleware
  - Create request/response transformation with zod validation
  - Implement error handling with exponential backoff

### 3.3 React Hooks & State Management (TDD)

#### Tests First
- [ ] **Create `frontend/src/hooks/__tests__/useAuth.test.tsx`**
  - Test authentication state management
  - Test login/logout functionality
  - Test token refresh handling
  - Test error scenarios

- [ ] **Create `frontend/src/hooks/__tests__/useMediaSources.test.tsx`**
  - Test media sources data fetching
  - Test optimistic updates
  - Test error handling and retry logic
  - Test cache invalidation

#### Implementation
- [ ] **Create `frontend/src/contexts/`** (New - Improvement)
  - `AuthContext.tsx` - Authentication context provider
  - `ThemeContext.tsx` - Theme management context

- [ ] **Create `frontend/src/hooks/useAuth.tsx`**
  - Implement type-safe authentication state management
  - Add secure token storage with localStorage/sessionStorage
  - Create authentication methods with error handling
  - Implement automatic token refresh

- [ ] **Create `frontend/src/hooks/useMediaSources.tsx`**
  - Integrate React Query for data management
  - Implement optimistic updates for better UX
  - Add error handling with retry logic
  - Create type-safe API integration

### 3.4 UI Components (TDD)

#### Tests First
- [ ] **Create `frontend/src/components/__tests__/AuthButton.test.tsx`**
  - Test OAuth flow initiation
  - Test loading states and error handling
  - Test accessibility compliance
  - Test user interaction scenarios

- [ ] **Create `frontend/src/components/__tests__/MediaSourcesList.test.tsx`**
  - Test media sources rendering
  - Test individual toggle functionality
  - Test loading and error states
  - Test accessibility features

- [ ] **Create `frontend/src/components/__tests__/BulkDisableButton.test.tsx`**
  - Test bulk disable functionality
  - Test confirmation dialog
  - Test progress indication
  - Test error feedback

#### Implementation
- [ ] **Create `frontend/src/components/AuthButton.tsx`**
  - Implement Plex OAuth authentication button
  - Add loading states with accessible indicators
  - Create user authentication status display
  - Apply responsive design with TailwindCSS v4

- [ ] **Create `frontend/src/components/MediaSourcesList.tsx`**
  - Implement virtualized list for performance
  - Add individual toggle controls with optimistic updates
  - Create loading skeletons and error states
  - Ensure accessibility compliance (ARIA labels, keyboard navigation)

- [ ] **Create `frontend/src/components/BulkDisableButton.tsx`**
  - Implement prominent "Disable All" functionality
  - Add confirmation dialog with clear messaging
  - Create progress indication for bulk operations
  - Implement success/error feedback with toast notifications

### 3.5 Main Application Component (TDD)

#### Tests First
- [ ] **Create `frontend/src/__tests__/App.test.tsx`**
  - Test application routing
  - Test authentication flow integration
  - Test error boundary functionality
  - Test responsive design

#### Implementation
- [ ] **Create `frontend/src/App.tsx`**
  - Set up React Router v6 for navigation
  - Integrate authentication context provider
  - Implement error boundary with proper error handling
  - Configure global state management with Zustand (if needed)

---

## Phase 4: Integration & Security

### 4.1 End-to-End Integration Testing
- [ ] **Create `tests/e2e/test_complete_flow.py`**
  - Test complete OAuth authentication flow
  - Test media sources management end-to-end
  - Test error scenarios and recovery
  - Test security measures integration

### 4.2 Security Hardening
- [ ] **Review and enhance security middleware**
  - Implement Content Security Policy (CSP)
  - Add HSTS headers for HTTPS enforcement
  - Configure secure cookie settings
  - Add request rate limiting and throttling

- [ ] **Create security documentation**
  - Document authentication flow security
  - Create privacy policy compliance notes
  - Document data handling practices
  - Add security best practices guide

### 4.3 Performance Optimization
- [ ] **Backend performance**
  - Implement connection pooling for PlexAPI
  - Add request caching where appropriate
  - Optimize database queries (if using database)
  - Add monitoring and logging

- [ ] **Frontend performance**
  - Implement code splitting for route-based loading
  - Add component lazy loading
  - Optimize bundle size with tree shaking
  - Implement virtual scrolling for large lists

---

## Phase 5: Testing & Quality Assurance

### 5.1 Test Coverage & Quality
- [ ] **Run comprehensive test suite**
  - Ensure 90% backend code coverage
  - Achieve 85% API endpoint coverage
  - Maintain 80% frontend component coverage
  - Verify 100% authentication module coverage

- [ ] **Type checking and linting**
  - Run `uvx basedpyright` for Python type checking
  - Execute TypeScript strict mode compilation
  - Run ruff for Python code quality
  - Execute ESLint for TypeScript/React code quality

### 5.2 Security Testing
- [ ] **Security vulnerability assessment**
  - Test OAuth flow for security vulnerabilities
  - Verify CSRF protection effectiveness
  - Test rate limiting and abuse prevention
  - Validate input sanitization and validation

- [ ] **Privacy compliance verification**
  - Verify minimal data collection practices
  - Test data retention and deletion
  - Validate GDPR compliance measures
  - Review cookie and session handling

### 5.3 User Acceptance Testing
- [ ] **Manual testing scenarios**
  - Test complete user journey from login to media source management
  - Verify error handling and user feedback
  - Test accessibility features with screen readers
  - Validate responsive design across devices

---

## Phase 6: Deployment & Documentation

### 6.1 Deployment Configuration
- [ ] **Create deployment scripts**
  - `scripts/deploy.sh` - Production deployment script
  - `scripts/health-check.sh` - Application health verification
  - Configure environment-specific settings

- [ ] **Create Docker configuration (optional)**
  - `Dockerfile` for backend containerization
  - `docker-compose.yml` for local development
  - Configure production-ready container settings

### 6.2 Documentation
- [ ] **Create comprehensive README.md**
  - Installation and setup instructions
  - Development workflow documentation
  - API documentation with examples
  - Security and privacy information

- [ ] **Create developer documentation**
  - Architecture overview and decisions
  - API reference documentation
  - Testing strategy and guidelines
  - Contribution guidelines

- [ ] **Create user documentation**
  - User guide for media source management
  - Privacy policy and data handling
  - Troubleshooting guide
  - FAQ section

### 6.3 Monitoring & Maintenance
- [ ] **Set up application monitoring**
  - Health check endpoints
  - Error tracking and alerting
  - Performance monitoring
  - Security event logging

- [ ] **Create maintenance procedures**
  - Backup and recovery procedures
  - Update and patch management
  - Security incident response plan
  - User support procedures

---

## Privacy & Security Checklist

### Authentication Security
- [ ] Implement secure OAuth 2.0 flow with proper state validation
- [ ] Use secure session management with HTTPOnly cookies
- [ ] Implement automatic token refresh with proper error handling
- [ ] Add logout functionality that clears all session data

### Data Privacy
- [ ] Minimize data collection to essential functionality only
- [ ] Implement data retention policies with automatic cleanup
- [ ] Ensure no sensitive user data is logged or stored unnecessarily
- [ ] Provide clear privacy policy and data handling documentation
