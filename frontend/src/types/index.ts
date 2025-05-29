/**
 * TypeScript type definitions for Plex Online Media Sources Manager.
 * 
 * Defines interfaces that match the backend Pydantic models for
 * type-safe API integration and frontend development.
 * 
 * Privacy-focused design matching backend data minimization principles.
 */

// =============================================================================
// USER-RELATED TYPES
// =============================================================================

/**
 * Plex user interface matching backend PlexUser Pydantic model.
 * Contains essential authentication data with privacy-first design.
 */
export interface PlexUser {
  /** Plex user ID (unique identifier) */
  readonly id: number
  
  /** Plex user UUID (unique identifier string) */
  readonly uuid: string
  
  /** Plex username */
  readonly username: string
  
  /** User's email address (validated format) */
  readonly email: string
  
  /** Plex authentication token for API access */
  readonly authentication_token: string
  
  /** User avatar/thumbnail URL (optional) */
  readonly thumb: string | null
  
  /** Whether user account is confirmed */
  readonly confirmed: boolean
  
  /** Whether user has restricted access */
  readonly restricted: boolean
  
  /** Whether user is a guest account */
  readonly guest: boolean
  
  /** Whether user has active Plex Pass subscription */
  readonly subscription_active: boolean
  
  /** User's subscription plan (optional) */
  readonly subscription_plan: string | null
  
  /** When the authentication token expires (ISO string, optional) */
  readonly token_expires_at: string | null
}

/**
 * Response from user info endpoint (/auth/me).
 * Used for session management and authentication status.
 */
export interface UserInfoResponse {
  /** Authenticated Plex user information (null if not authenticated) */
  readonly user: PlexUser | null
  
  /** Whether the user is currently authenticated */
  readonly authenticated: boolean
  
  /** When the current session expires (ISO string, null if not authenticated) */
  readonly session_expires_at: string | null
}

// =============================================================================
// MEDIA SOURCE TYPES
// =============================================================================

/**
 * Online media source interface matching backend OnlineMediaSource Pydantic model.
 * Represents individual online media sources (e.g., Spotify, TIDAL, YouTube).
 */
export interface OnlineMediaSource {
  /** Unique identifier for the online media source */
  readonly identifier: string
  
  /** Display name of the online media source */
  readonly title: string
  
  /** Whether the source is enabled for scrobbling */
  readonly enabled: boolean
  
  /** Types of media that can be scrobbled */
  readonly scrobble_types: readonly string[]
}

/**
 * Response for media sources list endpoint.
 * Includes pagination metadata for large lists.
 */
export interface MediaSourceListResponse {
  /** Array of online media sources */
  readonly data: readonly OnlineMediaSource[]
  
  /** Pagination metadata */
  readonly meta: PaginationMeta
}

/**
 * Request payload for toggling individual media sources.
 */
export interface IndividualSourceToggleRequest {
  /** Whether to enable or disable the source */
  readonly enabled: boolean
}

/**
 * Response from bulk disable operation.
 */
export interface BulkDisableResponse {
  /** Whether the bulk operation was successful */
  readonly success: boolean
  
  /** Number of sources that were disabled */
  readonly disabled_count: number
  
  /** Array of error messages for failed operations */
  readonly errors: readonly string[]
  
  /** Unique identifier for the operation */
  readonly operation_id: string
  
  /** When the operation completed (ISO string) */
  readonly completed_at: string
}

// =============================================================================
// AUTHENTICATION TYPES
// =============================================================================

/**
 * Response from OAuth callback endpoint.
 * Contains authentication token and user information.
 */
export interface OAuthCallbackResponse {
  /** Plex authentication token */
  readonly access_token: string
  
  /** Token type (always Bearer for OAuth 2.0) */
  readonly token_type: 'Bearer'
  
  /** User information from Plex account */
  readonly user: PlexUser
  
  /** Token expiration time in seconds */
  readonly expires_in: number
}

/**
 * Response from OAuth initiation endpoint.
 * Contains OAuth flow initialization data.
 */
export interface OAuthInitiationResponse {
  /** OAuth authorization URL for user redirection */
  readonly auth_url: string
  
  /** OAuth state parameter for security */
  readonly state: string
  
  /** OAuth code verifier for PKCE flow */
  readonly code_verifier: string
  
  /** How long the auth flow is valid (seconds) */
  readonly expires_in: number
}

/**
 * Response from token validation endpoint.
 * Used to verify existing tokens.
 */
export interface TokenValidationResponse {
  /** Whether the token is valid */
  readonly valid: boolean
  
  /** User information if token is valid */
  readonly user: PlexUser | null
  
  /** Whether the token is expired */
  readonly expired: boolean
  
  /** Error message if token is invalid */
  readonly error: string | null
}

/**
 * Frontend authentication state interface.
 * Used by authentication context and hooks.
 */
export interface AuthState {
  /** Whether user is currently authenticated */
  readonly isAuthenticated: boolean
  
  /** Current authenticated user (null if not authenticated) */
  readonly user: PlexUser | null
  
  /** Current authentication token (null if not authenticated) */
  readonly token: string | null
  
  /** Whether authentication operation is in progress */
  readonly isLoading: boolean
  
  /** Current authentication error (null if no error) */
  readonly error: string | null
}

// =============================================================================
// ERROR TYPES
// =============================================================================

/**
 * Flexible error details type for various debugging information.
 * Can contain different types of values based on error context.
 */
export type ErrorDetails = Record<string, string | number | readonly string[] | boolean>

/**
 * Standardized API error structure.
 * Used for consistent error handling across the application.
 */
export interface ApiError {
  /** Error code for programmatic handling */
  readonly code: string
  
  /** Human-readable error message */
  readonly message: string
  
  /** Additional error details (optional) */
  readonly details: ErrorDetails | null
  
  /** When the error occurred (ISO string) */
  readonly timestamp: string
  
  /** Request ID for tracing (optional) */
  readonly request_id?: string
}

/**
 * API error response wrapper.
 * Standard format for all API error responses.
 */
export interface ApiErrorResponse {
  /** Error information */
  readonly error: ApiError
  
  /** Always false for error responses */
  readonly success: false
}

// =============================================================================
// COMMON API TYPES
// =============================================================================

/**
 * Pagination metadata for paginated responses.
 */
export interface PaginationMeta {
  /** Total number of items available */
  readonly total: number
  
  /** Current page number (1-based) */
  readonly page: number
  
  /** Number of items per page */
  readonly per_page: number
  
  /** Whether there are more pages available */
  readonly has_more: boolean
}

/**
 * Generic API response wrapper.
 * Provides consistent structure for all API responses.
 */
export type ApiResponse<T> = {
  /** Response data (null on error) */
  readonly data: T
  
  /** Whether the request was successful */
  readonly success: true
  
  /** Pagination metadata (optional) */
  readonly meta?: PaginationMeta
} | {
  /** Response data (null on error) */
  readonly data: null
  
  /** Whether the request was successful */
  readonly success: false
  
  /** Error information */
  readonly error: ApiError
}

// =============================================================================
// UTILITY TYPES
// =============================================================================

/**
 * HTTP method types for API requests.
 */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'

/**
 * API endpoint paths for type-safe routing.
 */
export type ApiEndpoint = 
  | '/api/media-sources'
  | '/api/media-sources/disable-all'
  | `/api/media-sources/${string}`
  | '/auth/login'
  | '/auth/callback'
  | '/auth/logout'
  | '/auth/me'
  | '/auth/refresh'

/**
 * Request configuration for API calls.
 */
export interface ApiRequestConfig {
  /** HTTP method */
  readonly method: HttpMethod
  
  /** Request headers */
  readonly headers?: Record<string, string>
  
  /** Request body (for POST/PUT/PATCH requests) */
  readonly body?: unknown
  
  /** Request timeout in milliseconds */
  readonly timeout?: number
  
  /** Whether to include authentication token */
  readonly requiresAuth?: boolean
}

/**
 * API client response type.
 */
export interface ApiClientResponse<T> {
  /** Response data */
  readonly data: T
  
  /** HTTP status code */
  readonly status: number
  
  /** Response headers */
  readonly headers: Record<string, string>
  
  /** Whether the request was successful (2xx status) */
  readonly ok: boolean
}

// =============================================================================
// COMPONENT PROP TYPES
// =============================================================================

/**
 * Common component props for loading states.
 */
export interface LoadingProps {
  /** Whether the component is in loading state */
  readonly isLoading: boolean
  
  /** Loading message to display */
  readonly loadingMessage?: string
  
  /** Size of loading indicator */
  readonly size?: 'sm' | 'md' | 'lg'
}

/**
 * Common component props for error states.
 */
export interface ErrorProps {
  /** Error message to display */
  readonly error: string | null
  
  /** Callback to retry the failed operation */
  readonly onRetry?: () => void
  
  /** Whether to show a retry button */
  readonly showRetry?: boolean
}

/**
 * Common component props for form validation.
 */
export interface ValidationProps {
  /** Whether the field/form is valid */
  readonly isValid: boolean
  
  /** Validation error messages */
  readonly errors: readonly string[]
  
  /** Whether validation is in progress */
  readonly isValidating?: boolean
}

// =============================================================================
// TYPE GUARDS
// =============================================================================

/**
 * Type guard to check if a response is an error response.
 */
export function isApiErrorResponse(response: unknown): response is ApiErrorResponse {
  return (
    typeof response === 'object' &&
    response !== null &&
    'error' in response &&
    'success' in response &&
    (response as ApiErrorResponse).success === false
  )
}

/**
 * Type guard to check if a user is authenticated.
 */
export function isAuthenticated(authState: AuthState): authState is AuthState & {
  readonly user: PlexUser
  readonly token: string
} {
  return authState.isAuthenticated && authState.user !== null && authState.token !== null
}

/**
 * Type guard to check if an API response is successful.
 */
export function isSuccessfulApiResponse<T>(
  response: ApiResponse<T>
): response is ApiResponse<T> & { readonly success: true } {
  return response.success === true
}

// =============================================================================
// CONSTANTS
// =============================================================================

/**
 * Known media source identifiers.
 */
export const MEDIA_SOURCE_IDENTIFIERS = [
  'spotify',
  'tidal',
  'youtube', 
  'lastfm',
  'musicbrainz',
  'deezer',
  'soundcloud'
] as const

/**
 * Known scrobble types.
 */
export const SCROBBLE_TYPES = [
  'track',
  'album', 
  'artist',
  'playlist'
] as const

/**
 * HTTP status codes used in the application.
 */
export const HTTP_STATUS_CODES = {
  OK: 200,
  CREATED: 201,
  NO_CONTENT: 204,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  UNPROCESSABLE_ENTITY: 422,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER_ERROR: 500,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503,
  GATEWAY_TIMEOUT: 504
} as const

/**
 * Error codes used throughout the application.
 */
export const ERROR_CODES = {
  AUTHENTICATION_FAILED: 'AUTHENTICATION_FAILED',
  AUTHORIZATION_REQUIRED: 'AUTHORIZATION_REQUIRED',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  INVALID_REQUEST: 'INVALID_REQUEST',
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  RESOURCE_NOT_FOUND: 'RESOURCE_NOT_FOUND',
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
  PLEX_API_ERROR: 'PLEX_API_ERROR',
  NETWORK_ERROR: 'NETWORK_ERROR',
  INTERNAL_ERROR: 'INTERNAL_ERROR'
} as const 