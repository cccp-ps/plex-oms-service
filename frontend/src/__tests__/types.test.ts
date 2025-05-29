/**
 * TypeScript interface tests for API integration.
 * 
 * Tests that TypeScript interfaces match the backend Pydantic schema
 * for API response validation and type safety.
 */

import { describe, it, expect, test } from 'vitest'
import type {
  // User-related types
  PlexUser,
  UserInfoResponse,
  OAuthCallbackResponse,
  OAuthInitiationResponse,
  
  // Media source types
  OnlineMediaSource,
  MediaSourceListResponse,
  BulkDisableResponse,
  IndividualSourceToggleRequest,
  
  // Authentication types
  AuthState,
  TokenValidationResponse,
  
  // Error types
  ApiError,
  ApiErrorResponse,
  ErrorDetails,
  
  // Common API types
  ApiResponse,
  PaginationMeta
} from '../types'

describe('User Interface Types', () => {
  it('should match backend PlexUser schema with proper field types', () => {
    // Test case: User interface matches backend schema
    const validUser: PlexUser = {
      id: 12345,
      uuid: 'test-uuid-12345',
      username: 'testuser',
      email: 'test@example.com',
      authentication_token: 'test-token-abcdef123456',
      thumb: 'https://plex.tv/users/test/avatar.jpg',
      confirmed: true,
      restricted: false,
      guest: false,
      subscription_active: true,
      subscription_plan: 'plexpass',
      token_expires_at: '2024-12-31T23:59:59Z'
    }

    // Verify required fields exist and have correct types
    expect(typeof validUser.id).toBe('number')
    expect(typeof validUser.uuid).toBe('string')
    expect(typeof validUser.username).toBe('string')
    expect(typeof validUser.email).toBe('string')
    expect(typeof validUser.authentication_token).toBe('string')
    
    // Verify optional fields can be null/undefined
    expect(typeof validUser.thumb === 'string' || validUser.thumb === null).toBe(true)
    expect(typeof validUser.subscription_plan === 'string' || validUser.subscription_plan === null).toBe(true)
    expect(typeof validUser.token_expires_at === 'string' || validUser.token_expires_at === null).toBe(true)
    
    // Verify boolean fields
    expect(typeof validUser.confirmed).toBe('boolean')
    expect(typeof validUser.restricted).toBe('boolean')
    expect(typeof validUser.guest).toBe('boolean')
    expect(typeof validUser.subscription_active).toBe('boolean')
  })

  it('should validate UserInfoResponse interface structure', () => {
    // Test valid authenticated response
    const authenticatedResponse: UserInfoResponse = {
      user: {
        id: 12345,
        uuid: 'test-uuid',
        username: 'testuser',
        email: 'test@example.com',
        authentication_token: 'token123',
        thumb: null,
        confirmed: true,
        restricted: false,
        guest: false,
        subscription_active: false,
        subscription_plan: null,
        token_expires_at: null
      },
      authenticated: true,
      session_expires_at: '2024-12-31T23:59:59Z'
    }

    expect(typeof authenticatedResponse.authenticated).toBe('boolean')
    expect(authenticatedResponse.user).toBeDefined()
    expect(typeof authenticatedResponse.session_expires_at === 'string' || 
           authenticatedResponse.session_expires_at === null).toBe(true)

    // Test unauthenticated response
    const unauthenticatedResponse: UserInfoResponse = {
      user: null,
      authenticated: false,
      session_expires_at: null
    }

    expect(unauthenticatedResponse.authenticated).toBe(false)
    expect(unauthenticatedResponse.user).toBeNull()
    expect(unauthenticatedResponse.session_expires_at).toBeNull()
  })
})

describe('MediaSource Interface Types', () => {
  it('should match backend OnlineMediaSource schema with proper field types', () => {
    // Test case: MediaSource interface with proper field types
    const validMediaSource: OnlineMediaSource = {
      identifier: 'spotify',
      title: 'Spotify',
      enabled: true,
      scrobble_types: ['track']
    }

    // Verify required fields exist and have correct types
    expect(typeof validMediaSource.identifier).toBe('string')
    expect(typeof validMediaSource.title).toBe('string')
    expect(typeof validMediaSource.enabled).toBe('boolean')
    expect(Array.isArray(validMediaSource.scrobble_types)).toBe(true)
    expect(validMediaSource.scrobble_types.every(type => typeof type === 'string')).toBe(true)
  })

  it('should validate MediaSourceListResponse structure', () => {
    const mediaSourcesList: MediaSourceListResponse = {
      data: [
        {
          identifier: 'spotify',
          title: 'Spotify',
          enabled: true,
          scrobble_types: ['track']
        },
        {
          identifier: 'tidal',
          title: 'TIDAL',
          enabled: false,
          scrobble_types: ['track', 'album']
        }
      ],
      meta: {
        total: 2,
        page: 1,
        per_page: 10,
        has_more: false
      }
    }

    expect(Array.isArray(mediaSourcesList.data)).toBe(true)
    expect(mediaSourcesList.data.length).toBe(2)
    expect(typeof mediaSourcesList.meta.total).toBe('number')
    expect(typeof mediaSourcesList.meta.page).toBe('number')
    expect(typeof mediaSourcesList.meta.per_page).toBe('number')
    expect(typeof mediaSourcesList.meta.has_more).toBe('boolean')
  })

  it('should validate IndividualSourceToggleRequest structure', () => {
    const toggleRequest: IndividualSourceToggleRequest = {
      enabled: true
    }

    expect(typeof toggleRequest.enabled).toBe('boolean')
  })

  it('should validate BulkDisableResponse structure', () => {
    const bulkResponse: BulkDisableResponse = {
      success: true,
      disabled_count: 5,
      errors: [],
      operation_id: 'op-123456',
      completed_at: '2024-01-01T12:00:00Z'
    }

    expect(typeof bulkResponse.success).toBe('boolean')
    expect(typeof bulkResponse.disabled_count).toBe('number')
    expect(Array.isArray(bulkResponse.errors)).toBe(true)
    expect(typeof bulkResponse.operation_id).toBe('string')
    expect(typeof bulkResponse.completed_at).toBe('string')
  })
})

describe('Authentication Response Interfaces', () => {
  it('should validate OAuthCallbackResponse interface structure', () => {
    // Test case: Authentication response interfaces
    const callbackResponse: OAuthCallbackResponse = {
      access_token: 'plex-token-abcdef123456',
      token_type: 'Bearer',
      user: {
        id: 12345,
        uuid: 'test-uuid',
        username: 'testuser',
        email: 'test@example.com',
        authentication_token: 'token123',
        thumb: null,
        confirmed: true,
        restricted: false,
        guest: false,
        subscription_active: false,
        subscription_plan: null,
        token_expires_at: null
      },
      expires_in: 3600
    }

    expect(typeof callbackResponse.access_token).toBe('string')
    expect(callbackResponse.token_type).toBe('Bearer')
    expect(typeof callbackResponse.expires_in).toBe('number')
    expect(callbackResponse.user).toBeDefined()
  })

  it('should validate OAuthInitiationResponse structure', () => {
    const initiationResponse: OAuthInitiationResponse = {
      auth_url: 'https://app.plex.tv/auth#?context[device][product]=PlexOMSManager',
      state: 'random-state-string',
      code_verifier: 'code-verifier-123',
      expires_in: 1800
    }

    expect(typeof initiationResponse.auth_url).toBe('string')
    expect(typeof initiationResponse.state).toBe('string')
    expect(typeof initiationResponse.code_verifier).toBe('string')
    expect(typeof initiationResponse.expires_in).toBe('number')
  })

  it('should validate TokenValidationResponse structure', () => {
    const validTokenResponse: TokenValidationResponse = {
      valid: true,
      user: {
        id: 12345,
        uuid: 'test-uuid',
        username: 'testuser',
        email: 'test@example.com',
        authentication_token: 'token123',
        thumb: null,
        confirmed: true,
        restricted: false,
        guest: false,
        subscription_active: false,
        subscription_plan: null,
        token_expires_at: null
      },
      expired: false,
      error: null
    }

    expect(typeof validTokenResponse.valid).toBe('boolean')
    expect(validTokenResponse.user).toBeDefined()
    expect(typeof validTokenResponse.expired).toBe('boolean')
    expect(validTokenResponse.error).toBeNull()

    // Test invalid token response
    const invalidTokenResponse: TokenValidationResponse = {
      valid: false,
      user: null,
      expired: true,
      error: 'Token has expired'
    }

    expect(invalidTokenResponse.valid).toBe(false)
    expect(invalidTokenResponse.user).toBeNull()
    expect(typeof invalidTokenResponse.error).toBe('string')
  })

  it('should validate AuthState interface structure', () => {
    const authState: AuthState = {
      isAuthenticated: true,
      user: {
        id: 12345,
        uuid: 'test-uuid',
        username: 'testuser',
        email: 'test@example.com',
        authentication_token: 'token123',
        thumb: null,
        confirmed: true,
        restricted: false,
        guest: false,
        subscription_active: false,
        subscription_plan: null,
        token_expires_at: null
      },
      token: 'auth-token-123',
      isLoading: false,
      error: null
    }

    expect(typeof authState.isAuthenticated).toBe('boolean')
    expect(authState.user).toBeDefined()
    expect(typeof authState.token === 'string' || authState.token === null).toBe(true)
    expect(typeof authState.isLoading).toBe('boolean')
    expect(authState.error === null || typeof authState.error === 'string').toBe(true)
  })
})

describe('Error Response Interfaces', () => {
  it('should validate ApiError interface structure', () => {
    // Test case: Error response interfaces
    const apiError: ApiError = {
      code: 'AUTHENTICATION_FAILED',
      message: 'Authentication credentials required',
      details: {
        field: 'authorization_header',
        reason: 'missing_token',
        suggestion: 'Include Bearer token in Authorization header'
      },
      timestamp: '2024-01-01T12:00:00Z',
      request_id: 'req-123456'
    }

    expect(typeof apiError.code).toBe('string')
    expect(typeof apiError.message).toBe('string')
    expect(typeof apiError.details === 'object' || apiError.details === null).toBe(true)
    expect(typeof apiError.timestamp).toBe('string')
    expect(typeof apiError.request_id === 'string' || apiError.request_id === undefined).toBe(true)
  })

  it('should validate ApiErrorResponse structure', () => {
    const errorResponse: ApiErrorResponse = {
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Invalid request data',
        details: {
          field: 'enabled',
          value: 'invalid',
          expected: 'boolean'
        },
        timestamp: '2024-01-01T12:00:00Z',
        request_id: 'req-123456'
      },
      success: false
    }

    expect(errorResponse.success).toBe(false)
    expect(errorResponse.error).toBeDefined()
    expect(typeof errorResponse.error.code).toBe('string')
    expect(typeof errorResponse.error.message).toBe('string')
  })

  it('should validate ErrorDetails type flexibility', () => {
    // Test various ErrorDetails structures
    const simpleDetails: ErrorDetails = {
      field: 'username',
      reason: 'required'
    }

    const complexDetails: ErrorDetails = {
      field: 'media_sources',
      errors: ['Invalid source: spotify', 'Source not found: unknown'],
      count: 2,
      retryable: true
    }

    expect(typeof simpleDetails.field).toBe('string')
    expect(typeof simpleDetails.reason).toBe('string')
    
    expect(typeof complexDetails.field).toBe('string')
    expect(Array.isArray(complexDetails.errors)).toBe(true)
    expect(typeof complexDetails.count).toBe('number')
    expect(typeof complexDetails.retryable).toBe('boolean')
  })
})

describe('Common API Response Types', () => {
  it('should validate generic ApiResponse structure', () => {
    // Test successful response
    const successResponse: ApiResponse<OnlineMediaSource[]> = {
      data: [
        {
          identifier: 'spotify',
          title: 'Spotify',
          enabled: true,
          scrobble_types: ['track']
        }
      ],
      success: true,
      meta: {
        total: 1,
        page: 1,
        per_page: 10,
        has_more: false
      }
    }

    expect(successResponse.success).toBe(true)
    expect(Array.isArray(successResponse.data)).toBe(true)
    expect(successResponse.meta).toBeDefined()

    // Test error response
    const errorResponse: ApiResponse<null> = {
      data: null,
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Something went wrong',
        details: null,
        timestamp: '2024-01-01T12:00:00Z'
      }
    }

    expect(errorResponse.success).toBe(false)
    expect(errorResponse.data).toBeNull()
    expect(errorResponse.error).toBeDefined()
  })

  it('should validate PaginationMeta structure', () => {
    const paginationMeta: PaginationMeta = {
      total: 100,
      page: 2,
      per_page: 20,
      has_more: true
    }

    expect(typeof paginationMeta.total).toBe('number')
    expect(typeof paginationMeta.page).toBe('number')
    expect(typeof paginationMeta.per_page).toBe('number')
    expect(typeof paginationMeta.has_more).toBe('boolean')
  })
})

describe('Type Guards and Validation', () => {
  it('should properly handle null and undefined values', () => {
    // Test nullable fields in PlexUser
    const userWithNulls: PlexUser = {
      id: 12345,
      uuid: 'test-uuid',
      username: 'testuser',
      email: 'test@example.com',
      authentication_token: 'token123',
      thumb: null,
      confirmed: true,
      restricted: false,
      guest: false,
      subscription_active: false,
      subscription_plan: null,
      token_expires_at: null
    }

    expect(userWithNulls.thumb).toBeNull()
    expect(userWithNulls.subscription_plan).toBeNull()
    expect(userWithNulls.token_expires_at).toBeNull()
  })

  it('should handle empty arrays and objects', () => {
    const emptyMediaSource: OnlineMediaSource = {
      identifier: 'test',
      title: 'Test Service',
      enabled: false,
      scrobble_types: []
    }

    expect(Array.isArray(emptyMediaSource.scrobble_types)).toBe(true)
    expect(emptyMediaSource.scrobble_types.length).toBe(0)
  })
}) 