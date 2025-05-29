/**
 * Tests for the API client service.
 * 
 * Tests HTTP client with authentication, request/response transformation,
 * error handling, and retry mechanisms following TDD methodology.
 */

import { describe, test, expect, beforeEach, afterEach, vi, type MockedFunction } from 'vitest'
import type {
  PlexUser,
  OnlineMediaSource,
  MediaSourceListResponse,
  IndividualSourceToggleRequest,
  BulkDisableResponse,
  OAuthInitiationResponse,
  OAuthCallbackResponse,
  UserInfoResponse,
  ApiResponse,
  ApiError,
  ApiClientResponse,
} from '../../types'

// Mock global fetch
const mockFetch = vi.fn() as MockedFunction<typeof fetch>
global.fetch = mockFetch

// Mock localStorage
const mockLocalStorage = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
} as const

Object.defineProperty(window, 'localStorage', {
  value: mockLocalStorage,
})

// We'll import the API client after setting up mocks
let apiClient: any

describe('API Client', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Reset fetch mock
    mockFetch.mockClear()
    // Reset localStorage mock
    mockLocalStorage.getItem.mockClear()
    mockLocalStorage.setItem.mockClear()
    mockLocalStorage.removeItem.mockClear()
    
    // Import API client for each test (will be implemented)
    return import('../api').then((module) => {
      apiClient = module.default
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('HTTP Client with Authentication', () => {
    test('should inject authentication token automatically when available', async () => {
      // Arrange
      const mockToken = 'test-auth-token-123'
      mockLocalStorage.getItem.mockReturnValue(mockToken)
      
      const mockResponse = {
        ok: true,
        status: 200,
        headers: new Headers({ 'Content-Type': 'application/json' }),
        json: vi.fn().mockResolvedValue({ data: [], success: true }),
      } as const
      
      mockFetch.mockResolvedValue(mockResponse as any)

      // Act
      await apiClient.getMediaSources()

      // Assert
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/media-sources'),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': `Bearer ${mockToken}`,
            'Content-Type': 'application/json',
          }),
        })
      )
    })

    test('should make requests without authentication when token is not available', async () => {
      // Arrange
      mockLocalStorage.getItem.mockReturnValue(null)
      
      const mockResponse = {
        ok: true,
        status: 200,
        headers: new Headers({ 'Content-Type': 'application/json' }),
        json: vi.fn().mockResolvedValue({ auth_url: 'https://app.plex.tv/auth', state: 'state123' }),
      } as const
      
      mockFetch.mockResolvedValue(mockResponse as any)

      // Act
      await apiClient.initiateOAuth()

      // Assert
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/auth/login'),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
        })
      )
      
      // Should not include Authorization header
      const [, options] = mockFetch.mock.calls[0] as [string, RequestInit]
      expect(options.headers).not.toHaveProperty('Authorization')
    })

    test('should transform request and response data properly', async () => {
      // Arrange
      const mockToken = 'test-token'
      mockLocalStorage.getItem.mockReturnValue(mockToken)
      
      const mockResponseData: MediaSourceListResponse = {
        data: [
          {
            identifier: 'spotify',
            title: 'Spotify',
            enabled: true,
            scrobble_types: ['music'],
          },
        ],
        meta: {
          total: 1,
          page: 1,
          per_page: 10,
          has_more: false,
        },
      }
      
      const mockResponse = {
        ok: true,
        status: 200,
        headers: new Headers({ 'Content-Type': 'application/json' }),
        json: vi.fn().mockResolvedValue({ data: mockResponseData, success: true }),
      } as const
      
      mockFetch.mockResolvedValue(mockResponse as any)

      // Act
      const response = await apiClient.getMediaSources()

      // Assert
      expect(response.data).toEqual(mockResponseData)
      expect(response.status).toBe(200)
      expect(response.ok).toBe(true)
    })

    test('should handle authentication token expiration', async () => {
      // Arrange
      const mockToken = 'expired-token'
      mockLocalStorage.getItem.mockReturnValue(mockToken)
      
      const mockErrorResponse = {
        ok: false,
        status: 401,
        headers: new Headers({ 'Content-Type': 'application/json' }),
        json: vi.fn().mockResolvedValue({
          error: {
            code: 'TOKEN_EXPIRED',
            message: 'Authentication token has expired',
            timestamp: new Date().toISOString(),
          },
          success: false,
        }),
      } as const
      
      mockFetch.mockResolvedValue(mockErrorResponse as any)

      // Act & Assert
      await expect(apiClient.getMediaSources()).rejects.toThrow('Authentication token has expired')
      
      // Should remove expired token from storage
      expect(mockLocalStorage.removeItem).toHaveBeenCalledWith('auth_token')
    })
  })

  describe('Error Handling', () => {
    test('should handle network errors with proper error transformation', async () => {
      // Arrange
      const networkError = new Error('Network connection failed')
      mockFetch.mockRejectedValue(networkError)

      // Act & Assert
      await expect(apiClient.getMediaSources()).rejects.toThrow('Network connection failed')
    })

    test('should handle API errors with structured error response', async () => {
      // Arrange
      const mockToken = 'test-token'
      mockLocalStorage.getItem.mockReturnValue(mockToken)
      
      const mockErrorResponse = {
        ok: false,
        status: 400,
        headers: new Headers({ 'Content-Type': 'application/json' }),
        json: vi.fn().mockResolvedValue({
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid request data',
            details: { field: 'enabled', message: 'Required field' },
            timestamp: new Date().toISOString(),
          },
          success: false,
        }),
      } as const
      
      mockFetch.mockResolvedValue(mockErrorResponse as any)

      // Act & Assert
      await expect(apiClient.getMediaSources()).rejects.toThrow('Invalid request data')
    })

    test('should handle malformed JSON responses gracefully', async () => {
      // Arrange
      const mockToken = 'test-token'
      mockLocalStorage.getItem.mockReturnValue(mockToken)
      
      const mockResponse = {
        ok: true,
        status: 200,
        headers: new Headers({ 'Content-Type': 'application/json' }),
        json: vi.fn().mockRejectedValue(new Error('Invalid JSON')),
      } as const
      
      mockFetch.mockResolvedValue(mockResponse as any)

      // Act & Assert
      await expect(apiClient.getMediaSources()).rejects.toThrow('Failed to parse response')
    })
  })

  describe('Retry Mechanism with Exponential Backoff', () => {
    test('should retry requests on network failure with exponential backoff', async () => {
      // Arrange
      mockLocalStorage.getItem.mockReturnValue('test-token')
      
      // First two calls fail, third succeeds
      mockFetch
        .mockRejectedValueOnce(new Error('Network error'))
        .mockRejectedValueOnce(new Error('Network error'))
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          headers: new Headers({ 'Content-Type': 'application/json' }),
          json: vi.fn().mockResolvedValue({ data: [], success: true }),
        } as any)

      // Act
      const response = await apiClient.getMediaSources()

      // Assert
      expect(mockFetch).toHaveBeenCalledTimes(3)
      expect(response.ok).toBe(true)
    })

    test('should not retry on 4xx client errors', async () => {
      // Arrange
      mockLocalStorage.getItem.mockReturnValue('test-token')
      
      const mockErrorResponse = {
        ok: false,
        status: 400,
        headers: new Headers({ 'Content-Type': 'application/json' }),
        json: vi.fn().mockResolvedValue({
          error: {
            code: 'BAD_REQUEST',
            message: 'Bad request',
            timestamp: new Date().toISOString(),
          },
          success: false,
        }),
      } as const
      
      mockFetch.mockResolvedValue(mockErrorResponse as any)

      // Act & Assert
      await expect(apiClient.getMediaSources()).rejects.toThrow('Bad request')
      
      // Should only be called once (no retry for 4xx errors)
      expect(mockFetch).toHaveBeenCalledTimes(1)
    })

    test('should retry on 5xx server errors', async () => {
      // Arrange
      mockLocalStorage.getItem.mockReturnValue('test-token')
      
      // First call returns 500, second succeeds
      mockFetch
        .mockResolvedValueOnce({
          ok: false,
          status: 500,
          headers: new Headers({ 'Content-Type': 'application/json' }),
          json: vi.fn().mockResolvedValue({
            error: {
              code: 'INTERNAL_ERROR',
              message: 'Internal server error',
              timestamp: new Date().toISOString(),
            },
            success: false,
          }),
        } as any)
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          headers: new Headers({ 'Content-Type': 'application/json' }),
          json: vi.fn().mockResolvedValue({ data: [], success: true }),
        } as any)

      // Act
      const response = await apiClient.getMediaSources()

      // Assert
      expect(mockFetch).toHaveBeenCalledTimes(2)
      expect(response.ok).toBe(true)
    })

    test('should give up after maximum retry attempts', async () => {
      // Arrange
      mockLocalStorage.getItem.mockReturnValue('test-token')
      
      // Always fail with network error
      mockFetch.mockRejectedValue(new Error('Persistent network error'))

      // Act & Assert
      await expect(apiClient.getMediaSources()).rejects.toThrow('Persistent network error')
      
      // Should try maximum number of times (initial + 3 retries = 4 total)
      expect(mockFetch).toHaveBeenCalledTimes(4)
    })
  })

  describe('API Endpoint Methods', () => {
    beforeEach(() => {
      mockLocalStorage.getItem.mockReturnValue('test-token')
    })

    describe('Authentication API Methods', () => {
      test('should initiate OAuth flow correctly', async () => {
        // Arrange
        const mockResponse: OAuthInitiationResponse = {
          auth_url: 'https://app.plex.tv/auth/oauth',
          state: 'random-state-string',
          code_verifier: 'code-verifier-string',
          expires_in: 600,
        }
        
        mockFetch.mockResolvedValue({
          ok: true,
          status: 200,
          headers: new Headers({ 'Content-Type': 'application/json' }),
          json: vi.fn().mockResolvedValue({ data: mockResponse, success: true }),
        } as any)

        // Act
        const response = await apiClient.initiateOAuth()

        // Assert
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('/auth/login'),
          expect.objectContaining({
            method: 'POST',
            headers: expect.objectContaining({
              'Content-Type': 'application/json',
            }),
          })
        )
        expect(response.data).toEqual(mockResponse)
      })

      test('should handle OAuth callback correctly', async () => {
        // Arrange
        const callbackData = {
          code: 'auth-code-123',
          state: 'state-parameter',
        }
        
        const mockUser: PlexUser = {
          id: 12345,
          uuid: 'user-uuid-string',
          username: 'testuser',
          email: 'test@example.com',
          authentication_token: 'new-auth-token',
          thumb: 'https://plex.tv/avatar.png',
          confirmed: true,
          restricted: false,
          guest: false,
          subscription_active: true,
          subscription_plan: 'Plex Pass',
          token_expires_at: null,
        }
        
        const mockResponse: OAuthCallbackResponse = {
          access_token: 'new-auth-token',
          token_type: 'Bearer',
          user: mockUser,
          expires_in: 3600,
        }
        
        mockFetch.mockResolvedValue({
          ok: true,
          status: 200,
          headers: new Headers({ 'Content-Type': 'application/json' }),
          json: vi.fn().mockResolvedValue({ data: mockResponse, success: true }),
        } as any)

        // Act
        const response = await apiClient.handleOAuthCallback(callbackData)

        // Assert
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('/auth/callback'),
          expect.objectContaining({
            method: 'POST',
            headers: expect.objectContaining({
              'Content-Type': 'application/json',
            }),
            body: JSON.stringify(callbackData),
          })
        )
        expect(response.data).toEqual(mockResponse)
      })

      test('should handle logout correctly', async () => {
        // Arrange
        mockFetch.mockResolvedValue({
          ok: true,
          status: 200,
          headers: new Headers({ 'Content-Type': 'application/json' }),
          json: vi.fn().mockResolvedValue({ success: true }),
        } as any)

        // Act
        const response = await apiClient.logout()

        // Assert
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('/auth/logout'),
          expect.objectContaining({
            method: 'POST',
            headers: expect.objectContaining({
              'Authorization': 'Bearer test-token',
              'Content-Type': 'application/json',
            }),
          })
        )
        expect(response.ok).toBe(true)
      })

      test('should get user info correctly', async () => {
        // Arrange
        const mockUser: PlexUser = {
          id: 12345,
          uuid: 'user-uuid',
          username: 'testuser',
          email: 'test@example.com',
          authentication_token: 'test-token',
          thumb: null,
          confirmed: true,
          restricted: false,
          guest: false,
          subscription_active: false,
          subscription_plan: null,
          token_expires_at: null,
        }
        
        const mockResponse: UserInfoResponse = {
          user: mockUser,
          authenticated: true,
          session_expires_at: new Date(Date.now() + 3600000).toISOString(),
        }
        
        mockFetch.mockResolvedValue({
          ok: true,
          status: 200,
          headers: new Headers({ 'Content-Type': 'application/json' }),
          json: vi.fn().mockResolvedValue({ data: mockResponse, success: true }),
        } as any)

        // Act
        const response = await apiClient.getUserInfo()

        // Assert
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('/auth/me'),
          expect.objectContaining({
            method: 'GET',
            headers: expect.objectContaining({
              'Authorization': 'Bearer test-token',
              'Content-Type': 'application/json',
            }),
          })
        )
        expect(response.data).toEqual(mockResponse)
      })
    })

    describe('Media Sources API Methods', () => {
      test('should get media sources list correctly', async () => {
        // Arrange
        const mockSources: OnlineMediaSource[] = [
          {
            identifier: 'spotify',
            title: 'Spotify',
            enabled: true,
            scrobble_types: ['music'],
          },
          {
            identifier: 'tidal',
            title: 'TIDAL',
            enabled: false,
            scrobble_types: ['music'],
          },
        ]
        
        const mockResponse: MediaSourceListResponse = {
          data: mockSources,
          meta: {
            total: 2,
            page: 1,
            per_page: 10,
            has_more: false,
          },
        }
        
        mockFetch.mockResolvedValue({
          ok: true,
          status: 200,
          headers: new Headers({ 'Content-Type': 'application/json' }),
          json: vi.fn().mockResolvedValue({ data: mockResponse, success: true }),
        } as any)

        // Act
        const response = await apiClient.getMediaSources()

        // Assert
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('/api/media-sources'),
          expect.objectContaining({
            method: 'GET',
            headers: expect.objectContaining({
              'Authorization': 'Bearer test-token',
              'Content-Type': 'application/json',
            }),
          })
        )
        expect(response.data).toEqual(mockResponse)
      })

      test('should toggle individual media source correctly', async () => {
        // Arrange
        const sourceId = 'spotify'
        const toggleRequest: IndividualSourceToggleRequest = { enabled: false }
        
        const mockSource: OnlineMediaSource = {
          identifier: sourceId,
          title: 'Spotify',
          enabled: false,
          scrobble_types: ['music'],
        }
        
        mockFetch.mockResolvedValue({
          ok: true,
          status: 200,
          headers: new Headers({ 'Content-Type': 'application/json' }),
          json: vi.fn().mockResolvedValue({ data: mockSource, success: true }),
        } as any)

        // Act
        const response = await apiClient.toggleMediaSource(sourceId, toggleRequest)

        // Assert
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining(`/api/media-sources/${sourceId}`),
          expect.objectContaining({
            method: 'PATCH',
            headers: expect.objectContaining({
              'Authorization': 'Bearer test-token',
              'Content-Type': 'application/json',
            }),
            body: JSON.stringify(toggleRequest),
          })
        )
        expect(response.data).toEqual(mockSource)
      })

      test('should bulk disable all sources correctly', async () => {
        // Arrange
        const mockResponse: BulkDisableResponse = {
          success: true,
          disabled_count: 5,
          errors: [],
          operation_id: 'bulk-op-123',
          completed_at: new Date().toISOString(),
        }
        
        mockFetch.mockResolvedValue({
          ok: true,
          status: 200,
          headers: new Headers({ 'Content-Type': 'application/json' }),
          json: vi.fn().mockResolvedValue({ data: mockResponse, success: true }),
        } as any)

        // Act
        const response = await apiClient.bulkDisableAllSources()

        // Assert
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('/api/media-sources/disable-all'),
          expect.objectContaining({
            method: 'POST',
            headers: expect.objectContaining({
              'Authorization': 'Bearer test-token',
              'Content-Type': 'application/json',
            }),
          })
        )
        expect(response.data).toEqual(mockResponse)
      })
    })

    describe('Type Safety', () => {
      test('should ensure request data matches expected types', async () => {
        // Arrange
        const sourceId = 'spotify'
        const invalidRequest = { enabled: 'not-boolean' } as any // Invalid type
        
        // Act & Assert
        await expect(
          apiClient.toggleMediaSource(sourceId, invalidRequest)
        ).rejects.toThrow(/type/i)
      })

      test('should validate response data types', async () => {
        // Arrange
        const invalidResponse = {
          ok: true,
          status: 200,
          headers: new Headers({ 'Content-Type': 'application/json' }),
          json: vi.fn().mockResolvedValue({
            data: { invalid: 'structure' }, // Doesn't match expected type
            success: true,
          }),
        } as const
        
        mockFetch.mockResolvedValue(invalidResponse as any)

        // Act & Assert
        await expect(apiClient.getMediaSources()).rejects.toThrow(/validation/i)
      })
    })
  })
}) 