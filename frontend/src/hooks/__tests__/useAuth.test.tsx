/**
 * Tests for useAuth hook - Authentication state management hook.
 *
 * Tests the authentication hook that provides a clean interface to authentication
 * functionality, OAuth flow handling, secure token storage, and automatic token refresh.
 *
 * Following TDD methodology with comprehensive test coverage.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import { useAuth } from '../useAuth'
import { AuthProvider } from '../../contexts/AuthContext'
import type { PlexUser, OAuthCallbackResponse } from '../../types'

// Mock the API client
vi.mock('../../services/api', () => ({
  apiClient: {
    initiateOAuth: vi.fn(),
    handleOAuthCallback: vi.fn(),
    getUserInfo: vi.fn(),
    logout: vi.fn(),
    refreshToken: vi.fn(),
  },
}))

// Get the mocked API client
const { apiClient: mockApiClient } = await import('../../services/api')

// Mock localStorage
const mockLocalStorage = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
}

Object.defineProperty(window, 'localStorage', {
  value: mockLocalStorage,
})

// Mock sessionStorage
const mockSessionStorage = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
}

Object.defineProperty(window, 'sessionStorage', {
  value: mockSessionStorage,
})

// Mock window.location
const mockLocation = {
  href: '',
  assign: vi.fn(),
  reload: vi.fn(),
}

Object.defineProperty(window, 'location', {
  value: mockLocation,
  writable: true,
})

// Test data
const mockUser: PlexUser = {
  id: 12345,
  uuid: 'test-uuid-12345',
  username: 'testuser',
  email: 'test@example.com',
  authentication_token: 'test-token-12345',
  thumb: 'https://plex.tv/users/test-avatar.png',
  confirmed: true,
  restricted: false,
  guest: false,
  subscription_active: true,
  subscription_plan: 'lifetime',
  token_expires_at: new Date(Date.now() + 3600000).toISOString(), // 1 hour from now
}

const mockToken = 'test-auth-token-12345'

describe('useAuth Hook', () => {
  beforeEach(() => {
    // Reset all mocks before each test
    vi.clearAllMocks()
    mockLocalStorage.getItem.mockReturnValue(null)
    mockSessionStorage.getItem.mockReturnValue(null)
    mockLocation.href = ''
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  describe('Authentication State and Methods', () => {
    it('should provide authentication state and methods', () => {
      // This test will fail until we implement the useAuth hook
      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      })

      // Should provide authentication state
      expect(result.current.isAuthenticated).toBeDefined()
      expect(result.current.user).toBeDefined()
      expect(result.current.token).toBeDefined()
      expect(result.current.isLoading).toBeDefined()
      expect(result.current.error).toBeDefined()

      // Should provide authentication methods
      expect(typeof result.current.login).toBe('function')
      expect(typeof result.current.logout).toBe('function')
      expect(typeof result.current.handleOAuthCallback).toBe('function')
      expect(typeof result.current.checkAuthStatus).toBe('function')
      expect(typeof result.current.clearError).toBe('function')
    })

    it('should initialize with unauthenticated state', () => {
      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      })

      expect(result.current.isAuthenticated).toBe(false)
      expect(result.current.user).toBe(null)
      expect(result.current.token).toBe(null)
      expect(result.current.error).toBe(null)
    })

    it('should provide type-safe authentication state', () => {
      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      })

      // Type assertions to ensure proper TypeScript types
      const authState = result.current
      expect(typeof authState.isAuthenticated).toBe('boolean')
      expect(authState.user === null || typeof authState.user === 'object').toBe(true)
      expect(authState.token === null || typeof authState.token === 'string').toBe(true)
      expect(typeof authState.isLoading).toBe('boolean')
      expect(authState.error === null || typeof authState.error === 'string').toBe(true)
    })
  })

  describe('OAuth Flow Initiation and Completion', () => {
    it('should handle OAuth flow initiation', async () => {
      // Mock OAuth initiation response
      mockApiClient.initiateOAuth.mockResolvedValue({
        data: {
          auth_url: 'https://plex.tv/oauth/authorize?code=123',
          state: 'test-state',
          code_verifier: 'test-verifier',
          expires_in: 3600,
        },
        ok: true,
        status: 200,
        headers: {},
      })

      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      })

      // Should start login process
      await act(async () => {
        await result.current.login()
      })

      // Should call OAuth initiation API
      expect(mockApiClient.initiateOAuth).toHaveBeenCalled()

      // Should store OAuth state and code verifier
      expect(mockSessionStorage.setItem).toHaveBeenCalledWith('oauth_state', 'test-state')
      expect(mockSessionStorage.setItem).toHaveBeenCalledWith('oauth_code_verifier', 'test-verifier')

      // Should redirect to OAuth URL
      expect(mockLocation.href).toBe('https://plex.tv/oauth/authorize?code=123')
    })

    it('should handle OAuth callback completion', async () => {
      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      })

      const mockOAuthData: OAuthCallbackResponse = {
        access_token: mockToken,
        token_type: 'Bearer',
        user: mockUser,
        expires_in: 3600,
      }

      // Handle OAuth callback
      act(() => {
        result.current.handleOAuthCallback(mockOAuthData)
      })

      await waitFor(() => {
        expect(result.current.isAuthenticated).toBe(true)
        expect(result.current.user).toEqual(mockUser)
        expect(result.current.token).toBe(mockToken)
      })

      // Should store token securely
      expect(mockLocalStorage.setItem).toHaveBeenCalledWith('plex_auth_token', mockToken)

      // Should clean up OAuth session data
      expect(mockSessionStorage.removeItem).toHaveBeenCalledWith('oauth_state')
      expect(mockSessionStorage.removeItem).toHaveBeenCalledWith('oauth_code_verifier')
    })

    it('should handle OAuth flow errors gracefully', async () => {
      // Mock OAuth initiation failure
      mockApiClient.initiateOAuth.mockRejectedValue(new Error('OAuth initiation failed'))

      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      })

      // Should handle login error
      await act(async () => {
        await result.current.login()
      })

      await waitFor(() => {
        expect(result.current.error).toBe('OAuth initiation failed')
        expect(result.current.isAuthenticated).toBe(false)
        expect(result.current.isLoading).toBe(false)
      })
    })
  })

  describe('Secure Token Storage', () => {
    it('should manage secure token storage', () => {
      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      })

      const mockOAuthData: OAuthCallbackResponse = {
        access_token: mockToken,
        token_type: 'Bearer',
        user: mockUser,
        expires_in: 3600,
      }

      // Handle OAuth callback
      act(() => {
        result.current.handleOAuthCallback(mockOAuthData)
      })

      // Should store token securely in localStorage
      expect(mockLocalStorage.setItem).toHaveBeenCalledWith('plex_auth_token', mockToken)
      expect(result.current.token).toBe(mockToken)
    })

    it('should retrieve stored token on initialization', async () => {
      // Mock stored token
      mockLocalStorage.getItem.mockReturnValue(mockToken)

      // Mock successful API response
      mockApiClient.getUserInfo.mockResolvedValue({
        data: {
          user: mockUser,
          authenticated: true,
          session_expires_at: mockUser.token_expires_at,
        },
        ok: true,
        status: 200,
        headers: {},
      })

      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      })

      // Should start with loading state
      expect(result.current.isLoading).toBe(true)

      await waitFor(() => {
        expect(result.current.isAuthenticated).toBe(true)
        expect(result.current.user).toEqual(mockUser)
        expect(result.current.token).toBe(mockToken)
        expect(result.current.isLoading).toBe(false)
      })
    })

    it('should clear token on logout', async () => {
      // Mock successful logout
      mockApiClient.logout.mockResolvedValue({
        data: { success: true },
        ok: true,
        status: 200,
        headers: {},
      })

      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      })

      // Set initial authenticated state
      const mockOAuthData: OAuthCallbackResponse = {
        access_token: mockToken,
        token_type: 'Bearer',
        user: mockUser,
        expires_in: 3600,
      }

      act(() => {
        result.current.handleOAuthCallback(mockOAuthData)
      })

      // Logout
      await act(async () => {
        await result.current.logout()
      })

      await waitFor(() => {
        expect(result.current.isAuthenticated).toBe(false)
        expect(result.current.user).toBe(null)
        expect(result.current.token).toBe(null)
      })

      // Should remove token from storage
      expect(mockLocalStorage.removeItem).toHaveBeenCalledWith('plex_auth_token')
    })
  })

  describe('Automatic Token Refresh', () => {
    it('should handle automatic token refresh', async () => {
      // Mock expired token scenario
      const expiredUser = {
        ...mockUser,
        token_expires_at: new Date(Date.now() - 1000).toISOString(), // Expired 1 second ago
      }

      // First call returns expired user info
      mockApiClient.getUserInfo.mockResolvedValueOnce({
        data: {
          user: expiredUser,
          authenticated: true,
          session_expires_at: expiredUser.token_expires_at,
        },
        ok: true,
        status: 200,
        headers: {},
      })

      // Mock successful token refresh
      const newToken = 'new-refreshed-token-12345'
      const refreshedUser = {
        ...mockUser,
        authentication_token: newToken,
        token_expires_at: new Date(Date.now() + 3600000).toISOString(), // 1 hour from now
      }

      mockApiClient.refreshToken.mockResolvedValue({
        data: {
          access_token: newToken,
          token_type: 'Bearer',
          user: refreshedUser,
          expires_in: 3600,
        },
        ok: true,
        status: 200,
        headers: {},
      })

      mockLocalStorage.getItem.mockReturnValue(mockToken)

      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      })

      // Trigger auth check
      await act(async () => {
        await result.current.checkAuthStatus()
      })

      await waitFor(() => {
        expect(result.current.isAuthenticated).toBe(true)
        expect(result.current.token).toBe(newToken)
        expect(result.current.user).toEqual(refreshedUser)
      })

      // Should call refresh token API
      expect(mockApiClient.refreshToken).toHaveBeenCalled()

      // Should store new token
      expect(mockLocalStorage.setItem).toHaveBeenCalledWith('plex_auth_token', newToken)
    })

    it('should handle token refresh failure', async () => {
      // Mock expired token scenario
      const expiredUser = {
        ...mockUser,
        token_expires_at: new Date(Date.now() - 1000).toISOString(), // Expired 1 second ago
      }

      mockApiClient.getUserInfo.mockResolvedValue({
        data: {
          user: expiredUser,
          authenticated: true,
          session_expires_at: expiredUser.token_expires_at,
        },
        ok: true,
        status: 200,
        headers: {},
      })

      // Mock failed token refresh
      mockApiClient.refreshToken.mockRejectedValue(new Error('Token refresh failed'))

      mockLocalStorage.getItem.mockReturnValue(mockToken)

      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      })

      // Trigger auth check
      await act(async () => {
        await result.current.checkAuthStatus()
      })

      await waitFor(() => {
        expect(result.current.isAuthenticated).toBe(false)
        expect(result.current.user).toBe(null)
        expect(result.current.token).toBe(null)
      })

      // Should remove invalid token
      expect(mockLocalStorage.removeItem).toHaveBeenCalledWith('plex_auth_token')
    })
  })

  describe('Error Handling', () => {
    it('should provide error clearing functionality', async () => {
      // Start with error state
      mockApiClient.getUserInfo.mockRejectedValueOnce(new Error('Test error'))

      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      })

      mockLocalStorage.getItem.mockReturnValue(mockToken)

      // Trigger auth check that will fail
      await act(async () => {
        await result.current.checkAuthStatus()
      })

      // Wait for error state
      await waitFor(() => {
        expect(result.current.error).toBe('Test error')
      })

      // Clear error
      act(() => {
        result.current.clearError()
      })

      expect(result.current.error).toBe(null)
    })

    it('should handle authentication errors gracefully', async () => {
      // Mock authentication error
      mockApiClient.getUserInfo.mockRejectedValue(new Error('Authentication failed'))

      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      })

      mockLocalStorage.getItem.mockReturnValue('invalid-token')

      // Trigger auth check
      await act(async () => {
        await result.current.checkAuthStatus()
      })

      await waitFor(() => {
        expect(result.current.error).toBe('Authentication failed')
        expect(result.current.isAuthenticated).toBe(false)
        expect(result.current.isLoading).toBe(false)
      })
    })
  })
})
