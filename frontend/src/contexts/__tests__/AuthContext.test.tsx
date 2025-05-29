/**
 * Tests for AuthContext module - Authentication state management.
 * 
 * Tests authentication state provider, login/logout flow, token management,
 * and error handling following TDD methodology.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, act, waitFor } from '@testing-library/react'
import { renderHook } from '@testing-library/react'
import { AuthProvider, useAuth } from '../AuthContext'
import type { PlexUser, AuthState } from '../../types'

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

// Mock window.location.href
const mockLocation = {
  href: '',
}

Object.defineProperty(window, 'location', {
  value: mockLocation,
  writable: true,
})

// Mock API service
vi.mock('../../services/api', () => ({
  apiClient: {
    getUserInfo: vi.fn(),
    initiateOAuth: vi.fn(),
    logout: vi.fn(),
    refreshToken: vi.fn(),
  },
}))

// Import the mocked apiClient
import { apiClient } from '../../services/api'
const mockApiClient = vi.mocked(apiClient)

// Test data
const mockUser: PlexUser = {
  id: 123,
  uuid: 'test-uuid-123',
  username: 'testuser',
  email: 'test@example.com',
  authentication_token: 'test-token-123',
  thumb: 'https://example.com/avatar.jpg',
  confirmed: true,
  restricted: false,
  guest: false,
  subscription_active: true,
  subscription_plan: 'Plex Pass',
  token_expires_at: new Date(Date.now() + 3600000).toISOString(), // 1 hour from now
} as const

const mockToken = 'mock-auth-token-123'

describe('AuthContext', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockLocalStorage.getItem.mockReturnValue(null)
    mockSessionStorage.getItem.mockReturnValue(null)
    mockLocation.href = ''
    
    // Set up default API responses
    mockApiClient.getUserInfo.mockResolvedValue({
      data: {
        user: null,
        authenticated: false,
        session_expires_at: null,
      },
      ok: true,
      status: 200,
      headers: {},
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('Authentication Context Provider', () => {
    it('should provide authentication state to child components', () => {
      // This test will fail until we implement the AuthProvider
      const TestComponent = () => {
        const auth = useAuth()
        return (
          <div>
            <span data-testid="auth-state">{auth.isAuthenticated ? 'authenticated' : 'not-authenticated'}</span>
            <span data-testid="user-name">{auth.user?.username || 'no-user'}</span>
            <span data-testid="loading-state">{auth.isLoading ? 'loading' : 'not-loading'}</span>
            <span data-testid="error-state">{auth.error || 'no-error'}</span>
          </div>
        )
      }

      render(
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      )

      expect(screen.getByTestId('auth-state')).toHaveTextContent('not-authenticated')
      expect(screen.getByTestId('user-name')).toHaveTextContent('no-user')
      expect(screen.getByTestId('loading-state')).toHaveTextContent('not-loading')
      expect(screen.getByTestId('error-state')).toHaveTextContent('no-error')
    })

    it('should initialize with stored token if available', async () => {
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

    it('should throw error when useAuth is used outside AuthProvider', () => {
      // Test that useAuth throws when used outside provider
      expect(() => {
        renderHook(() => useAuth())
      }).toThrow('useAuth must be used within an AuthProvider')
    })
  })

  describe('Login/Logout State Transitions', () => {
    it('should handle login state transitions', async () => {
      // Mock OAuth initiation
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

      // Initial state should not be authenticated
      expect(result.current.isAuthenticated).toBe(false)
      expect(result.current.user).toBe(null)
      expect(result.current.token).toBe(null)

      // Start login process
      await act(async () => {
        await result.current.login()
      })

      // Verify OAuth was initiated
      expect(mockApiClient.initiateOAuth).toHaveBeenCalled()
      
      // Should have stored OAuth state
      expect(mockSessionStorage.setItem).toHaveBeenCalledWith('oauth_state', 'test-state')
      expect(mockSessionStorage.setItem).toHaveBeenCalledWith('oauth_code_verifier', 'test-verifier')
      
      // Should have redirected to OAuth URL
      expect(mockLocation.href).toBe('https://plex.tv/oauth/authorize?code=123')
    })

    it('should handle logout state transitions', async () => {
      // Setup initial authenticated state
      mockLocalStorage.getItem.mockReturnValue(mockToken)
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

      mockApiClient.logout.mockResolvedValue({
        data: { success: true },
        ok: true,
        status: 200,
        headers: {},
      })

      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      })

      // Wait for initial authentication
      await waitFor(() => {
        expect(result.current.isAuthenticated).toBe(true)
      })

      // Perform logout
      await act(async () => {
        await result.current.logout()
      })

      await waitFor(() => {
        expect(result.current.isAuthenticated).toBe(false)
        expect(result.current.user).toBe(null)
        expect(result.current.token).toBe(null)
        expect(result.current.isLoading).toBe(false)
      })

      // Verify logout API was called and token was removed
      expect(mockApiClient.logout).toHaveBeenCalled()
      expect(mockLocalStorage.removeItem).toHaveBeenCalledWith('plex_auth_token')
    })

    it('should handle successful OAuth callback', async () => {
      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      })

      const mockOAuthData = {
        access_token: mockToken,
        token_type: 'Bearer' as const,
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

      // Verify token was stored
      expect(mockLocalStorage.setItem).toHaveBeenCalledWith('plex_auth_token', mockToken)
    })
  })

  describe('Authentication Token Storage', () => {
    it('should manage authentication token storage securely', () => {
      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      })

      const mockOAuthData = {
        access_token: mockToken,
        token_type: 'Bearer' as const,
        user: mockUser,
        expires_in: 3600,
      }

      // Handle OAuth callback
      act(() => {
        result.current.handleOAuthCallback(mockOAuthData)
      })

      // Verify token is stored securely
      expect(mockLocalStorage.setItem).toHaveBeenCalledWith('plex_auth_token', mockToken)
      expect(result.current.token).toBe(mockToken)
    })

    it('should clear token storage on logout', async () => {
      mockApiClient.logout.mockResolvedValue({
        data: { success: true },
        ok: true,
        status: 200,
        headers: {},
      })

      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      })

      // Setup authenticated state
      const mockOAuthData = {
        access_token: mockToken,
        token_type: 'Bearer' as const,
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
        expect(result.current.token).toBe(null)
      })

      // Verify token was removed from storage
      expect(mockLocalStorage.removeItem).toHaveBeenCalledWith('plex_auth_token')
    })

    it('should handle missing stored token gracefully', () => {
      // Mock no stored token
      mockLocalStorage.getItem.mockReturnValue(null)

      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      })

      expect(result.current.isAuthenticated).toBe(false)
      expect(result.current.token).toBe(null)
      expect(result.current.user).toBe(null)
    })
  })

  describe('Authentication Errors and Token Expiration', () => {
    it('should handle authentication errors properly', async () => {
      // Mock API error
      mockApiClient.getUserInfo.mockRejectedValue(new Error('Authentication failed'))

      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      })

      // Try to authenticate with invalid token
      mockLocalStorage.getItem.mockReturnValue('invalid-token')

      // Manually trigger checkAuthStatus to see the error
      await act(async () => {
        await result.current.checkAuthStatus()
      })

      await waitFor(() => {
        expect(result.current.error).toBe('Authentication failed')
        expect(result.current.isAuthenticated).toBe(false)
        expect(result.current.isLoading).toBe(false)
      })
    })

    it('should handle token expiration and automatic refresh', async () => {
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

      // Mock successful token refresh
      mockApiClient.refreshToken.mockResolvedValue({
        data: {
          access_token: 'new-token-123',
          token_type: 'Bearer' as const,
          user: mockUser,
          expires_in: 3600,
        },
        ok: true,
        status: 200,
        headers: {},
      })

      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      })

      mockLocalStorage.getItem.mockReturnValue(mockToken)

      // Wait for the authentication check to complete and token refresh
      await waitFor(() => {
        expect(result.current.isAuthenticated).toBe(true)
        expect(result.current.token).toBe('new-token-123')
      }, { timeout: 3000 })

      // Verify token refresh was called and new token was stored
      expect(mockApiClient.refreshToken).toHaveBeenCalled()
      expect(mockLocalStorage.setItem).toHaveBeenCalledWith('plex_auth_token', 'new-token-123')
    })

    it('should handle token refresh failure', async () => {
      // Mock expired token
      const expiredUser = {
        ...mockUser,
        token_expires_at: new Date(Date.now() - 1000).toISOString(),
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

      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      })

      mockLocalStorage.getItem.mockReturnValue(mockToken)

      await waitFor(() => {
        expect(result.current.isAuthenticated).toBe(false)
        expect(result.current.token).toBe(null)
      }, { timeout: 3000 })

      // Verify token was removed on refresh failure
      expect(mockLocalStorage.removeItem).toHaveBeenCalledWith('plex_auth_token')
    })

    it('should clear error state on successful operations', async () => {
      // Start with error state
      mockApiClient.getUserInfo.mockRejectedValueOnce(new Error('Initial error'))

      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      })

      // Trigger initial auth check that will fail
      await act(async () => {
        await result.current.checkAuthStatus()
      })

      await waitFor(() => {
        expect(result.current.error).toBe('Initial error')
      })

      // Mock successful operation
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

      // Retry authentication
      await act(async () => {
        await result.current.checkAuthStatus()
      })

      await waitFor(() => {
        expect(result.current.error).toBe(null)
        expect(result.current.isAuthenticated).toBe(true)
      })
    })
  })
}) 