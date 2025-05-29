/**
 * Authentication Context for Plex Online Media Sources Manager.
 * 
 * Provides authentication state management, OAuth flow handling,
 * secure token storage, and automatic token refresh functionality.
 * 
 * Privacy-focused implementation with minimal data retention.
 */

import React, { createContext, useContext, useReducer, useEffect, useCallback } from 'react'
import type { PlexUser, AuthState, OAuthCallbackResponse } from '../types'
import { apiClient } from '../services/api'

// =============================================================================
// CONTEXT INTERFACES
// =============================================================================

/**
 * Authentication context value interface.
 * Provides state and methods for authentication management.
 */
interface AuthContextValue extends AuthState {
  /** Initiate OAuth login flow */
  login: () => Promise<void>
  
  /** Logout and clear authentication state */
  logout: () => Promise<void>
  
  /** Handle OAuth callback with authorization data */
  handleOAuthCallback: (data: OAuthCallbackResponse) => void
  
  /** Check current authentication status */
  checkAuthStatus: () => Promise<void>
  
  /** Clear error state */
  clearError: () => void
}

// =============================================================================
// STATE MANAGEMENT
// =============================================================================

/**
 * Authentication state reducer actions.
 */
type AuthAction =
  | { type: 'SET_LOADING'; payload: boolean }
  | { type: 'SET_ERROR'; payload: string | null }
  | { type: 'SET_AUTHENTICATED'; payload: { user: PlexUser; token: string } }
  | { type: 'SET_UNAUTHENTICATED' }
  | { type: 'CLEAR_ERROR' }

/**
 * Initial authentication state.
 */
const initialAuthState: AuthState = {
  isAuthenticated: false,
  user: null,
  token: null,
  isLoading: false,
  error: null,
}

/**
 * Authentication state reducer.
 * Manages authentication state transitions with type safety.
 */
function authReducer(state: AuthState, action: AuthAction): AuthState {
  switch (action.type) {
    case 'SET_LOADING':
      return {
        ...state,
        isLoading: action.payload,
        error: action.payload ? null : state.error, // Clear error when starting new operation
      }
    
    case 'SET_ERROR':
      return {
        ...state,
        error: action.payload,
        isLoading: false,
      }
    
    case 'SET_AUTHENTICATED':
      return {
        ...state,
        isAuthenticated: true,
        user: action.payload.user,
        token: action.payload.token,
        isLoading: false,
        error: null,
      }
    
    case 'SET_UNAUTHENTICATED':
      return {
        ...state,
        isAuthenticated: false,
        user: null,
        token: null,
        isLoading: false,
        error: null,
      }
    
    case 'CLEAR_ERROR':
      return {
        ...state,
        error: null,
      }
    
    default:
      return state
  }
}

// =============================================================================
// CONTEXT CREATION
// =============================================================================

/**
 * Authentication context.
 * Provides authentication state and methods to child components.
 */
const AuthContext = createContext<AuthContextValue | undefined>(undefined)

// =============================================================================
// TOKEN STORAGE UTILITIES
// =============================================================================

const AUTH_TOKEN_KEY = 'plex_auth_token'

/**
 * Safely store authentication token in localStorage.
 * @param token - Authentication token to store
 */
function storeToken(token: string): void {
  try {
    localStorage.setItem(AUTH_TOKEN_KEY, token)
  } catch (error) {
    console.warn('Failed to store authentication token:', error)
  }
}

/**
 * Safely retrieve authentication token from localStorage.
 * @returns Stored token or null if not found
 */
function getStoredToken(): string | null {
  try {
    return localStorage.getItem(AUTH_TOKEN_KEY)
  } catch (error) {
    console.warn('Failed to retrieve authentication token:', error)
    return null
  }
}

/**
 * Safely remove authentication token from localStorage.
 */
function removeStoredToken(): void {
  try {
    localStorage.removeItem(AUTH_TOKEN_KEY)
  } catch (error) {
    console.warn('Failed to remove authentication token:', error)
  }
}

/**
 * Check if token is expired based on user's token_expires_at.
 * @param user - User object with expiration information
 * @returns True if token is expired or expiring soon (within 5 minutes)
 */
function isTokenExpired(user: PlexUser): boolean {
  if (!user.token_expires_at) {
    return false // No expiration info, assume valid
  }
  
  const expiresAt = new Date(user.token_expires_at).getTime()
  const now = Date.now()
  const fiveMinutes = 5 * 60 * 1000 // 5 minutes in milliseconds
  
  return expiresAt <= (now + fiveMinutes) // Expire 5 minutes early for safety
}

// =============================================================================
// PROVIDER COMPONENT
// =============================================================================

/**
 * Authentication Provider component.
 * Manages authentication state and provides it to child components.
 */
export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatch] = useReducer(authReducer, initialAuthState)

  /**
   * Check authentication status with stored token.
   * Automatically refreshes expired tokens.
   */
  const checkAuthStatus = useCallback(async (): Promise<void> => {
    const storedToken = getStoredToken()
    
    if (!storedToken) {
      dispatch({ type: 'SET_UNAUTHENTICATED' })
      return
    }

    dispatch({ type: 'SET_LOADING', payload: true })

    try {
      const response = await apiClient.getUserInfo()
      
      if (response.ok && response.data.authenticated && response.data.user) {
        const { user } = response.data
        
        // Check if token is expired or expiring soon
        if (isTokenExpired(user)) {
          try {
            // Attempt to refresh token
            const refreshResponse = await apiClient.refreshToken()
            
            if (refreshResponse.ok) {
              const newToken = refreshResponse.data.access_token
              storeToken(newToken)
              dispatch({
                type: 'SET_AUTHENTICATED',
                payload: { user: refreshResponse.data.user, token: newToken },
              })
              return
            }
          } catch (refreshError) {
            console.warn('Token refresh failed:', refreshError)
            // Fall through to remove invalid token
          }
          
          // Token refresh failed, remove stored token
          removeStoredToken()
          dispatch({ type: 'SET_UNAUTHENTICATED' })
          return
        }
        
        // Token is valid, set authenticated state
        dispatch({
          type: 'SET_AUTHENTICATED',
          payload: { user, token: storedToken },
        })
      } else {
        // User not authenticated, remove stored token
        removeStoredToken()
        dispatch({ type: 'SET_UNAUTHENTICATED' })
      }
    } catch (error) {
      console.error('Authentication check failed:', error)
      removeStoredToken()
      dispatch({
        type: 'SET_ERROR',
        payload: error instanceof Error ? error.message : 'Authentication failed',
      })
    }
  }, [])

  /**
   * Initiate OAuth login flow.
   * Redirects user to Plex OAuth authorization page.
   */
  const login = useCallback(async (): Promise<void> => {
    dispatch({ type: 'SET_LOADING', payload: true })

    try {
      const response = await apiClient.initiateOAuth()
      
      if (response.ok) {
        // Store OAuth state for security
        const { auth_url, state, code_verifier } = response.data
        sessionStorage.setItem('oauth_state', state)
        sessionStorage.setItem('oauth_code_verifier', code_verifier)
        
        // Redirect to Plex OAuth page
        window.location.href = auth_url
      } else {
        dispatch({
          type: 'SET_ERROR',
          payload: 'Failed to initiate OAuth flow',
        })
      }
    } catch (error) {
      console.error('OAuth initiation failed:', error)
      dispatch({
        type: 'SET_ERROR',
        payload: error instanceof Error ? error.message : 'OAuth initiation failed',
      })
    }
  }, [])

  /**
   * Logout user and clear authentication state.
   * Calls backend logout endpoint and removes stored token.
   */
  const logout = useCallback(async (): Promise<void> => {
    dispatch({ type: 'SET_LOADING', payload: true })

    try {
      // Call backend logout endpoint
      await apiClient.logout()
    } catch (error) {
      console.warn('Logout API call failed:', error)
      // Continue with local logout even if API call fails
    }

    // Always clear local authentication state
    removeStoredToken()
    sessionStorage.removeItem('oauth_state')
    sessionStorage.removeItem('oauth_code_verifier')
    dispatch({ type: 'SET_UNAUTHENTICATED' })
  }, [])

  /**
   * Handle OAuth callback with authorization data.
   * Sets authentication state and stores token.
   */
  const handleOAuthCallback = useCallback((data: OAuthCallbackResponse): void => {
    try {
      const { access_token, user } = data
      
      // Store token securely
      storeToken(access_token)
      
      // Clean up OAuth session data
      sessionStorage.removeItem('oauth_state')
      sessionStorage.removeItem('oauth_code_verifier')
      
      // Set authenticated state
      dispatch({
        type: 'SET_AUTHENTICATED',
        payload: { user, token: access_token },
      })
    } catch (error) {
      console.error('OAuth callback handling failed:', error)
      dispatch({
        type: 'SET_ERROR',
        payload: error instanceof Error ? error.message : 'OAuth callback failed',
      })
    }
  }, [])

  /**
   * Clear error state.
   */
  const clearError = useCallback((): void => {
    dispatch({ type: 'CLEAR_ERROR' })
  }, [])

  // Check authentication status on mount
  useEffect(() => {
    checkAuthStatus()
  }, [checkAuthStatus])

  const contextValue: AuthContextValue = {
    ...state,
    login,
    logout,
    handleOAuthCallback,
    checkAuthStatus,
    clearError,
  }

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  )
}

// =============================================================================
// HOOK
// =============================================================================

/**
 * Custom hook for accessing authentication context.
 * Throws error if used outside AuthProvider.
 * 
 * @returns Authentication context value with state and methods
 * @throws Error if used outside AuthProvider
 */
export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext)
  
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  
  return context
} 