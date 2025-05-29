/**
 * Authentication Hook for Plex Online Media Sources Manager.
 *
 * Provides a clean interface to authentication functionality including:
 * - Authentication state management
 * - OAuth flow initiation and completion
 * - Secure token storage
 * - Automatic token refresh
 *
 * This hook wraps the AuthContext to provide a focused authentication interface
 * for components that need authentication functionality.
 */

import { useAuth as useAuthContext } from '../contexts/AuthContext'
import type { AuthState, OAuthCallbackResponse, PlexUser } from '../types'

// =============================================================================
// HOOK INTERFACE
// =============================================================================

/**
 * Authentication hook interface.
 * Provides authentication state and methods for components.
 */
export interface UseAuthReturn extends AuthState {
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

  /** Check if user is authenticated (type guard) */
  isUserAuthenticated: () => boolean

  /** Get current user safely (returns null if not authenticated) */
  getCurrentUser: () => PlexUser | null

  /** Get current token safely (returns null if not authenticated) */
  getCurrentToken: () => string | null
}

// =============================================================================
// HOOK IMPLEMENTATION
// =============================================================================

/**
 * Custom authentication hook.
 *
 * Provides a clean interface to authentication functionality by wrapping
 * the AuthContext. This hook adds additional utility methods and ensures
 * type safety for authentication operations.
 *
 * @returns Authentication state and methods
 * @throws Error if used outside AuthProvider
 *
 * @example
 * ```tsx
 * function LoginButton() {
 *   const { isAuthenticated, login, logout, user, isLoading } = useAuth()
 *
 *   if (isLoading) {
 *     return <div>Loading...</div>
 *   }
 *
 *   if (isAuthenticated) {
 *     return (
 *       <div>
 *         <span>Welcome, {user?.username}!</span>
 *         <button onClick={logout}>Logout</button>
 *       </div>
 *     )
 *   }
 *
 *   return <button onClick={login}>Login with Plex</button>
 * }
 * ```
 */
export function useAuth(): UseAuthReturn {
  // Get authentication context
  const authContext = useAuthContext()

  /**
   * Type guard to check if user is authenticated.
   * Provides better type safety than checking isAuthenticated boolean.
   *
   * @returns True if user is authenticated with valid user and token
   */
  const isUserAuthenticated = (): boolean => {
    return authContext.isAuthenticated &&
           authContext.user !== null &&
           authContext.token !== null
  }

  /**
   * Get current user safely.
   * Returns null if user is not authenticated.
   *
   * @returns Current user or null
   */
  const getCurrentUser = (): PlexUser | null => {
    return isUserAuthenticated() ? authContext.user : null
  }

  /**
   * Get current token safely.
   * Returns null if user is not authenticated.
   *
   * @returns Current authentication token or null
   */
  const getCurrentToken = (): string | null => {
    return isUserAuthenticated() ? authContext.token : null
  }

  // Return enhanced authentication interface
  return {
    // Authentication state from context
    isAuthenticated: authContext.isAuthenticated,
    user: authContext.user,
    token: authContext.token,
    isLoading: authContext.isLoading,
    error: authContext.error,

    // Authentication methods from context
    login: authContext.login,
    logout: authContext.logout,
    handleOAuthCallback: authContext.handleOAuthCallback,
    checkAuthStatus: authContext.checkAuthStatus,
    clearError: authContext.clearError,

    // Additional utility methods
    isUserAuthenticated,
    getCurrentUser,
    getCurrentToken,
  }
}

// =============================================================================
// UTILITY HOOKS
// =============================================================================

/**
 * Hook to get current authenticated user.
 * Returns null if user is not authenticated.
 *
 * @returns Current user or null
 *
 * @example
 * ```tsx
 * function UserProfile() {
 *   const user = useCurrentUser()
 *
 *   if (!user) {
 *     return <div>Please log in to view your profile</div>
 *   }
 *
 *   return (
 *     <div>
 *       <h1>{user.username}</h1>
 *       <p>{user.email}</p>
 *     </div>
 *   )
 * }
 * ```
 */
export function useCurrentUser(): PlexUser | null {
  const { getCurrentUser } = useAuth()
  return getCurrentUser()
}

/**
 * Hook to get current authentication token.
 * Returns null if user is not authenticated.
 *
 * @returns Current authentication token or null
 *
 * @example
 * ```tsx
 * function ApiComponent() {
 *   const token = useAuthToken()
 *
 *   useEffect(() => {
 *     if (token) {
 *       // Make authenticated API calls
 *       fetchUserData(token)
 *     }
 *   }, [token])
 *
 *   return <div>...</div>
 * }
 * ```
 */
export function useAuthToken(): string | null {
  const { getCurrentToken } = useAuth()
  return getCurrentToken()
}

/**
 * Hook to check if user is authenticated.
 * Provides type-safe authentication checking.
 *
 * @returns True if user is authenticated
 *
 * @example
 * ```tsx
 * function ProtectedComponent() {
 *   const isAuthenticated = useIsAuthenticated()
 *
 *   if (!isAuthenticated) {
 *     return <LoginPrompt />
 *   }
 *
 *   return <ProtectedContent />
 * }
 * ```
 */
export function useIsAuthenticated(): boolean {
  const { isUserAuthenticated } = useAuth()
  return isUserAuthenticated()
}

/**
 * Hook for authentication loading state.
 * Useful for showing loading indicators during auth operations.
 *
 * @returns True if authentication operation is in progress
 *
 * @example
 * ```tsx
 * function AuthButton() {
 *   const { login } = useAuth()
 *   const isLoading = useAuthLoading()
 *
 *   return (
 *     <button onClick={login} disabled={isLoading}>
 *       {isLoading ? 'Logging in...' : 'Login'}
 *     </button>
 *   )
 * }
 * ```
 */
export function useAuthLoading(): boolean {
  const { isLoading } = useAuth()
  return isLoading
}

/**
 * Hook for authentication error state.
 * Provides access to current authentication error.
 *
 * @returns Current authentication error or null
 *
 * @example
 * ```tsx
 * function AuthErrorDisplay() {
 *   const error = useAuthError()
 *   const { clearError } = useAuth()
 *
 *   if (!error) return null
 *
 *   return (
 *     <div className="error">
 *       <p>{error}</p>
 *       <button onClick={clearError}>Dismiss</button>
 *     </div>
 *   )
 * }
 * ```
 */
export function useAuthError(): string | null {
  const { error } = useAuth()
  return error
}

// =============================================================================
// EXPORTS
// =============================================================================

export default useAuth
