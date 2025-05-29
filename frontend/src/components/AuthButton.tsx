/**
 * Authentication Button Component for Plex Online Media Sources Manager.
 * 
 * Provides a responsive authentication button that handles:
 * - OAuth login flow initiation for unauthenticated users
 * - User information display and logout for authenticated users
 * - Loading states with accessible indicators
 * - Error handling with user feedback
 * - Accessibility compliance (ARIA labels, keyboard navigation)
 * - Responsive design with TailwindCSS v4+
 */

import React from 'react'
import { useAuth } from '../hooks/useAuth'
import { clsx } from 'clsx'

// =============================================================================
// COMPONENT INTERFACES
// =============================================================================

/**
 * Props for AuthButton component
 */
export interface AuthButtonProps {
  /** Additional CSS classes for customization */
  className?: string
  
  /** Size variant for the button */
  size?: 'sm' | 'md' | 'lg'
  
  /** Whether to show user avatar when authenticated */
  showAvatar?: boolean
  
  /** Custom text for login button */
  loginText?: string
  
  /** Custom text for logout button */
  logoutText?: string
}

// =============================================================================
// SUBCOMPONENTS
// =============================================================================

/**
 * Loading spinner component with accessibility
 */
const LoadingSpinner: React.FC<{ size?: 'sm' | 'md' | 'lg' }> = ({ size = 'md' }) => {
  const sizeClasses = {
    sm: 'h-4 w-4',
    md: 'h-5 w-5',
    lg: 'h-6 w-6',
  }

  return (
    <div
      role="status"
      aria-label="Loading authentication"
      className={clsx('loading-spinner', sizeClasses[size])}
    >
      <span className="sr-only">Loading...</span>
    </div>
  )
}

/**
 * User avatar component with fallback
 */
const UserAvatar: React.FC<{
  user: { username: string; thumb: string | null }
  size?: 'sm' | 'md' | 'lg'
}> = ({ user, size = 'md' }) => {
  const sizeClasses = {
    sm: 'h-6 w-6 text-xs',
    md: 'h-8 w-8 text-sm',
    lg: 'h-10 w-10 text-base',
  }

  if (user.thumb) {
    return (
      <img
        src={user.thumb}
        alt={`${user.username} avatar`}
        className={clsx(
          'rounded-full object-cover',
          sizeClasses[size]
        )}
      />
    )
  }

  // Fallback to initials
  const initials = user.username.charAt(0).toUpperCase()
  
  return (
    <div
      className={clsx(
        'rounded-full bg-primary-600 text-white flex items-center justify-center font-medium',
        sizeClasses[size]
      )}
      aria-label={`${user.username} avatar`}
    >
      {initials}
    </div>
  )
}

/**
 * Error message component with accessibility
 */
const ErrorMessage: React.FC<{
  error: string
  onDismiss: () => void
  onRetry: () => void
}> = ({ error, onDismiss, onRetry }) => {
  return (
    <div
      role="alert"
      aria-live="polite"
      className="mb-4 p-3 bg-error-50 border border-error-200 rounded-lg dark:bg-error-900/20 dark:border-error-800"
    >
      <div className="flex items-center justify-between">
        <div className="flex items-start">
          <div className="ml-3">
            <p className="text-sm text-error-800 dark:text-error-200">
              {error}
            </p>
          </div>
        </div>
        <div className="flex space-x-2">
          <button
            type="button"
            onClick={onRetry}
            className="inline-flex items-center px-2.5 py-1.5 border border-error-300 shadow-sm text-xs font-medium rounded text-error-700 bg-white hover:bg-error-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-error-500 dark:bg-error-800 dark:text-error-200 dark:border-error-600 dark:hover:bg-error-700"
            aria-label="Try again"
          >
            Try Again
          </button>
          <button
            type="button"
            onClick={onDismiss}
            className="inline-flex items-center px-2.5 py-1.5 border border-transparent text-xs font-medium rounded text-error-700 hover:text-error-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-error-500 dark:text-error-200 dark:hover:text-error-300"
            aria-label="Dismiss error"
          >
            Dismiss
          </button>
        </div>
      </div>
    </div>
  )
}

// =============================================================================
// MAIN COMPONENT
// =============================================================================

/**
 * AuthButton Component
 * 
 * Renders an authentication button that adapts based on user authentication state.
 * Provides login functionality for unauthenticated users and user info with logout
 * for authenticated users.
 * 
 * @param props - Component props
 * @returns JSX element
 */
export const AuthButton: React.FC<AuthButtonProps> = ({
  className,
  size = 'md',
  showAvatar = true,
  loginText = 'Sign in with Plex',
  logoutText = 'Sign out',
}) => {
  const {
    isAuthenticated,
    isLoading,
    error,
    login,
    logout,
    clearError,
    getCurrentUser,
  } = useAuth()

  // Get current user safely
  const currentUser = getCurrentUser()

  // Handle login button click
  const handleLogin = async () => {
    try {
      await login()
    } catch (err) {
      // Error handling is managed by the auth context
      console.error('Login failed:', err)
    }
  }

  // Handle logout button click
  const handleLogout = async () => {
    try {
      await logout()
    } catch (err) {
      // Error handling is managed by the auth context
      console.error('Logout failed:', err)
    }
  }

  // Handle error retry
  const handleRetry = () => {
    clearError()
  }

  // Handle error dismiss
  const handleDismiss = () => {
    clearError()
  }

  // Size-based styling
  const sizeClasses = {
    sm: 'px-3 py-1.5 text-sm',
    md: 'px-4 py-2 text-base',
    lg: 'px-6 py-3 text-lg',
  }

  return (
    <div className={clsx('flex flex-col', className)}>
      {/* Error Message */}
      {error && (
        <ErrorMessage
          error={error}
          onDismiss={handleDismiss}
          onRetry={handleRetry}
        />
      )}

      {/* Authentication Button */}
      {!isAuthenticated ? (
        // Login Button for Unauthenticated Users
        <button
          type="button"
          onClick={handleLogin}
          disabled={isLoading}
          aria-disabled={isLoading}
          className={clsx(
            'btn btn-primary inline-flex items-center justify-center space-x-2',
            sizeClasses[size],
            {
              'cursor-not-allowed opacity-60': isLoading,
            }
          )}
          aria-label={isLoading ? 'Signing in...' : loginText}
        >
          {isLoading ? (
            <>
              <LoadingSpinner size={size} />
              <span>Signing in...</span>
            </>
          ) : (
            <>
              <svg
                className="w-5 h-5"
                fill="currentColor"
                viewBox="0 0 24 24"
                aria-hidden="true"
              >
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
              </svg>
              <span>{loginText}</span>
            </>
          )}
        </button>
      ) : (
        // User Info and Logout for Authenticated Users
        <div className="flex items-center space-x-3">
          {/* User Avatar and Info */}
          <div className="flex items-center space-x-2">
            {showAvatar && currentUser && (
              <UserAvatar user={currentUser} size={size} />
            )}
            {currentUser && (
              <div className="flex flex-col">
                <span
                  className={clsx(
                    'font-medium text-gray-900 dark:text-dark-100',
                    {
                      'text-sm': size === 'sm',
                      'text-base': size === 'md',
                      'text-lg': size === 'lg',
                    }
                  )}
                  title={currentUser.username}
                >
                  {currentUser.username}
                </span>
                {currentUser.email && (
                  <span
                    className={clsx(
                      'text-muted',
                      {
                        'text-xs': size === 'sm',
                        'text-sm': size === 'md',
                        'text-base': size === 'lg',
                      }
                    )}
                  >
                    {currentUser.email}
                  </span>
                )}
              </div>
            )}
          </div>

          {/* Logout Button */}
          <button
            type="button"
            onClick={handleLogout}
            disabled={isLoading}
            aria-disabled={isLoading}
            className={clsx(
              'btn btn-secondary inline-flex items-center justify-center space-x-2',
              sizeClasses[size],
              {
                'cursor-not-allowed opacity-60': isLoading,
              }
            )}
            aria-label={isLoading ? 'Signing out...' : logoutText}
          >
            {isLoading ? (
              <>
                <LoadingSpinner size={size} />
                <span>Signing out...</span>
              </>
            ) : (
              <>
                <svg
                  className="w-4 h-4"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  aria-hidden="true"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"
                  />
                </svg>
                <span>{logoutText}</span>
              </>
            )}
          </button>
        </div>
      )}
    </div>
  )
}

export default AuthButton 