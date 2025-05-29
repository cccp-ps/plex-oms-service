/**
 * Test suite for AuthButton component.
 * 
 * Tests authentication button functionality including:
 * - Login button when user is not authenticated
 * - User info and logout when authenticated
 * - OAuth flow initiation
 * - Loading states with accessible indicators
 * - Authentication errors with user feedback
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AuthButton } from '../AuthButton'
import { useAuth } from '../../hooks/useAuth'
import type { AuthState, PlexUser } from '../../types'

// Mock the useAuth hook
vi.mock('../../hooks/useAuth')

// Mock PlexUser for testing
const mockUser: PlexUser = {
  id: 12345,
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
  token_expires_at: '2024-12-31T23:59:59Z',
}

// Mock auth states for testing
const createMockAuthState = (overrides: Partial<AuthState> = {}): AuthState => ({
  isAuthenticated: false,
  user: null,
  token: null,
  isLoading: false,
  error: null,
  ...overrides,
})

const mockAuthMethods = {
  login: vi.fn(),
  logout: vi.fn(),
  handleOAuthCallback: vi.fn(),
  checkAuthStatus: vi.fn(),
  clearError: vi.fn(),
  isUserAuthenticated: vi.fn(),
  getCurrentUser: vi.fn(),
  getCurrentToken: vi.fn(),
}

describe('AuthButton', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    
    // Reset mock implementations
    mockAuthMethods.login.mockResolvedValue(undefined)
    mockAuthMethods.logout.mockResolvedValue(undefined)
    mockAuthMethods.clearError.mockImplementation(() => {})
    mockAuthMethods.isUserAuthenticated.mockReturnValue(false)
    mockAuthMethods.getCurrentUser.mockReturnValue(null)
    mockAuthMethods.getCurrentToken.mockReturnValue(null)
  })

  describe('Test case: Render login button when user is not authenticated', () => {
    it('should render login button when user is not authenticated', () => {
      // Arrange
      const authState = createMockAuthState({
        isAuthenticated: false,
        user: null,
        token: null,
      })

      vi.mocked(useAuth).mockReturnValue({
        ...authState,
        ...mockAuthMethods,
      })

      // Act
      render(<AuthButton />)

      // Assert
      expect(screen.getByRole('button', { name: /sign in with plex/i })).toBeInTheDocument()
      expect(screen.queryByText(mockUser.username)).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: /sign out/i })).not.toBeInTheDocument()
    })

    it('should call login method when login button is clicked', async () => {
      // Arrange
      const user = userEvent.setup()
      const authState = createMockAuthState({
        isAuthenticated: false,
        user: null,
        token: null,
      })

      vi.mocked(useAuth).mockReturnValue({
        ...authState,
        ...mockAuthMethods,
      })

      // Act
      render(<AuthButton />)
      const loginButton = screen.getByRole('button', { name: /sign in with plex/i })
      await user.click(loginButton)

      // Assert
      expect(mockAuthMethods.login).toHaveBeenCalledOnce()
    })

    it('should have proper accessibility attributes for login button', () => {
      // Arrange
      const authState = createMockAuthState({
        isAuthenticated: false,
        user: null,
        token: null,
      })

      vi.mocked(useAuth).mockReturnValue({
        ...authState,
        ...mockAuthMethods,
      })

      // Act
      render(<AuthButton />)
      const loginButton = screen.getByRole('button', { name: /sign in with plex/i })

      // Assert
      expect(loginButton).toHaveAttribute('type', 'button')
      expect(loginButton).toHaveAccessibleName()
      expect(loginButton).not.toHaveAttribute('aria-disabled', 'true')
    })
  })

  describe('Test case: Render user info and logout when authenticated', () => {
    it('should render user info and logout button when authenticated', () => {
      // Arrange
      const authState = createMockAuthState({
        isAuthenticated: true,
        user: mockUser,
        token: 'test-token-123',
      })

      mockAuthMethods.isUserAuthenticated.mockReturnValue(true)
      mockAuthMethods.getCurrentUser.mockReturnValue(mockUser)

      vi.mocked(useAuth).mockReturnValue({
        ...authState,
        ...mockAuthMethods,
      })

      // Act
      render(<AuthButton />)

      // Assert
      expect(screen.getByText(mockUser.username)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /sign out/i })).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: /sign in with plex/i })).not.toBeInTheDocument()
    })

    it('should display user avatar when available', () => {
      // Arrange
      const authState = createMockAuthState({
        isAuthenticated: true,
        user: mockUser,
        token: 'test-token-123',
      })

      mockAuthMethods.isUserAuthenticated.mockReturnValue(true)
      mockAuthMethods.getCurrentUser.mockReturnValue(mockUser)

      vi.mocked(useAuth).mockReturnValue({
        ...authState,
        ...mockAuthMethods,
      })

      // Act
      render(<AuthButton />)

      // Assert
      const avatar = screen.getByRole('img', { name: new RegExp(mockUser.username, 'i') })
      expect(avatar).toBeInTheDocument()
      expect(avatar).toHaveAttribute('src', mockUser.thumb)
    })

    it('should call logout method when logout button is clicked', async () => {
      // Arrange
      const user = userEvent.setup()
      const authState = createMockAuthState({
        isAuthenticated: true,
        user: mockUser,
        token: 'test-token-123',
      })

      mockAuthMethods.isUserAuthenticated.mockReturnValue(true)
      mockAuthMethods.getCurrentUser.mockReturnValue(mockUser)

      vi.mocked(useAuth).mockReturnValue({
        ...authState,
        ...mockAuthMethods,
      })

      // Act
      render(<AuthButton />)
      const logoutButton = screen.getByRole('button', { name: /sign out/i })
      await user.click(logoutButton)

      // Assert
      expect(mockAuthMethods.logout).toHaveBeenCalledOnce()
    })

    it('should show fallback when user has no avatar', () => {
      // Arrange
      const userWithoutAvatar = { ...mockUser, thumb: null }
      const authState = createMockAuthState({
        isAuthenticated: true,
        user: userWithoutAvatar,
        token: 'test-token-123',
      })

      mockAuthMethods.isUserAuthenticated.mockReturnValue(true)
      mockAuthMethods.getCurrentUser.mockReturnValue(userWithoutAvatar)

      vi.mocked(useAuth).mockReturnValue({
        ...authState,
        ...mockAuthMethods,
      })

      // Act
      render(<AuthButton />)

      // Assert
      expect(screen.getByText(userWithoutAvatar.username.charAt(0).toUpperCase())).toBeInTheDocument()
      expect(screen.queryByRole('img')).not.toBeInTheDocument()
    })
  })

  describe('Test case: Handle OAuth flow initiation', () => {
    it('should initiate OAuth flow when login button is clicked', async () => {
      // Arrange
      const user = userEvent.setup()
      const authState = createMockAuthState({
        isAuthenticated: false,
        user: null,
        token: null,
      })

      vi.mocked(useAuth).mockReturnValue({
        ...authState,
        ...mockAuthMethods,
      })

      // Act
      render(<AuthButton />)
      const loginButton = screen.getByRole('button', { name: /sign in with plex/i })
      await user.click(loginButton)

      // Assert
      expect(mockAuthMethods.login).toHaveBeenCalledOnce()
    })

    it('should handle OAuth flow initiation errors gracefully', async () => {
      // Arrange
      const user = userEvent.setup()
      const loginError = new Error('OAuth initiation failed')
      mockAuthMethods.login.mockRejectedValue(loginError)

      const authState = createMockAuthState({
        isAuthenticated: false,
        user: null,
        token: null,
      })

      vi.mocked(useAuth).mockReturnValue({
        ...authState,
        ...mockAuthMethods,
      })

      // Act
      render(<AuthButton />)
      const loginButton = screen.getByRole('button', { name: /sign in with plex/i })
      await user.click(loginButton)

      // Assert
      expect(mockAuthMethods.login).toHaveBeenCalledOnce()
      // Note: Error handling is expected to be managed by the auth context
    })
  })

  describe('Test case: Display loading states with accessible indicators', () => {
    it('should show loading spinner when authentication is in progress', () => {
      // Arrange
      const authState = createMockAuthState({
        isAuthenticated: false,
        user: null,
        token: null,
        isLoading: true,
      })

      vi.mocked(useAuth).mockReturnValue({
        ...authState,
        ...mockAuthMethods,
      })

      // Act
      render(<AuthButton />)

      // Assert
      expect(screen.getByRole('status')).toBeInTheDocument()
      expect(screen.getByLabelText(/loading/i)).toBeInTheDocument()
      expect(screen.getByRole('button')).toHaveAttribute('aria-disabled', 'true')
    })

    it('should disable button during loading state', () => {
      // Arrange
      const authState = createMockAuthState({
        isAuthenticated: false,
        user: null,
        token: null,
        isLoading: true,
      })

      vi.mocked(useAuth).mockReturnValue({
        ...authState,
        ...mockAuthMethods,
      })

      // Act
      render(<AuthButton />)
      const button = screen.getByRole('button')

      // Assert
      expect(button).toHaveAttribute('disabled')
      expect(button).toHaveAttribute('aria-disabled', 'true')
    })

    it('should show loading text during authentication', () => {
      // Arrange
      const authState = createMockAuthState({
        isAuthenticated: false,
        user: null,
        token: null,
        isLoading: true,
      })

      vi.mocked(useAuth).mockReturnValue({
        ...authState,
        ...mockAuthMethods,
      })

      // Act
      render(<AuthButton />)

      // Assert
      expect(screen.getByText(/signing in/i)).toBeInTheDocument()
    })

    it('should maintain proper accessibility during loading state', () => {
      // Arrange
      const authState = createMockAuthState({
        isAuthenticated: false,
        user: null,
        token: null,
        isLoading: true,
      })

      vi.mocked(useAuth).mockReturnValue({
        ...authState,
        ...mockAuthMethods,
      })

      // Act
      render(<AuthButton />)
      const button = screen.getByRole('button')
      const loadingIndicator = screen.getByRole('status')

      // Assert
      expect(button).toHaveAccessibleName()
      expect(loadingIndicator).toHaveAttribute('aria-label', expect.stringMatching(/loading/i))
    })
  })

  describe('Test case: Handle authentication errors with user feedback', () => {
    it('should display error message when authentication fails', () => {
      // Arrange
      const errorMessage = 'Authentication failed. Please try again.'
      const authState = createMockAuthState({
        isAuthenticated: false,
        user: null,
        token: null,
        error: errorMessage,
      })

      vi.mocked(useAuth).mockReturnValue({
        ...authState,
        ...mockAuthMethods,
      })

      // Act
      render(<AuthButton />)

      // Assert
      expect(screen.getByRole('alert')).toBeInTheDocument()
      expect(screen.getByText(errorMessage)).toBeInTheDocument()
    })

    it('should provide retry option when authentication fails', async () => {
      // Arrange
      const user = userEvent.setup()
      const errorMessage = 'Network error occurred'
      const authState = createMockAuthState({
        isAuthenticated: false,
        user: null,
        token: null,
        error: errorMessage,
      })

      vi.mocked(useAuth).mockReturnValue({
        ...authState,
        ...mockAuthMethods,
      })

      // Act
      render(<AuthButton />)
      const retryButton = screen.getByRole('button', { name: /try again/i })
      await user.click(retryButton)

      // Assert
      expect(mockAuthMethods.clearError).toHaveBeenCalledOnce()
    })

    it('should clear error when user clicks dismiss button', async () => {
      // Arrange
      const user = userEvent.setup()
      const errorMessage = 'Authentication failed'
      const authState = createMockAuthState({
        isAuthenticated: false,
        user: null,
        token: null,
        error: errorMessage,
      })

      vi.mocked(useAuth).mockReturnValue({
        ...authState,
        ...mockAuthMethods,
      })

      // Act
      render(<AuthButton />)
      const dismissButton = screen.getByRole('button', { name: /dismiss/i })
      await user.click(dismissButton)

      // Assert
      expect(mockAuthMethods.clearError).toHaveBeenCalledOnce()
    })

    it('should have proper accessibility for error messages', () => {
      // Arrange
      const errorMessage = 'Authentication failed'
      const authState = createMockAuthState({
        isAuthenticated: false,
        user: null,
        token: null,
        error: errorMessage,
      })

      vi.mocked(useAuth).mockReturnValue({
        ...authState,
        ...mockAuthMethods,
      })

      // Act
      render(<AuthButton />)
      const errorAlert = screen.getByRole('alert')

      // Assert
      expect(errorAlert).toHaveAttribute('aria-live', 'polite')
      expect(errorAlert).toBeInTheDocument()
    })

    it('should not display error when error is null', () => {
      // Arrange
      const authState = createMockAuthState({
        isAuthenticated: false,
        user: null,
        token: null,
        error: null,
      })

      vi.mocked(useAuth).mockReturnValue({
        ...authState,
        ...mockAuthMethods,
      })

      // Act
      render(<AuthButton />)

      // Assert
      expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    })
  })

  describe('Edge cases and responsive design', () => {
    it('should handle long usernames gracefully', () => {
      // Arrange
      const userWithLongName = {
        ...mockUser,
        username: 'very_long_username_that_might_overflow_the_component',
      }
      const authState = createMockAuthState({
        isAuthenticated: true,
        user: userWithLongName,
        token: 'test-token-123',
      })

      mockAuthMethods.isUserAuthenticated.mockReturnValue(true)
      mockAuthMethods.getCurrentUser.mockReturnValue(userWithLongName)

      vi.mocked(useAuth).mockReturnValue({
        ...authState,
        ...mockAuthMethods,
      })

      // Act
      render(<AuthButton />)

      // Assert
      expect(screen.getByText(userWithLongName.username)).toBeInTheDocument()
    })

    it('should be keyboard navigable', async () => {
      // Arrange
      const user = userEvent.setup()
      const authState = createMockAuthState({
        isAuthenticated: false,
        user: null,
        token: null,
      })

      vi.mocked(useAuth).mockReturnValue({
        ...authState,
        ...mockAuthMethods,
      })

      // Act
      render(<AuthButton />)
      const loginButton = screen.getByRole('button', { name: /sign in with plex/i })
      
      await user.tab()
      expect(loginButton).toHaveFocus()
      
      await user.keyboard('{Enter}')

      // Assert
      expect(mockAuthMethods.login).toHaveBeenCalledOnce()
    })
  })
}) 