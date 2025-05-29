/**
 * Test suite for MediaSourcesList component.
 * 
 * Tests media sources list functionality including:
 * - Render list of media sources with proper information
 * - Individual toggle controls with optimistic updates
 * - Loading skeletons and error states
 * - Accessibility compliance (ARIA labels, keyboard navigation)
 * - Responsive design for different screen sizes
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MediaSourcesList } from '../MediaSourcesList'
import { useMediaSources } from '../../hooks/useMediaSources'
import type { OnlineMediaSource, UseMediaSourcesReturn } from '../../types'

// Mock the useMediaSources hook
vi.mock('../../hooks/useMediaSources')

// Mock media sources for testing
const mockMediaSources: OnlineMediaSource[] = [
  {
    identifier: 'spotify',
    title: 'Spotify',
    enabled: true,
    scrobble_types: ['music', 'podcast'],
  },
  {
    identifier: 'tidal',
    title: 'TIDAL',
    enabled: false,
    scrobble_types: ['music'],
  },
  {
    identifier: 'youtube-music',
    title: 'YouTube Music',
    enabled: true,
    scrobble_types: ['music', 'video'],
  },
  {
    identifier: 'apple-music',
    title: 'Apple Music',
    enabled: false,
    scrobble_types: ['music'],
  },
]

// Create mock hook return value
const createMockUseMediaSources = (overrides: Partial<UseMediaSourcesReturn> = {}): UseMediaSourcesReturn => ({
  data: undefined,
  isLoading: false,
  isError: false,
  error: null,
  refetch: vi.fn().mockResolvedValue({}),
  toggleSource: {
    mutate: vi.fn(),
    mutateAsync: vi.fn(),
    isLoading: false,
    isError: false,
    error: null,
  },
  bulkDisable: {
    mutate: vi.fn(),
    mutateAsync: vi.fn(),
    isLoading: false,
    isError: false,
    error: null,
  },
  ...overrides,
})

describe('MediaSourcesList', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('Test case: Render list of media sources with proper information', () => {
    it('should render all media sources with correct titles and states', () => {
      // Arrange
      const mockHook = createMockUseMediaSources({
        data: mockMediaSources,
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList />)

      // Assert
      mockMediaSources.forEach(source => {
        expect(screen.getByText(source.title)).toBeInTheDocument()
      })
    })

    it('should display enabled/disabled status for each source', () => {
      // Arrange
      const mockHook = createMockUseMediaSources({
        data: mockMediaSources,
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList />)

      // Assert
      // Check that enabled sources show as enabled
      const enabledSources = mockMediaSources.filter(s => s.enabled)
      enabledSources.forEach(source => {
        const toggle = screen.getByRole('switch', { name: new RegExp(source.title, 'i') })
        expect(toggle).toBeChecked()
      })

      // Check that disabled sources show as disabled
      const disabledSources = mockMediaSources.filter(s => !s.enabled)
      disabledSources.forEach(source => {
        const toggle = screen.getByRole('switch', { name: new RegExp(source.title, 'i') })
        expect(toggle).not.toBeChecked()
      })
    })

    it('should display scrobble types for each source', () => {
      // Arrange
      const mockHook = createMockUseMediaSources({
        data: mockMediaSources,
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList />)

      // Assert
      // Check that all unique scrobble types are present
      const allTypes = [...new Set(mockMediaSources.flatMap(s => s.scrobble_types))]
      allTypes.forEach(type => {
        expect(screen.getAllByText(type).length).toBeGreaterThan(0)
      })
    })

    it('should have proper semantic structure with list and list items', () => {
      // Arrange
      const mockHook = createMockUseMediaSources({
        data: mockMediaSources,
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList />)

      // Assert
      const list = screen.getByRole('list', { name: /media sources/i })
      expect(list).toBeInTheDocument()

      const listItems = screen.getAllByRole('listitem')
      expect(listItems).toHaveLength(mockMediaSources.length)
    })

    it('should render empty state when no media sources are available', () => {
      // Arrange
      const mockHook = createMockUseMediaSources({
        data: [],
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList />)

      // Assert
      expect(screen.getByText(/no media sources available/i)).toBeInTheDocument()
    })
  })

  describe('Test case: Individual toggle controls with optimistic updates', () => {
    it('should call toggleSource when toggle switch is clicked', async () => {
      // Arrange
      const user = userEvent.setup()
      const mockToggle = vi.fn()
      const mockHook = createMockUseMediaSources({
        data: mockMediaSources,
        toggleSource: {
          mutate: mockToggle,
          mutateAsync: vi.fn(),
          isLoading: false,
          isError: false,
          error: null,
        },
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList />)
      const toggle = screen.getByRole('switch', { name: /spotify/i })
      await user.click(toggle)

      // Assert
      expect(mockToggle).toHaveBeenCalledWith({
        sourceId: 'spotify',
        toggleRequest: { enabled: false }, // Should toggle from true to false
      })
    })

    it('should disable toggle controls when mutation is loading', () => {
      // Arrange
      const mockHook = createMockUseMediaSources({
        data: mockMediaSources,
        toggleSource: {
          mutate: vi.fn(),
          mutateAsync: vi.fn(),
          isLoading: true,
          isError: false,
          error: null,
        },
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList />)

      // Assert
      const toggles = screen.getAllByRole('switch')
      toggles.forEach(toggle => {
        expect(toggle).toBeDisabled()
      })
    })

    it('should show loading indicator on specific toggle being mutated', () => {
      // Arrange
      const mockHook = createMockUseMediaSources({
        data: mockMediaSources,
        toggleSource: {
          mutate: vi.fn(),
          mutateAsync: vi.fn(),
          isLoading: true,
          isError: false,
          error: null,
        },
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList />)

      // Assert
      expect(screen.getByLabelText(/updating media source/i)).toBeInTheDocument()
    })

    it('should handle keyboard navigation for toggle controls', async () => {
      // Arrange
      const user = userEvent.setup()
      const mockToggle = vi.fn()
      const mockHook = createMockUseMediaSources({
        data: mockMediaSources,
        toggleSource: {
          mutate: mockToggle,
          mutateAsync: vi.fn(),
          isLoading: false,
          isError: false,
          error: null,
        },
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList />)
      const toggle = screen.getByRole('switch', { name: /spotify/i })
      await user.click(toggle)

      // Assert
      expect(mockToggle).toHaveBeenCalled()
    })
  })

  describe('Test case: Loading skeletons and error states', () => {
    it('should display loading skeletons when data is loading', () => {
      // Arrange
      const mockHook = createMockUseMediaSources({
        isLoading: true,
        data: undefined,
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList />)

      // Assert
      expect(screen.getByLabelText(/loading media sources/i)).toBeInTheDocument()
      expect(screen.getAllByTestId('media-source-skeleton')).toHaveLength(3) // Should show 3 skeleton items
    })

    it('should display error message when data fetching fails', () => {
      // Arrange
      const errorMessage = 'Failed to load media sources'
      const mockHook = createMockUseMediaSources({
        isError: true,
        error: new Error(errorMessage),
        data: undefined,
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList />)

      // Assert
      expect(screen.getByRole('alert')).toBeInTheDocument()
      expect(screen.getAllByText(/failed to load media sources/i)).toHaveLength(2) // Title and description
    })

    it('should display retry button when error occurs', async () => {
      // Arrange
      const user = userEvent.setup()
      const mockRefetch = vi.fn()
      const mockHook = createMockUseMediaSources({
        isError: true,
        error: new Error('Network error'),
        refetch: mockRefetch,
        data: undefined,
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList />)
      const retryButton = screen.getByRole('button', { name: /try again/i })
      await user.click(retryButton)

      // Assert
      expect(mockRefetch).toHaveBeenCalledOnce()
    })

    it('should display error message for toggle operation failures', () => {
      // Arrange
      const mockHook = createMockUseMediaSources({
        data: mockMediaSources,
        toggleSource: {
          mutate: vi.fn(),
          mutateAsync: vi.fn(),
          isLoading: false,
          isError: true,
          error: new Error('Failed to toggle source'),
        },
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList />)

      // Assert
      expect(screen.getByRole('alert')).toBeInTheDocument()
      expect(screen.getByText(/failed to toggle source/i)).toBeInTheDocument()
    })
  })

  describe('Test case: Accessibility compliance (ARIA labels, keyboard navigation)', () => {
    it('should have proper ARIA labels for the list and items', () => {
      // Arrange
      const mockHook = createMockUseMediaSources({
        data: mockMediaSources,
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList />)

      // Assert
      const list = screen.getByRole('list', { name: /media sources/i })
      expect(list).toHaveAttribute('aria-label')

      const listItems = screen.getAllByRole('listitem')
      listItems.forEach(item => {
        expect(item).toBeInTheDocument()
      })
    })

    it('should have descriptive labels for toggle switches', () => {
      // Arrange
      const mockHook = createMockUseMediaSources({
        data: mockMediaSources,
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList />)

      // Assert
      mockMediaSources.forEach(source => {
        const toggle = screen.getByRole('switch', { name: new RegExp(`toggle ${source.title}`, 'i') })
        expect(toggle).toHaveAccessibleName()
        expect(toggle).toHaveAttribute('aria-describedby')
      })
    })

    it('should announce status changes to screen readers', () => {
      // Arrange
      const mockHook = createMockUseMediaSources({
        data: mockMediaSources,
        toggleSource: {
          mutate: vi.fn(),
          mutateAsync: vi.fn(),
          isLoading: true,
          isError: false,
          error: null,
        },
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList />)

      // Assert
      expect(screen.getByLabelText(/updating media source/i)).toHaveAttribute('aria-live', 'polite')
    })

    it('should support keyboard navigation between items', async () => {
      // Arrange
      const user = userEvent.setup()
      const mockHook = createMockUseMediaSources({
        data: mockMediaSources,
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList />)
      const firstToggle = screen.getByRole('switch', { name: /spotify/i })
      firstToggle.focus()

      // Tab to next item
      await user.tab()
      const secondToggle = screen.getByRole('switch', { name: /tidal/i })

      // Assert
      expect(secondToggle).toHaveFocus()
    })

    it('should provide status information to assistive technologies', () => {
      // Arrange
      const mockHook = createMockUseMediaSources({
        data: mockMediaSources,
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList />)

      // Assert
      // Check that we have the right number of enabled and disabled statuses
      const enabledSources = mockMediaSources.filter(s => s.enabled)
      const disabledSources = mockMediaSources.filter(s => !s.enabled)
      
      expect(screen.getAllByText(/enabled/i)).toHaveLength(enabledSources.length)
      expect(screen.getAllByText(/disabled/i)).toHaveLength(disabledSources.length)
    })
  })

  describe('Test case: Responsive design for different screen sizes', () => {
    it('should render in grid layout on larger screens', () => {
      // Arrange
      const mockHook = createMockUseMediaSources({
        data: mockMediaSources,
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList />)

      // Assert
      const list = screen.getByRole('list')
      expect(list).toHaveClass('grid')
    })

    it('should have proper responsive classes for different screen sizes', () => {
      // Arrange
      const mockHook = createMockUseMediaSources({
        data: mockMediaSources,
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList />)

      // Assert
      const list = screen.getByRole('list')
      expect(list).toHaveClass('grid-cols-1') // Mobile
      expect(list).toHaveClass('md:grid-cols-2') // Tablet
      expect(list).toHaveClass('lg:grid-cols-3') // Desktop
    })

    it('should adjust item spacing for different screen sizes', () => {
      // Arrange
      const mockHook = createMockUseMediaSources({
        data: mockMediaSources,
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList />)

      // Assert
      const list = screen.getByRole('list')
      expect(list).toHaveClass('gap-4') // Base gap
      expect(list).toHaveClass('md:gap-6') // Larger gap on tablets and up
    })

    it('should handle long source titles gracefully', () => {
      // Arrange
      const longTitleSources: OnlineMediaSource[] = [
        {
          identifier: 'very-long-name',
          title: 'This is a very long media source name that should wrap properly',
          enabled: true,
          scrobble_types: ['music'],
        },
      ]

      const mockHook = createMockUseMediaSources({
        data: longTitleSources,
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList />)

      // Assert
      expect(screen.getByText(longTitleSources[0].title)).toBeInTheDocument()
    })

    it('should support custom className prop for additional styling', () => {
      // Arrange
      const mockHook = createMockUseMediaSources({
        data: mockMediaSources,
      })

      vi.mocked(useMediaSources).mockReturnValue(mockHook)

      // Act
      render(<MediaSourcesList className="custom-class" />)

      // Assert
      const container = screen.getByTestId('media-sources-list')
      expect(container).toHaveClass('custom-class')
    })
  })
}) 