/**
 * Tests for useMediaSources hook - Media sources data management hook.
 *
 * Tests the media sources hook that provides React Query integration for:
 * - Fetching and caching media sources data
 * - Handling optimistic updates for better UX
 * - Implementing error handling with retry logic
 * - Cache invalidation after mutations
 *
 * Following TDD methodology with comprehensive test coverage.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { useMediaSources } from '../useMediaSources'
import type { 
  OnlineMediaSource, 
  MediaSourceListResponse, 
  BulkDisableResponse,
  IndividualSourceToggleRequest,
  ApiClientResponse 
} from '../../types'

// Mock the API client
vi.mock('../../services/api', () => ({
  apiClient: {
    getMediaSources: vi.fn(),
    toggleMediaSource: vi.fn(),
    bulkDisableAllSources: vi.fn(),
  },
}))

// Get the mocked API client
const { apiClient: mockApiClient } = await import('../../services/api')

// Test data
const mockMediaSources: OnlineMediaSource[] = [
  {
    identifier: 'spotify',
    title: 'Spotify',
    enabled: true,
    scrobble_types: ['music'],
  },
  {
    identifier: 'tidal',
    title: 'TIDAL',
    enabled: true,
    scrobble_types: ['music'],
  },
  {
    identifier: 'youtube',
    title: 'YouTube',
    enabled: false,
    scrobble_types: ['music', 'video'],
  },
]

const mockMediaSourcesResponse: MediaSourceListResponse = {
  data: mockMediaSources,
  meta: {
    total: 3,
    page: 1,
    per_page: 10,
    has_more: false,
  },
}

const mockSuccessfulApiResponse: ApiClientResponse<MediaSourceListResponse> = {
  data: mockMediaSourcesResponse,
  ok: true,
  status: 200,
  headers: {},
}

const mockBulkDisableResponse: BulkDisableResponse = {
  success: true,
  disabled_count: 2,
  errors: [],
  operation_id: 'op-12345',
  completed_at: new Date().toISOString(),
}

const mockApiError = new Error('Network error')

// Test wrapper with QueryClient
function createTestWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false, // Disable retries for testing
        gcTime: 1000 * 60 * 10, // Enable caching for optimistic updates (10 minutes)
        staleTime: 0, // Data is immediately stale for testing
      },
      mutations: {
        retry: false, // Disable retries for testing
        // Reset mutation states to avoid cross-test pollution
        gcTime: 0,
      },
    },
  })

  return function TestWrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        {children}
      </QueryClientProvider>
    )
  }
}

describe('useMediaSources Hook', () => {
  let TestWrapper: ReturnType<typeof createTestWrapper>

  beforeEach(() => {
    // Reset all mocks and create fresh test wrapper
    vi.clearAllMocks()
    TestWrapper = createTestWrapper()
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  describe('Fetch and Cache Media Sources Data', () => {
    it('should fetch media sources data successfully', async () => {
      // Arrange
      mockApiClient.getMediaSources.mockResolvedValue(mockSuccessfulApiResponse)

      // Act
      const { result } = renderHook(() => useMediaSources(), {
        wrapper: TestWrapper,
      })

      // Assert initial state
      expect(result.current.isLoading).toBe(true)
      expect(result.current.data).toBeUndefined()
      expect(result.current.error).toBe(null)

      // Wait for the query to complete
      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      // Assert successful fetch
      expect(result.current.data).toEqual(mockMediaSources)
      expect(result.current.error).toBe(null)
      expect(mockApiClient.getMediaSources).toHaveBeenCalledOnce()
    })

    it('should handle fetch errors with proper error state', async () => {
      // Arrange
      mockApiClient.getMediaSources.mockRejectedValue(mockApiError)

      // Act
      const { result } = renderHook(() => useMediaSources(), {
        wrapper: TestWrapper,
      })

      // Wait for the query to complete
      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      // Assert error state
      expect(result.current.data).toBeUndefined()
      expect(result.current.error).toBeTruthy()
      expect(result.current.isError).toBe(true)
    })

    it('should cache media sources data and avoid refetching', async () => {
      // Arrange
      mockApiClient.getMediaSources.mockResolvedValue(mockSuccessfulApiResponse)

      // Act - First render
      const { result: result1, unmount } = renderHook(() => useMediaSources(), {
        wrapper: TestWrapper,
      })

      await waitFor(() => {
        expect(result1.current.isLoading).toBe(false)
      })

      unmount()

      // Act - Second render (should use cache)
      const { result: result2 } = renderHook(() => useMediaSources(), {
        wrapper: TestWrapper,
      })

      // Assert cache hit
      expect(result2.current.data).toEqual(mockMediaSources)
      expect(result2.current.isLoading).toBe(false)
      // Should still only be called once due to caching
      expect(mockApiClient.getMediaSources).toHaveBeenCalledOnce()
    })

    it('should provide proper loading states during data fetching', async () => {
      // Arrange
      const resolvePromise = vi.fn()
      const promise = new Promise<ApiClientResponse<MediaSourceListResponse>>((resolve) => {
        resolvePromise.mockImplementation(() => resolve(mockSuccessfulApiResponse))
      })
      mockApiClient.getMediaSources.mockReturnValue(promise)

      // Act
      const { result } = renderHook(() => useMediaSources(), {
        wrapper: TestWrapper,
      })

      // Assert loading state
      expect(result.current.isLoading).toBe(true)
      expect(result.current.data).toBeUndefined()
      expect(result.current.error).toBe(null)

      // Resolve the promise
      act(() => {
        resolvePromise()
      })

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      // Assert loaded state
      expect(result.current.data).toEqual(mockMediaSources)
    })
  })

  describe('Handle Optimistic Updates for Better UX', () => {
    it('should handle optimistic updates when toggling individual source', async () => {
      // Arrange
      mockApiClient.getMediaSources.mockResolvedValue(mockSuccessfulApiResponse)
      
      const updatedSource: OnlineMediaSource = {
        ...mockMediaSources[0],
        enabled: false, // Toggle from true to false
      }
      
      const mockToggleResponse: ApiClientResponse<OnlineMediaSource> = {
        data: updatedSource,
        ok: true,
        status: 200,
        headers: {},
      }
      
      mockApiClient.toggleMediaSource.mockResolvedValue(mockToggleResponse)

      // Act - Initial render
      const { result } = renderHook(() => useMediaSources(), {
        wrapper: TestWrapper,
      })

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      expect(result.current.data).toEqual(mockMediaSources)

      // Act - Toggle source with optimistic update
      const toggleRequest: IndividualSourceToggleRequest = { enabled: false }
      
      await act(async () => {
        await result.current.toggleSource.mutateAsync({
          sourceId: 'spotify',
          toggleRequest,
        })
      })

      // Wait for any state updates to complete
      await waitFor(() => {
        const updatedData = result.current.data
        expect(updatedData).toBeDefined()
        if (updatedData) {
          const spotifySource = updatedData.find(s => s.identifier === 'spotify')
          expect(spotifySource?.enabled).toBe(false)
        }
      })
    })

    it('should revert optimistic updates on mutation failure', async () => {
      // Arrange
      mockApiClient.getMediaSources.mockResolvedValue(mockSuccessfulApiResponse)
      mockApiClient.toggleMediaSource.mockRejectedValue(new Error('Toggle failed'))

      // Act - Initial render
      const { result } = renderHook(() => useMediaSources(), {
        wrapper: TestWrapper,
      })

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      const originalData = result.current.data
      expect(originalData).toEqual(mockMediaSources)

      // Act - Attempt toggle that will fail
      const toggleRequest: IndividualSourceToggleRequest = { enabled: false }
      
      // Use mutate instead of mutateAsync for better error state handling
      await act(async () => {
        result.current.toggleSource.mutate({
          sourceId: 'spotify',
          toggleRequest,
        })
      })

      // Wait for error state to be updated
      await waitFor(
        () => {
          expect(result.current.toggleSource.isError).toBe(true)
          expect(result.current.toggleSource.error).toBeTruthy()
        },
        { timeout: 3000 }
      )

      // Assert data was reverted to original state
      expect(result.current.data).toEqual(originalData)
    })

    it('should handle bulk disable with optimistic updates', async () => {
      // Arrange
      mockApiClient.getMediaSources.mockResolvedValue(mockSuccessfulApiResponse)
      
      const mockBulkResponse: ApiClientResponse<BulkDisableResponse> = {
        data: mockBulkDisableResponse,
        ok: true,
        status: 200,
        headers: {},
      }
      
      mockApiClient.bulkDisableAllSources.mockResolvedValue(mockBulkResponse)

      // Act - Initial render
      const { result } = renderHook(() => useMediaSources(), {
        wrapper: TestWrapper,
      })

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      // Act - Bulk disable
      await act(async () => {
        await result.current.bulkDisable.mutateAsync()
      })

      // Wait for state updates to complete
      await waitFor(() => {
        const updatedData = result.current.data
        expect(updatedData).toBeDefined()
        if (updatedData) {
          updatedData.forEach(source => {
            expect(source.enabled).toBe(false)
          })
        }
      })
    })
  })

  describe('Implement Error Handling with Retry Logic', () => {
    it('should handle API errors gracefully', async () => {
      // Arrange
      const apiError = new Error('API Error: Failed to fetch media sources')
      mockApiClient.getMediaSources.mockRejectedValue(apiError)

      // Act
      const { result } = renderHook(() => useMediaSources(), {
        wrapper: TestWrapper,
      })

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      // Assert error handling
      expect(result.current.isError).toBe(true)
      expect(result.current.error).toBeTruthy()
      expect(result.current.data).toBeUndefined()
    })

    it('should provide retry functionality for failed queries', async () => {
      // Arrange
      mockApiClient.getMediaSources
        .mockRejectedValueOnce(new Error('Network error'))
        .mockResolvedValueOnce(mockSuccessfulApiResponse)

      // Act
      const { result } = renderHook(() => useMediaSources(), {
        wrapper: TestWrapper,
      })

      await waitFor(() => {
        expect(result.current.isError).toBe(true)
      })

      // Act - Retry
      await act(async () => {
        await result.current.refetch()
      })

      // Wait for successful retry
      await waitFor(() => {
        expect(result.current.isError).toBe(false)
        expect(result.current.data).toEqual(mockMediaSources)
      })
    })

    it('should handle toggle source errors with proper error state', async () => {
      // Arrange
      mockApiClient.getMediaSources.mockResolvedValue(mockSuccessfulApiResponse)
      mockApiClient.toggleMediaSource.mockRejectedValue(new Error('Toggle failed'))

      // Act
      const { result } = renderHook(() => useMediaSources(), {
        wrapper: TestWrapper,
      })

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      // Act - Attempt toggle
      const toggleRequest: IndividualSourceToggleRequest = { enabled: false }
      
      // Use mutate instead of mutateAsync for better error state handling
      await act(async () => {
        result.current.toggleSource.mutate({
          sourceId: 'spotify',
          toggleRequest,
        })
      })

      // Wait for error state to be updated
      await waitFor(
        () => {
          expect(result.current.toggleSource.isError).toBe(true)
          expect(result.current.toggleSource.error).toBeTruthy()
        },
        { timeout: 3000 }
      )
    })

    it('should handle bulk disable errors with proper error state', async () => {
      // Arrange
      mockApiClient.getMediaSources.mockResolvedValue(mockSuccessfulApiResponse)
      mockApiClient.bulkDisableAllSources.mockRejectedValue(new Error('Bulk disable failed'))

      // Act
      const { result } = renderHook(() => useMediaSources(), {
        wrapper: TestWrapper,
      })

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      // Act - Attempt bulk disable
      // Use mutate instead of mutateAsync for better error state handling
      await act(async () => {
        result.current.bulkDisable.mutate()
      })

      // Wait for error state to be updated
      await waitFor(
        () => {
          expect(result.current.bulkDisable.isError).toBe(true)
          expect(result.current.bulkDisable.error).toBeTruthy()
        },
        { timeout: 3000 }
      )
    })
  })

  describe('Cache Invalidation After Mutations', () => {
    it('should invalidate cache after successful toggle operation', async () => {
      // Arrange
      mockApiClient.getMediaSources.mockResolvedValue(mockSuccessfulApiResponse)
      
      const updatedSource: OnlineMediaSource = {
        ...mockMediaSources[0],
        enabled: false,
      }
      
      const mockToggleResponse: ApiClientResponse<OnlineMediaSource> = {
        data: updatedSource,
        ok: true,
        status: 200,
        headers: {},
      }
      
      mockApiClient.toggleMediaSource.mockResolvedValue(mockToggleResponse)

      // Act
      const { result } = renderHook(() => useMediaSources(), {
        wrapper: TestWrapper,
      })

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      expect(mockApiClient.getMediaSources).toHaveBeenCalledOnce()

      // Act - Toggle source
      const toggleRequest: IndividualSourceToggleRequest = { enabled: false }
      
      await act(async () => {
        await result.current.toggleSource.mutateAsync({
          sourceId: 'spotify',
          toggleRequest,
        })
      })

      // Assert cache was invalidated and data refetched
      await waitFor(() => {
        expect(mockApiClient.getMediaSources).toHaveBeenCalledTimes(2)
      })
    })

    it('should invalidate cache after successful bulk disable operation', async () => {
      // Arrange
      mockApiClient.getMediaSources.mockResolvedValue(mockSuccessfulApiResponse)
      
      const mockBulkResponse: ApiClientResponse<BulkDisableResponse> = {
        data: mockBulkDisableResponse,
        ok: true,
        status: 200,
        headers: {},
      }
      
      mockApiClient.bulkDisableAllSources.mockResolvedValue(mockBulkResponse)

      // Act
      const { result } = renderHook(() => useMediaSources(), {
        wrapper: TestWrapper,
      })

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      expect(mockApiClient.getMediaSources).toHaveBeenCalledOnce()

      // Act - Bulk disable
      await act(async () => {
        await result.current.bulkDisable.mutateAsync()
      })

      // Assert cache was invalidated and data refetched
      await waitFor(() => {
        expect(mockApiClient.getMediaSources).toHaveBeenCalledTimes(2)
      })
    })

    it('should not invalidate cache after failed mutations', async () => {
      // Arrange
      mockApiClient.getMediaSources.mockResolvedValue(mockSuccessfulApiResponse)
      mockApiClient.toggleMediaSource.mockRejectedValue(new Error('Toggle failed'))

      // Act
      const { result } = renderHook(() => useMediaSources(), {
        wrapper: TestWrapper,
      })

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      expect(mockApiClient.getMediaSources).toHaveBeenCalledOnce()

      // Act - Attempt toggle that will fail
      const toggleRequest: IndividualSourceToggleRequest = { enabled: false }
      
      try {
        await act(async () => {
          await result.current.toggleSource.mutateAsync({
            sourceId: 'spotify',
            toggleRequest,
          })
        })
      } catch {
        // Expected to fail
      }

      // Assert cache was not invalidated (still only called once)
      expect(mockApiClient.getMediaSources).toHaveBeenCalledOnce()
    })
  })

  describe('Hook Interface and Return Values', () => {
    it('should provide expected hook interface', async () => {
      // Arrange
      mockApiClient.getMediaSources.mockResolvedValue(mockSuccessfulApiResponse)

      // Act
      const { result } = renderHook(() => useMediaSources(), {
        wrapper: TestWrapper,
      })

      // Assert hook interface
      expect(result.current).toHaveProperty('data')
      expect(result.current).toHaveProperty('isLoading')
      expect(result.current).toHaveProperty('isError')
      expect(result.current).toHaveProperty('error')
      expect(result.current).toHaveProperty('refetch')
      expect(result.current).toHaveProperty('toggleSource')
      expect(result.current).toHaveProperty('bulkDisable')

      // Assert mutation objects have proper interface
      expect(result.current.toggleSource).toHaveProperty('mutate')
      expect(result.current.toggleSource).toHaveProperty('mutateAsync')
      expect(result.current.toggleSource).toHaveProperty('isLoading')
      expect(result.current.toggleSource).toHaveProperty('isError')
      expect(result.current.toggleSource).toHaveProperty('error')

      expect(result.current.bulkDisable).toHaveProperty('mutate')
      expect(result.current.bulkDisable).toHaveProperty('mutateAsync')
      expect(result.current.bulkDisable).toHaveProperty('isLoading')
      expect(result.current.bulkDisable).toHaveProperty('isError')
      expect(result.current.bulkDisable).toHaveProperty('error')
    })

    it('should handle empty media sources list', async () => {
      // Arrange
      const emptyResponse: MediaSourceListResponse = {
        data: [],
        meta: {
          total: 0,
          page: 1,
          per_page: 10,
          has_more: false,
        },
      }
      
      const mockEmptyApiResponse: ApiClientResponse<MediaSourceListResponse> = {
        data: emptyResponse,
        ok: true,
        status: 200,
        headers: {},
      }
      
      mockApiClient.getMediaSources.mockResolvedValue(mockEmptyApiResponse)

      // Act
      const { result } = renderHook(() => useMediaSources(), {
        wrapper: TestWrapper,
      })

      await waitFor(() => {
        expect(result.current.isLoading).toBe(false)
      })

      // Assert empty list handling
      expect(result.current.data).toEqual([])
      expect(result.current.isError).toBe(false)
    })
  })
}) 