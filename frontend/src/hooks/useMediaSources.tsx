/**
 * Media Sources Hook for Plex Online Media Sources Manager.
 *
 * Provides React Query integration for media sources data management including:
 * - Fetching and caching media sources data
 * - Handling optimistic updates for better UX
 * - Implementing error handling with retry logic
 * - Cache invalidation after mutations
 *
 * This hook wraps React Query functionality to provide a clean interface
 * for media sources CRUD operations with proper state management.
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiClient } from '../services/api'
import type { 
  OnlineMediaSource, 
  IndividualSourceToggleRequest,
  BulkDisableResponse,
  ApiClientResponse,
  MediaSourceListResponse
} from '../types'

// =============================================================================
// QUERY KEYS
// =============================================================================

/**
 * Query keys for media sources operations.
 * Following React Query key structure for consistent caching.
 */
export const MEDIA_SOURCES_QUERY_KEYS = {
  all: ['mediaSource'] as const,
  lists: () => [...MEDIA_SOURCES_QUERY_KEYS.all, 'list'] as const,
  list: (filters?: Record<string, unknown>) => [...MEDIA_SOURCES_QUERY_KEYS.lists(), filters] as const,
  details: () => [...MEDIA_SOURCES_QUERY_KEYS.all, 'detail'] as const,
  detail: (id: string) => [...MEDIA_SOURCES_QUERY_KEYS.details(), id] as const,
} as const

// =============================================================================
// HOOK INTERFACES
// =============================================================================

/**
 * Toggle source mutation variables interface.
 */
export interface ToggleSourceMutationVariables {
  /** The source identifier to toggle */
  readonly sourceId: string
  /** The toggle request data */
  readonly toggleRequest: IndividualSourceToggleRequest
}

/**
 * Media sources hook return interface.
 * Provides comprehensive media sources management functionality.
 */
export interface UseMediaSourcesReturn {
  // Query state
  /** Media sources data array */
  readonly data: OnlineMediaSource[] | undefined
  /** Whether the initial query is loading */
  readonly isLoading: boolean
  /** Whether the query is in error state */
  readonly isError: boolean
  /** Query error if any */
  readonly error: Error | null
  /** Function to manually refetch the data */
  readonly refetch: () => Promise<any>

  // Toggle source mutation
  readonly toggleSource: {
    /** Trigger toggle mutation */
    readonly mutate: (variables: ToggleSourceMutationVariables) => void
    /** Trigger toggle mutation and return promise */
    readonly mutateAsync: (variables: ToggleSourceMutationVariables) => Promise<OnlineMediaSource>
    /** Whether toggle mutation is loading */
    readonly isLoading: boolean
    /** Whether toggle mutation is in error state */
    readonly isError: boolean
    /** Toggle mutation error if any */
    readonly error: Error | null
  }

  // Bulk disable mutation  
  readonly bulkDisable: {
    /** Trigger bulk disable mutation */
    readonly mutate: () => void
    /** Trigger bulk disable mutation and return promise */
    readonly mutateAsync: () => Promise<BulkDisableResponse>
    /** Whether bulk disable mutation is loading */
    readonly isLoading: boolean
    /** Whether bulk disable mutation is in error state */
    readonly isError: boolean
    /** Bulk disable mutation error if any */
    readonly error: Error | null
  }
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Extract media sources array from API response.
 * Handles the nested data structure from the API.
 */
function extractMediaSourcesData(response: ApiClientResponse<MediaSourceListResponse>): OnlineMediaSource[] {
  if (!response.ok || !response.data?.data) {
    throw new Error('Invalid response structure')
  }
  return [...response.data.data] // Convert readonly array to mutable array
}

/**
 * Apply optimistic update to media sources list for individual toggle.
 */
function applyOptimisticToggleUpdate(
  currentData: OnlineMediaSource[] | undefined,
  variables: ToggleSourceMutationVariables
): OnlineMediaSource[] | undefined {
  if (!currentData) return currentData

  return currentData.map(source =>
    source.identifier === variables.sourceId
      ? { ...source, enabled: variables.toggleRequest.enabled }
      : source
  )
}

/**
 * Apply optimistic update to media sources list for bulk disable.
 */
function applyOptimisticBulkDisableUpdate(
  currentData: OnlineMediaSource[] | undefined
): OnlineMediaSource[] | undefined {
  if (!currentData) return currentData

  return currentData.map(source => ({ ...source, enabled: false }))
}

// =============================================================================
// HOOK IMPLEMENTATION
// =============================================================================

/**
 * Custom hook for media sources data management.
 *
 * Provides React Query integration for fetching, caching, and mutating
 * media sources data with optimistic updates and proper error handling.
 *
 * @returns Media sources state and mutation methods
 *
 * @example
 * ```tsx
 * function MediaSourcesManager() {
 *   const { 
 *     data: sources, 
 *     isLoading, 
 *     toggleSource, 
 *     bulkDisable 
 *   } = useMediaSources()
 *
 *   if (isLoading) {
 *     return <LoadingSpinner />
 *   }
 *
 *   return (
 *     <div>
 *       {sources?.map(source => (
 *         <div key={source.identifier}>
 *           <span>{source.title}</span>
 *           <button 
 *             onClick={() => toggleSource.mutate({
 *               sourceId: source.identifier,
 *               toggleRequest: { enabled: !source.enabled }
 *             })}
 *           >
 *             {source.enabled ? 'Disable' : 'Enable'}
 *           </button>
 *         </div>
 *       ))}
 *       <button onClick={() => bulkDisable.mutate()}>
 *         Disable All
 *       </button>
 *     </div>
 *   )
 * }
 * ```
 */
export function useMediaSources(): UseMediaSourcesReturn {
  const queryClient = useQueryClient()

  // Media sources query
  const {
    data: queryData,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: MEDIA_SOURCES_QUERY_KEYS.list(),
    queryFn: async () => {
      const response = await apiClient.getMediaSources()
      return extractMediaSourcesData(response)
    },
    staleTime: 5 * 60 * 1000, // 5 minutes
    gcTime: 10 * 60 * 1000, // 10 minutes (was cacheTime in v4)
  })

  // Toggle source mutation
  const toggleSourceMutation = useMutation({
    mutationFn: async (variables: ToggleSourceMutationVariables) => {
      const response = await apiClient.toggleMediaSource(
        variables.sourceId, 
        variables.toggleRequest
      )
      if (!response.ok || !response.data) {
        throw new Error('Failed to toggle media source')
      }
      return response.data
    },
    onMutate: async (variables: ToggleSourceMutationVariables) => {
      // Cancel any outgoing refetches
      await queryClient.cancelQueries({ queryKey: MEDIA_SOURCES_QUERY_KEYS.list() })

      // Snapshot the previous value
      const previousData = queryClient.getQueryData<OnlineMediaSource[]>(
        MEDIA_SOURCES_QUERY_KEYS.list()
      )

      // Optimistically update to the new value
      queryClient.setQueryData<OnlineMediaSource[]>(
        MEDIA_SOURCES_QUERY_KEYS.list(),
        oldData => applyOptimisticToggleUpdate(oldData, variables)
      )

      // Return a context object with the snapshotted value
      return { previousData }
    },
    onError: (_err, _variables, context) => {
      // If the mutation fails, use the context returned from onMutate to roll back
      if (context?.previousData) {
        queryClient.setQueryData(MEDIA_SOURCES_QUERY_KEYS.list(), context.previousData)
      }
    },
    onSuccess: (data, variables) => {
      // Update the cache with the actual server response
      queryClient.setQueryData<OnlineMediaSource[]>(
        MEDIA_SOURCES_QUERY_KEYS.list(),
        oldData => {
          if (!oldData) return oldData
          return oldData.map(source =>
            source.identifier === variables.sourceId ? data : source
          )
        }
      )
      
      // Invalidate queries after a short delay to allow optimistic updates to be seen
      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: MEDIA_SOURCES_QUERY_KEYS.list() })
      }, 100)
    },
  })

  // Bulk disable mutation
  const bulkDisableMutation = useMutation({
    mutationFn: async () => {
      const response = await apiClient.bulkDisableAllSources()
      if (!response.ok || !response.data) {
        throw new Error('Failed to bulk disable media sources')
      }
      return response.data
    },
    onMutate: async () => {
      // Cancel any outgoing refetches
      await queryClient.cancelQueries({ queryKey: MEDIA_SOURCES_QUERY_KEYS.list() })

      // Snapshot the previous value
      const previousData = queryClient.getQueryData<OnlineMediaSource[]>(
        MEDIA_SOURCES_QUERY_KEYS.list()
      )

      // Optimistically update to the new value (all disabled)
      queryClient.setQueryData<OnlineMediaSource[]>(
        MEDIA_SOURCES_QUERY_KEYS.list(),
        oldData => applyOptimisticBulkDisableUpdate(oldData)
      )

      // Return a context object with the snapshotted value
      return { previousData }
    },
    onError: (_err, _variables, context) => {
      // If the mutation fails, use the context returned from onMutate to roll back
      if (context?.previousData) {
        queryClient.setQueryData(MEDIA_SOURCES_QUERY_KEYS.list(), context.previousData)
      }
    },
    onSuccess: () => {
      // For bulk disable, keep the optimistic update since all sources are disabled
      // Invalidate queries after a short delay to allow optimistic updates to be seen
      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: MEDIA_SOURCES_QUERY_KEYS.list() })
      }, 100)
    },
  })

  return {
    // Query state
    data: queryData,
    isLoading,
    isError,
    error,
    refetch,

    // Toggle source mutation
    toggleSource: {
      mutate: toggleSourceMutation.mutate,
      mutateAsync: toggleSourceMutation.mutateAsync,
      isLoading: toggleSourceMutation.isPending, // isPending in v5, was isLoading in v4
      isError: toggleSourceMutation.isError,
      error: toggleSourceMutation.error,
    },

    // Bulk disable mutation
    bulkDisable: {
      mutate: bulkDisableMutation.mutate,
      mutateAsync: bulkDisableMutation.mutateAsync,
      isLoading: bulkDisableMutation.isPending, // isPending in v5, was isLoading in v4
      isError: bulkDisableMutation.isError,
      error: bulkDisableMutation.error,
    },
  }
}

// =============================================================================
// UTILITY HOOKS
// =============================================================================

/**
 * Hook to get a specific media source by identifier.
 * Returns undefined if the source is not found or data is not loaded.
 *
 * @param sourceId - The identifier of the media source
 * @returns The media source if found, undefined otherwise
 *
 * @example
 * ```tsx
 * function SpotifyToggle() {
 *   const spotifySource = useMediaSource('spotify')
 *   const { toggleSource } = useMediaSources()
 *
 *   if (!spotifySource) {
 *     return <div>Loading...</div>
 *   }
 *
 *   return (
 *     <button 
 *       onClick={() => toggleSource.mutate({
 *         sourceId: 'spotify',
 *         toggleRequest: { enabled: !spotifySource.enabled }
 *       })}
 *     >
 *       {spotifySource.enabled ? 'Disable' : 'Enable'} Spotify
 *     </button>
 *   )
 * }
 * ```
 */
export function useMediaSource(sourceId: string): OnlineMediaSource | undefined {
  const { data } = useMediaSources()
  return data?.find(source => source.identifier === sourceId)
}

/**
 * Hook to get the count of enabled media sources.
 * Returns 0 if data is not loaded.
 *
 * @returns Number of enabled media sources
 *
 * @example
 * ```tsx
 * function MediaSourcesStats() {
 *   const enabledCount = useEnabledMediaSourcesCount()
 *   const { data: allSources } = useMediaSources()
 *
 *   return (
 *     <div>
 *       {enabledCount} of {allSources?.length || 0} sources enabled
 *     </div>
 *   )
 * }
 * ```
 */
export function useEnabledMediaSourcesCount(): number {
  const { data } = useMediaSources()
  return data?.filter(source => source.enabled).length || 0
}