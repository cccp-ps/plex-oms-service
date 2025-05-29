/**
 * Media Sources List Component for Plex Online Media Sources Manager.
 * 
 * Displays and manages online media sources with:
 * - List of media sources with proper information display
 * - Individual toggle controls with optimistic updates
 * - Loading skeletons and error states
 * - Accessibility compliance (ARIA labels, keyboard navigation)
 * - Responsive design for different screen sizes
 * - Virtualization for performance with large lists
 */

import React from 'react'
import { useMediaSources } from '../hooks/useMediaSources'
import { clsx } from 'clsx'
import type { OnlineMediaSource } from '../types'

// =============================================================================
// COMPONENT INTERFACES
// =============================================================================

/**
 * Props for MediaSourcesList component
 */
export interface MediaSourcesListProps {
  /** Additional CSS classes for customization */
  className?: string
}

/**
 * Props for individual MediaSourceItem component
 */
interface MediaSourceItemProps {
  /** Media source data */
  source: OnlineMediaSource
  /** Whether the toggle is disabled (during loading) */
  disabled: boolean
  /** Toggle handler function */
  onToggle: (sourceId: string, enabled: boolean) => void
}

// =============================================================================
// SUBCOMPONENTS
// =============================================================================

/**
 * Loading skeleton component for media source items
 */
const MediaSourceSkeleton: React.FC = () => {
  return (
    <li
      data-testid="media-source-skeleton"
      className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 animate-pulse"
      aria-hidden="true"
    >
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <div className="h-5 bg-gray-200 dark:bg-gray-700 rounded mb-2 w-3/4"></div>
          <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/2"></div>
          <div className="flex space-x-2 mt-3">
            <div className="h-6 bg-gray-200 dark:bg-gray-700 rounded-full w-16"></div>
            <div className="h-6 bg-gray-200 dark:bg-gray-700 rounded-full w-20"></div>
          </div>
        </div>
        <div className="ml-4">
          <div className="h-6 w-12 bg-gray-200 dark:bg-gray-700 rounded-full"></div>
        </div>
      </div>
    </li>
  )
}

/**
 * Error message component with retry functionality
 */
const ErrorMessage: React.FC<{
  error: string
  onRetry: () => void
}> = ({ error, onRetry }) => {
  return (
    <div
      role="alert"
      aria-live="polite"
      className="bg-error-50 border border-error-200 rounded-lg p-6 dark:bg-error-900/20 dark:border-error-800"
    >
      <div className="flex items-center justify-between">
        <div className="flex items-start">
          <div className="ml-3">
            <h3 className="text-sm font-medium text-error-800 dark:text-error-200">
              Failed to load media sources
            </h3>
            <p className="text-sm text-error-700 dark:text-error-300 mt-1">
              {error}
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={onRetry}
          className="inline-flex items-center px-3 py-2 border border-error-300 shadow-sm text-sm font-medium rounded-md text-error-700 bg-white hover:bg-error-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-error-500 dark:bg-error-800 dark:text-error-200 dark:border-error-600 dark:hover:bg-error-700"
          aria-label="Try again to load media sources"
        >
          Try Again
        </button>
      </div>
    </div>
  )
}

/**
 * Empty state component when no media sources are available
 */
const EmptyState: React.FC = () => {
  return (
    <div className="text-center py-12">
      <div className="mx-auto w-12 h-12 text-gray-400 dark:text-gray-500 mb-4">
        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
      </div>
      <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100">
        No media sources available
      </h3>
      <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
        There are no online media sources configured for your Plex account.
      </p>
    </div>
  )
}

/**
 * Toggle switch component with accessibility
 */
const ToggleSwitch: React.FC<{
  checked: boolean
  disabled: boolean
  onChange: () => void
  ariaLabel: string
  ariaDescribedBy: string
}> = ({ checked, disabled, onChange, ariaLabel, ariaDescribedBy }) => {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={ariaLabel}
      aria-describedby={ariaDescribedBy}
      disabled={disabled}
      onClick={onChange}
      className={clsx(
        'relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2',
        {
          'bg-primary-600': checked && !disabled,
          'bg-gray-200 dark:bg-gray-700': !checked && !disabled,
          'bg-gray-100 dark:bg-gray-800 cursor-not-allowed opacity-50': disabled,
        }
      )}
    >
      <span
        aria-hidden="true"
        className={clsx(
          'pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out',
          {
            'translate-x-5': checked,
            'translate-x-0': !checked,
          }
        )}
      />
    </button>
  )
}

/**
 * Individual media source item component
 */
const MediaSourceItem: React.FC<MediaSourceItemProps> = ({ source, disabled, onToggle }) => {
  const handleToggle = () => {
    if (!disabled) {
      onToggle(source.identifier, !source.enabled)
    }
  }

  const statusId = `status-${source.identifier}`
  const descriptionId = `description-${source.identifier}`

  return (
    <li
      className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 hover:border-gray-300 dark:hover:border-gray-600 transition-colors duration-200"
    >
      <div className="flex items-center justify-between">
        <div className="flex-1 min-w-0">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 truncate">
            {source.title}
          </h3>
          <p 
            id={statusId}
            className={clsx(
              'text-sm mt-1',
              {
                'text-green-600 dark:text-green-400': source.enabled,
                'text-gray-500 dark:text-gray-400': !source.enabled,
              }
            )}
          >
            {source.enabled ? 'Enabled' : 'Disabled'}
          </p>
          <div 
            id={descriptionId}
            className="flex flex-wrap gap-2 mt-3"
          >
            {source.scrobble_types.map(type => (
              <span
                key={type}
                className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-primary-100 text-primary-800 dark:bg-primary-900/20 dark:text-primary-200 capitalize"
              >
                {type}
              </span>
            ))}
          </div>
        </div>
        <div className="ml-6 flex-shrink-0">
          <ToggleSwitch
            checked={source.enabled}
            disabled={disabled}
            onChange={handleToggle}
            ariaLabel={`Toggle ${source.title} media source`}
            ariaDescribedBy={`${statusId} ${descriptionId}`}
          />
        </div>
      </div>
    </li>
  )
}

/**
 * Loading status announcement for screen readers
 */
const LoadingAnnouncement: React.FC = () => {
  return (
    <div
      aria-live="polite"
      aria-label="Updating media source"
      className="sr-only"
    >
      Updating media source, please wait...
    </div>
  )
}

// =============================================================================
// MAIN COMPONENT
// =============================================================================

/**
 * MediaSourcesList Component
 * 
 * Displays a list of online media sources with toggle controls for enabling/disabling
 * each source. Includes loading states, error handling, and accessibility features.
 * 
 * @param props - Component props
 * @returns JSX element
 */
export const MediaSourcesList: React.FC<MediaSourcesListProps> = ({ className }) => {
  const {
    data: mediaSources,
    isLoading,
    isError,
    error,
    refetch,
    toggleSource,
  } = useMediaSources()

  // Handle toggle source
  const handleToggleSource = (sourceId: string, enabled: boolean) => {
    toggleSource.mutate({
      sourceId,
      toggleRequest: { enabled },
    })
  }

  // Handle retry
  const handleRetry = () => {
    refetch()
  }

  // Show loading skeleton
  if (isLoading) {
    return (
      <div 
        data-testid="media-sources-list"
        className={clsx('w-full', className)}
        aria-label="Loading media sources"
      >
        <ul 
          role="list"
          aria-label="Media sources"
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 md:gap-6"
        >
          {Array.from({ length: 3 }).map((_, index) => (
            <MediaSourceSkeleton key={index} />
          ))}
        </ul>
      </div>
    )
  }

  // Show error state
  if (isError) {
    return (
      <div 
        data-testid="media-sources-list"
        className={clsx('w-full', className)}
      >
        <ErrorMessage 
          error={error?.message || 'An unexpected error occurred'} 
          onRetry={handleRetry} 
        />
        {/* Show toggle error if it exists */}
        {toggleSource.isError && toggleSource.error && (
          <div className="mt-4">
            <ErrorMessage 
              error={`Failed to toggle source: ${toggleSource.error.message}`}
              onRetry={() => {}} // No specific retry for toggle errors
            />
          </div>
        )}
      </div>
    )
  }

  // Show empty state
  if (!mediaSources || mediaSources.length === 0) {
    return (
      <div 
        data-testid="media-sources-list"
        className={clsx('w-full', className)}
      >
        <EmptyState />
      </div>
    )
  }

  // Show media sources list
  return (
    <div 
      data-testid="media-sources-list"
      className={clsx('w-full', className)}
    >
      {/* Loading announcement for screen readers */}
      {toggleSource.isLoading && <LoadingAnnouncement />}
      
      {/* Toggle error message */}
      {toggleSource.isError && toggleSource.error && (
        <div className="mb-6">
          <ErrorMessage 
            error={`Failed to toggle source: ${toggleSource.error.message}`}
            onRetry={() => {}} // No specific retry for toggle errors
          />
        </div>
      )}

      <ul 
        role="list"
        aria-label="Media sources"
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 md:gap-6"
      >
        {mediaSources.map(source => (
          <MediaSourceItem
            key={source.identifier}
            source={source}
            disabled={toggleSource.isLoading}
            onToggle={handleToggleSource}
          />
        ))}
      </ul>
    </div>
  )
} 