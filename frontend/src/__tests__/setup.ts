/**
 * Vitest setup file for TypeScript interface tests.
 * 
 * Configures the testing environment for TypeScript type validation
 * and API interface testing.
 */

import { beforeAll, afterEach, afterAll, vi } from 'vitest'
import { cleanup, configure } from '@testing-library/react'

// Setup DOM globals for testing environment
import '@testing-library/jest-dom'

// Configure React Testing Library for React 18
configure({
  // React 18 automatic batching configuration
  reactStrictMode: true,
  // Avoid act warnings for async operations
  asyncUtilTimeout: 5000,
})

// Mock IntersectionObserver for components that might use it
global.IntersectionObserver = vi.fn().mockImplementation((_callback: IntersectionObserverCallback) => ({
  observe: vi.fn(),
  disconnect: vi.fn(),
  unobserve: vi.fn(),
  root: null,
  rootMargin: '0px',
  thresholds: [0],
  takeRecords: vi.fn().mockReturnValue([]),
})) as unknown as typeof IntersectionObserver

// Mock ResizeObserver for components that might use it
global.ResizeObserver = vi.fn().mockImplementation((_callback: ResizeObserverCallback) => ({
  observe: vi.fn(),
  disconnect: vi.fn(),
  unobserve: vi.fn(),
})) as unknown as typeof ResizeObserver

// Mock window.matchMedia for responsive components
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
})

// Cleanup after each test
afterEach(() => {
  cleanup()
})

// Global test configuration
beforeAll(() => {
  // Add any global test setup here
})

afterAll(() => {
  // Add any global test cleanup here
})

// Extend global namespace for test environment
declare global {
  var __APP_VERSION__: string
  var __BUILD_TIME__: string  
  var __DEV__: boolean
}

// Mock global variables that might be used in types
global.__APP_VERSION__ = '0.1.0'
global.__BUILD_TIME__ = '2024-01-01T00:00:00Z'
global.__DEV__ = true 