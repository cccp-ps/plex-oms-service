/**
 * Vitest setup file for TypeScript interface tests.
 * 
 * Configures the testing environment for TypeScript type validation
 * and API interface testing.
 */

import { beforeAll, afterEach, afterAll } from 'vitest'
import { cleanup } from '@testing-library/react'

// Setup DOM globals for testing environment
import '@testing-library/jest-dom'

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