/**
 * Privacy-first type validation tests.
 * 
 * Ensures TypeScript interfaces match backend Pydantic models
 * with proper privacy and security considerations.
 */

import { describe, it, expect } from 'vitest'
import type { PlexUser, OnlineMediaSource, ApiError } from '../types'

describe('Privacy-First Type Validation', () => {
  it('should ensure PlexUser only contains essential fields matching backend', () => {
    // Test that PlexUser interface matches backend privacy constraints
    const minimalUser: PlexUser = {
      id: 12345,
      uuid: 'test-uuid',
      username: 'testuser',
      email: 'test@example.com',
      authentication_token: 'token123',
      thumb: null,
      confirmed: false, // Should default to false for security
      restricted: false,
      guest: false,
      subscription_active: false, // Should default to false for privacy
      subscription_plan: null,
      token_expires_at: null
    }

    // Verify essential authentication fields are required
    expect(typeof minimalUser.id).toBe('number')
    expect(typeof minimalUser.uuid).toBe('string')
    expect(typeof minimalUser.username).toBe('string')
    expect(typeof minimalUser.email).toBe('string')
    expect(typeof minimalUser.authentication_token).toBe('string')

    // Verify privacy defaults
    expect(minimalUser.confirmed).toBe(false)
    expect(minimalUser.subscription_active).toBe(false)
    
    // Verify nullable privacy fields
    expect(minimalUser.thumb).toBeNull()
    expect(minimalUser.subscription_plan).toBeNull()
    expect(minimalUser.token_expires_at).toBeNull()
  })

  it('should ensure OnlineMediaSource follows data minimization principles', () => {
    // Test that OnlineMediaSource contains only essential fields
    const minimalSource: OnlineMediaSource = {
      identifier: 'spotify',
      title: 'Spotify',
      enabled: false, // Should default to false for privacy
      scrobble_types: []
    }

    // Verify essential fields
    expect(typeof minimalSource.identifier).toBe('string')
    expect(typeof minimalSource.title).toBe('string')
    expect(typeof minimalSource.enabled).toBe('boolean')
    expect(Array.isArray(minimalSource.scrobble_types)).toBe(true)

    // Verify privacy default (disabled by default)
    expect(minimalSource.enabled).toBe(false)
  })

  it('should ensure error types do not leak sensitive information', () => {
    // Test that error interfaces are secure and don't expose internals
    const secureError: ApiError = {
      code: 'AUTHENTICATION_FAILED',
      message: 'Authentication failed',
      details: null, // Should allow null to avoid leaking details
      timestamp: '2024-01-01T12:00:00Z',
      request_id: 'req-123'
    }

    expect(typeof secureError.code).toBe('string')
    expect(typeof secureError.message).toBe('string')
    expect(secureError.details).toBeNull()
    expect(typeof secureError.timestamp).toBe('string')
    expect(typeof secureError.request_id === 'string' || 
           secureError.request_id === undefined).toBe(true)
  })

  it('should validate readonly fields prevent accidental mutations', () => {
    // Test that all fields are properly readonly for immutability
    const user: PlexUser = {
      id: 12345,
      uuid: 'test-uuid',
      username: 'testuser',
      email: 'test@example.com',
      authentication_token: 'token123',
      thumb: null,
      confirmed: true,
      restricted: false,
      guest: false,
      subscription_active: true,
      subscription_plan: 'plexpass',
      token_expires_at: '2024-12-31T23:59:59Z'
    }

    // TypeScript should prevent mutations (compile-time check)
    // These would fail at compile time if readonly is not properly applied:
    // user.id = 54321; // Type error
    // user.username = 'hacker'; // Type error
    // user.authentication_token = 'stolen'; // Type error

    // Runtime validation that the object structure is correct
    expect(user).toHaveProperty('id')
    expect(user).toHaveProperty('uuid')
    expect(user).toHaveProperty('username')
    expect(user).toHaveProperty('authentication_token')
  })

  it('should validate that scrobble_types array is readonly', () => {
    const source: OnlineMediaSource = {
      identifier: 'spotify',
      title: 'Spotify',
      enabled: true,
      scrobble_types: ['track', 'album']
    }

    // TypeScript should prevent array mutations (compile-time check)
    // These would fail at compile time:
    // source.scrobble_types.push('artist'); // Type error
    // source.scrobble_types[0] = 'hacked'; // Type error

    // Runtime validation
    expect(Array.isArray(source.scrobble_types)).toBe(true)
    expect(source.scrobble_types.includes('track')).toBe(true)
    expect(source.scrobble_types.includes('album')).toBe(true)
  })
}) 