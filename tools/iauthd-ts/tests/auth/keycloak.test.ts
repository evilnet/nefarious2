/**
 * Tests for KeycloakAuthProvider
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { KeycloakAuthProvider } from '../../src/auth/providers/keycloak.js';

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

describe('KeycloakAuthProvider', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  /**
   * Create a mock JWT access token
   */
  function createMockToken(payload: Record<string, unknown>): string {
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = 'mock-signature';
    return `${header}.${body}.${signature}`;
  }

  describe('initialization', () => {
    it('should throw if url is missing', async () => {
      const provider = new KeycloakAuthProvider({
        provider: 'keycloak',
        url: '',
        realm: 'test',
        clientid: 'myclient',
      });

      await expect(provider.initialize()).rejects.toThrow('requires url');
    });

    it('should throw if realm is missing', async () => {
      const provider = new KeycloakAuthProvider({
        provider: 'keycloak',
        url: 'https://keycloak.example.com',
        realm: '',
        clientid: 'myclient',
      });

      await expect(provider.initialize()).rejects.toThrow('requires realm');
    });

    it('should throw if clientid is missing', async () => {
      const provider = new KeycloakAuthProvider({
        provider: 'keycloak',
        url: 'https://keycloak.example.com',
        realm: 'test',
        clientid: '',
      });

      await expect(provider.initialize()).rejects.toThrow('requires clientid');
    });

    it('should initialize successfully with valid config', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ issuer: 'https://keycloak.example.com/realms/test' }),
      });

      const provider = new KeycloakAuthProvider({
        provider: 'keycloak',
        url: 'https://keycloak.example.com',
        realm: 'test',
        clientid: 'myclient',
      });

      await provider.initialize();
      expect(provider.isHealthy()).toBe(true);
    });

    it('should use default priority of 100', () => {
      const provider = new KeycloakAuthProvider({
        provider: 'keycloak',
        url: 'https://keycloak.example.com',
        realm: 'test',
        clientid: 'myclient',
      });
      expect(provider.priority).toBe(100);
    });

    it('should use custom priority', () => {
      const provider = new KeycloakAuthProvider({
        provider: 'keycloak',
        url: 'https://keycloak.example.com',
        realm: 'test',
        clientid: 'myclient',
        priority: 50,
      });
      expect(provider.priority).toBe(50);
    });
  });

  describe('authentication', () => {
    it('should authenticate valid user', async () => {
      const accessToken = createMockToken({
        sub: 'user-uuid',
        preferred_username: 'testuser',
        email: 'test@example.com',
      });

      // Mock well-known endpoint
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({}),
      });

      // Mock token endpoint
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: async () =>
          JSON.stringify({
            access_token: accessToken,
            token_type: 'Bearer',
            expires_in: 300,
            scope: 'openid profile email',
          }),
      });

      const provider = new KeycloakAuthProvider({
        provider: 'keycloak',
        url: 'https://keycloak.example.com',
        realm: 'test',
        clientid: 'myclient',
      });

      await provider.initialize();
      const result = await provider.authenticate('testuser', 'password123');

      expect(result.success).toBe(true);
      expect(result.account).toBe('testuser');
    });

    it('should use clientsecret for confidential clients', async () => {
      const accessToken = createMockToken({ preferred_username: 'testuser' });

      mockFetch.mockResolvedValueOnce({ ok: true, json: async () => ({}) });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: async () => JSON.stringify({ access_token: accessToken }),
      });

      const provider = new KeycloakAuthProvider({
        provider: 'keycloak',
        url: 'https://keycloak.example.com',
        realm: 'test',
        clientid: 'myclient',
        clientsecret: 'secret123',
      });

      await provider.initialize();
      await provider.authenticate('testuser', 'password123');

      // Check that client_secret was included in the request
      const tokenCall = mockFetch.mock.calls[1];
      expect(tokenCall[1].body).toContain('client_secret=secret123');
    });

    it('should reject invalid credentials', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, json: async () => ({}) });
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        text: async () =>
          JSON.stringify({
            error: 'invalid_grant',
            error_description: 'Invalid user credentials',
          }),
      });

      const provider = new KeycloakAuthProvider({
        provider: 'keycloak',
        url: 'https://keycloak.example.com',
        realm: 'test',
        clientid: 'myclient',
      });

      await provider.initialize();
      const result = await provider.authenticate('testuser', 'wrongpass');

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid credentials');
    });

    it('should handle disabled account', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, json: async () => ({}) });
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        text: async () =>
          JSON.stringify({
            error: 'invalid_grant',
            error_description: 'Account disabled',
          }),
      });

      const provider = new KeycloakAuthProvider({
        provider: 'keycloak',
        url: 'https://keycloak.example.com',
        realm: 'test',
        clientid: 'myclient',
      });

      await provider.initialize();
      const result = await provider.authenticate('disableduser', 'password');

      expect(result.success).toBe(false);
      expect(result.error).toBe('Account disabled');
    });

    it('should handle client misconfiguration', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, json: async () => ({}) });
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        text: async () =>
          JSON.stringify({
            error: 'unauthorized_client',
            error_description: 'Client not allowed for direct access grants',
          }),
      });

      const provider = new KeycloakAuthProvider({
        provider: 'keycloak',
        url: 'https://keycloak.example.com',
        realm: 'test',
        clientid: 'misconfigured-client',
      });

      await provider.initialize();
      const result = await provider.authenticate('testuser', 'password');

      expect(result.success).toBe(false);
      expect(result.error).toContain('Client error');
    });

    it('should extract account from custom attribute', async () => {
      const accessToken = createMockToken({
        sub: 'user-uuid',
        preferred_username: 'testuser',
        irc_account: 'CustomNick',
      });

      mockFetch.mockResolvedValueOnce({ ok: true, json: async () => ({}) });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: async () => JSON.stringify({ access_token: accessToken }),
      });

      const provider = new KeycloakAuthProvider({
        provider: 'keycloak',
        url: 'https://keycloak.example.com',
        realm: 'test',
        clientid: 'myclient',
        accountattr: 'irc_account',
      });

      await provider.initialize();
      const result = await provider.authenticate('testuser', 'password');

      expect(result.success).toBe(true);
      expect(result.account).toBe('CustomNick');
    });

    it('should fall back to sub if preferred_username not available', async () => {
      const accessToken = createMockToken({
        sub: 'user-uuid-12345',
      });

      mockFetch.mockResolvedValueOnce({ ok: true, json: async () => ({}) });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: async () => JSON.stringify({ access_token: accessToken }),
      });

      const provider = new KeycloakAuthProvider({
        provider: 'keycloak',
        url: 'https://keycloak.example.com',
        realm: 'test',
        clientid: 'myclient',
      });

      await provider.initialize();
      const result = await provider.authenticate('testuser', 'password');

      expect(result.success).toBe(true);
      expect(result.account).toBe('user-uuid-12345');
    });
  });

  describe('token endpoint URL', () => {
    it('should build correct token endpoint URL', async () => {
      const accessToken = createMockToken({ preferred_username: 'testuser' });

      mockFetch.mockResolvedValueOnce({ ok: true, json: async () => ({}) });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: async () => JSON.stringify({ access_token: accessToken }),
      });

      const provider = new KeycloakAuthProvider({
        provider: 'keycloak',
        url: 'https://keycloak.example.com',
        realm: 'myrealm',
        clientid: 'myclient',
      });

      await provider.initialize();
      await provider.authenticate('testuser', 'password');

      // Check the token endpoint URL
      const tokenCall = mockFetch.mock.calls[1];
      expect(tokenCall[0]).toBe(
        'https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token'
      );
    });

    it('should handle trailing slash in URL', async () => {
      const accessToken = createMockToken({ preferred_username: 'testuser' });

      mockFetch.mockResolvedValueOnce({ ok: true, json: async () => ({}) });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: async () => JSON.stringify({ access_token: accessToken }),
      });

      const provider = new KeycloakAuthProvider({
        provider: 'keycloak',
        url: 'https://keycloak.example.com/', // Trailing slash
        realm: 'myrealm',
        clientid: 'myclient',
      });

      await provider.initialize();
      await provider.authenticate('testuser', 'password');

      const tokenCall = mockFetch.mock.calls[1];
      expect(tokenCall[0]).toBe(
        'https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token'
      );
    });
  });

  describe('health status', () => {
    it('should mark as unhealthy on connection failure', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Connection refused'));

      const provider = new KeycloakAuthProvider({
        provider: 'keycloak',
        url: 'https://keycloak.example.com',
        realm: 'test',
        clientid: 'myclient',
      });

      await provider.initialize();
      expect(provider.isHealthy()).toBe(false);
    });

    it('should mark as healthy after successful auth', async () => {
      const accessToken = createMockToken({ preferred_username: 'testuser' });

      // Initialize fails
      mockFetch.mockRejectedValueOnce(new Error('Connection refused'));

      const provider = new KeycloakAuthProvider({
        provider: 'keycloak',
        url: 'https://keycloak.example.com',
        realm: 'test',
        clientid: 'myclient',
      });

      await provider.initialize();
      expect(provider.isHealthy()).toBe(false);

      // Auth succeeds
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: async () => JSON.stringify({ access_token: accessToken }),
      });

      const result = await provider.authenticate('testuser', 'password');
      expect(result.success).toBe(true);
      expect(provider.isHealthy()).toBe(true);
    });
  });

  describe('shutdown', () => {
    it('should mark provider as unhealthy after shutdown', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, json: async () => ({}) });

      const provider = new KeycloakAuthProvider({
        provider: 'keycloak',
        url: 'https://keycloak.example.com',
        realm: 'test',
        clientid: 'myclient',
      });

      await provider.initialize();
      expect(provider.isHealthy()).toBe(true);

      await provider.shutdown();
      expect(provider.isHealthy()).toBe(false);
    });
  });
});
