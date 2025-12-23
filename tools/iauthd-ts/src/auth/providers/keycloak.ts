/**
 * Keycloak authentication provider
 * Uses Resource Owner Password Credentials (ROPC) grant to authenticate users
 */

import type { AuthProvider, AuthResult, KeycloakAuthConfig } from '../types.js';

const DEFAULT_PRIORITY = 100;
const DEFAULT_TIMEOUT = 5000;

/**
 * Token response from Keycloak
 */
interface TokenResponse {
  access_token: string;
  expires_in: number;
  refresh_expires_in: number;
  refresh_token?: string;
  token_type: string;
  'not-before-policy'?: number;
  session_state?: string;
  scope: string;
}

/**
 * Error response from Keycloak
 */
interface ErrorResponse {
  error: string;
  error_description?: string;
}

/**
 * Decoded JWT payload (partial - only fields we care about)
 */
interface JWTPayload {
  sub: string;
  preferred_username?: string;
  email?: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  [key: string]: unknown;
}

export class KeycloakAuthProvider implements AuthProvider {
  readonly name = 'keycloak';
  readonly priority: number;

  private readonly config: KeycloakAuthConfig;
  private readonly tokenEndpoint: string;
  private healthy = false;

  constructor(config: KeycloakAuthConfig) {
    this.config = config;
    this.priority = config.priority ?? DEFAULT_PRIORITY;

    // Build token endpoint URL
    // Format: {url}/realms/{realm}/protocol/openid-connect/token
    const baseUrl = config.url.replace(/\/$/, ''); // Remove trailing slash
    this.tokenEndpoint = `${baseUrl}/realms/${config.realm}/protocol/openid-connect/token`;
  }

  async initialize(): Promise<void> {
    // Validate configuration
    if (!this.config.url) {
      throw new Error('Keycloak provider requires url');
    }

    if (!this.config.realm) {
      throw new Error('Keycloak provider requires realm');
    }

    if (!this.config.clientid) {
      throw new Error('Keycloak provider requires clientid');
    }

    // Test connectivity by fetching the OpenID configuration
    try {
      const wellKnownUrl = `${this.config.url.replace(/\/$/, '')}/realms/${this.config.realm}/.well-known/openid-configuration`;
      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        this.config.timeout ?? DEFAULT_TIMEOUT
      );

      try {
        const response = await fetch(wellKnownUrl, {
          method: 'GET',
          signal: controller.signal,
        });
        clearTimeout(timeout);

        if (response.ok) {
          this.healthy = true;
        } else {
          // Server responded but with error - still mark as potentially healthy
          // since auth might still work
          this.healthy = true;
        }
      } catch (err) {
        clearTimeout(timeout);
        throw err;
      }
    } catch (err) {
      // Connection failed - mark as unhealthy but don't throw
      // Provider may become healthy later
      this.healthy = false;
    }
  }

  async authenticate(
    authcid: string,
    password: string,
    _authzid?: string
  ): Promise<AuthResult> {
    try {
      // Build form data for ROPC grant
      const params = new URLSearchParams();
      params.append('grant_type', 'password');
      params.append('client_id', this.config.clientid);
      params.append('username', authcid);
      params.append('password', password);

      // Add client secret if configured (for confidential clients)
      if (this.config.clientsecret) {
        params.append('client_secret', this.config.clientsecret);
      }

      // Make request with timeout
      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        this.config.timeout ?? DEFAULT_TIMEOUT
      );

      let response: Response;
      try {
        response = await fetch(this.tokenEndpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: params.toString(),
          signal: controller.signal,
        });
        clearTimeout(timeout);
      } catch (err) {
        clearTimeout(timeout);
        if (err instanceof Error && err.name === 'AbortError') {
          this.healthy = false;
          return { success: false, error: 'Request timeout' };
        }
        throw err;
      }

      // Parse response
      const body = await response.text();

      if (response.ok) {
        // Success - parse token response
        const tokenResponse = JSON.parse(body) as TokenResponse;
        this.healthy = true;

        // Extract account name from access token
        const account = this.extractAccountFromToken(tokenResponse.access_token, authcid);

        return { success: true, account };
      } else {
        // Error response
        try {
          const errorResponse = JSON.parse(body) as ErrorResponse;

          // Check for disabled user (before generic invalid_grant)
          if (errorResponse.error_description?.includes('Account disabled')) {
            this.healthy = true;
            return { success: false, error: 'Account disabled' };
          }

          // Check for invalid credentials
          if (
            errorResponse.error === 'invalid_grant' ||
            errorResponse.error_description?.includes('Invalid user credentials')
          ) {
            this.healthy = true; // Server is healthy, just bad credentials
            return { success: false, error: 'Invalid credentials' };
          }

          // Check for client errors (misconfiguration)
          if (
            errorResponse.error === 'unauthorized_client' ||
            errorResponse.error === 'invalid_client'
          ) {
            return {
              success: false,
              error: `Client error: ${errorResponse.error_description || errorResponse.error}`,
            };
          }

          return {
            success: false,
            error: errorResponse.error_description || errorResponse.error,
          };
        } catch {
          return { success: false, error: `HTTP ${response.status}: ${body}` };
        }
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.healthy = false;
      return { success: false, error: `Keycloak error: ${message}` };
    }
  }

  /**
   * Extract account name from JWT access token
   */
  private extractAccountFromToken(accessToken: string, fallback: string): string {
    try {
      // JWT format: header.payload.signature
      const parts = accessToken.split('.');
      if (parts.length !== 3) {
        return fallback;
      }

      // Decode payload (base64url)
      const payload = this.decodeBase64Url(parts[1]);
      const claims = JSON.parse(payload) as JWTPayload;

      // Use configured attribute or default to preferred_username
      if (this.config.accountattr) {
        const value = claims[this.config.accountattr];
        if (typeof value === 'string') {
          return value;
        }
      }

      // Try common username claims
      if (claims.preferred_username) {
        return claims.preferred_username;
      }

      // Fall back to subject (UUID)
      if (claims.sub) {
        return claims.sub;
      }

      return fallback;
    } catch {
      return fallback;
    }
  }

  /**
   * Decode base64url string
   */
  private decodeBase64Url(str: string): string {
    // Convert base64url to base64
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');

    // Add padding if needed
    const padding = base64.length % 4;
    if (padding) {
      base64 += '='.repeat(4 - padding);
    }

    return Buffer.from(base64, 'base64').toString('utf-8');
  }

  async reload(): Promise<void> {
    // Re-test connectivity
    await this.initialize();
  }

  async shutdown(): Promise<void> {
    this.healthy = false;
  }

  isHealthy(): boolean {
    return this.healthy;
  }
}
