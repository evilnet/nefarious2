/**
 * Authentication Manager
 * Coordinates multiple authentication providers with fallback chain behavior
 */

import type {
  AuthProvider,
  AuthResult,
  AuthProviderConfig,
  FileAuthConfig,
  LDAPAuthConfig,
  KeycloakAuthConfig,
} from './types.js';
import { FileAuthProvider } from './providers/file.js';
import { LDAPAuthProvider } from './providers/ldap.js';
import { KeycloakAuthProvider } from './providers/keycloak.js';

export class AuthManager {
  private providers: AuthProvider[] = [];
  private initialized = false;

  constructor(private readonly configs: AuthProviderConfig[]) {}

  /**
   * Initialize all configured providers
   * Providers are sorted by priority (lower = first)
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    // Sort by priority (lower first)
    const sorted = [...this.configs].sort(
      (a, b) => (a.priority ?? 100) - (b.priority ?? 100)
    );

    for (const config of sorted) {
      const provider = this.createProvider(config);
      try {
        await provider.initialize();
        this.providers.push(provider);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`Failed to initialize ${config.provider} provider: ${message}`);
        // Continue with other providers
      }
    }

    this.initialized = true;
  }

  /**
   * Create a provider instance from configuration
   */
  private createProvider(config: AuthProviderConfig): AuthProvider {
    switch (config.provider) {
      case 'file':
        return new FileAuthProvider(config as FileAuthConfig);
      case 'ldap':
        return new LDAPAuthProvider(config as LDAPAuthConfig);
      case 'keycloak':
        return new KeycloakAuthProvider(config as KeycloakAuthConfig);
      default:
        throw new Error(`Unknown auth provider: ${(config as AuthProviderConfig).provider}`);
    }
  }

  /**
   * Authenticate using fallback chain
   * Tries providers in priority order until one succeeds
   */
  async authenticate(
    authcid: string,
    password: string,
    authzid?: string
  ): Promise<AuthResult> {
    if (!this.initialized) {
      return { success: false, error: 'AuthManager not initialized' };
    }

    if (this.providers.length === 0) {
      return { success: false, error: 'No auth providers configured' };
    }

    let lastError: string | undefined;

    for (const provider of this.providers) {
      // Skip unhealthy providers
      if (!provider.isHealthy()) {
        continue;
      }

      try {
        const result = await provider.authenticate(authcid, password, authzid);
        if (result.success) {
          return result;
        }
        // Provider returned explicit failure - continue to next
        lastError = result.error;
      } catch (err) {
        // Provider threw error - log and continue
        const message = err instanceof Error ? err.message : String(err);
        console.error(`Auth provider ${provider.name} error: ${message}`);
        lastError = message;
      }
    }

    return { success: false, error: lastError ?? 'Authentication failed' };
  }

  /**
   * Check if any providers are configured and healthy
   */
  hasProviders(): boolean {
    return this.providers.length > 0;
  }

  /**
   * Check if any provider is healthy
   */
  hasHealthyProviders(): boolean {
    return this.providers.some((p) => p.isHealthy());
  }

  /**
   * Get provider count
   */
  getProviderCount(): number {
    return this.providers.length;
  }

  /**
   * Get provider info for status display
   */
  getProviderInfo(): Array<{ name: string; priority: number; healthy: boolean }> {
    return this.providers.map((p) => ({
      name: p.name,
      priority: p.priority,
      healthy: p.isHealthy(),
    }));
  }

  /**
   * Reload all providers
   */
  async reload(): Promise<void> {
    for (const provider of this.providers) {
      try {
        await provider.reload();
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`Failed to reload ${provider.name} provider: ${message}`);
      }
    }
  }

  /**
   * Shutdown all providers
   */
  async shutdown(): Promise<void> {
    for (const provider of this.providers) {
      try {
        await provider.shutdown();
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`Failed to shutdown ${provider.name} provider: ${message}`);
      }
    }
    this.providers = [];
    this.initialized = false;
  }
}
