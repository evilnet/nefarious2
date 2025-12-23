/**
 * Authentication provider types for iauthd-ts
 * Defines the interface for modular authentication backends
 */

/**
 * Result of an authentication attempt
 */
export interface AuthResult {
  /** Whether authentication succeeded */
  success: boolean;
  /** Account name if successful (used for IRC account tracking) */
  account?: string;
  /** Error message if failed (for logging, not shown to user) */
  error?: string;
}

/**
 * Authentication provider interface
 * All providers must implement this interface
 */
export interface AuthProvider {
  /** Provider name for logging/debugging */
  readonly name: string;

  /** Provider priority (lower = checked first) */
  readonly priority: number;

  /**
   * Initialize the provider (called once at startup)
   * Should throw if configuration is invalid
   */
  initialize(): Promise<void>;

  /**
   * Authenticate a user with SASL PLAIN credentials
   * @param authcid - Authentication identity (username)
   * @param password - Password
   * @param authzid - Authorization identity (usually empty or same as authcid)
   * @returns AuthResult indicating success/failure
   */
  authenticate(authcid: string, password: string, authzid?: string): Promise<AuthResult>;

  /**
   * Called on rehash to reload configuration
   */
  reload(): Promise<void>;

  /**
   * Cleanup resources (called on shutdown)
   */
  shutdown(): Promise<void>;

  /**
   * Check if provider is healthy/connected
   */
  isHealthy(): boolean;
}

/**
 * Base configuration for all auth providers
 */
export interface BaseAuthConfig {
  provider: string;
  priority?: number; // Default: 100
}

/**
 * Static file provider configuration
 */
export interface FileAuthConfig extends BaseAuthConfig {
  provider: 'file';
  path: string;
}

/**
 * LDAP provider configuration
 */
export interface LDAPAuthConfig extends BaseAuthConfig {
  provider: 'ldap';
  /** LDAP server URI (ldap:// or ldaps://) */
  uri: string;
  /** Authentication mode */
  mode: 'direct' | 'search';
  /** Direct mode: DN template with %s for username */
  userdn?: string;
  /** Search mode: Base DN for user search */
  basedn?: string;
  /** Search mode: Admin bind DN */
  binddn?: string;
  /** Search mode: Admin bind password */
  bindpass?: string;
  /** Search mode: User search filter with %s for username (e.g., "(uid=%s)") */
  userfilter?: string;
  /** Optional: Group DN for membership check */
  groupdn?: string;
  /** Optional: Attribute to use as account name (default: uid or sAMAccountName) */
  accountattr?: string;
  /** Connection timeout in milliseconds (default: 5000) */
  timeout?: number;
}

/**
 * Keycloak provider configuration
 * Uses Resource Owner Password Credentials (ROPC) grant
 */
export interface KeycloakAuthConfig extends BaseAuthConfig {
  provider: 'keycloak';
  /** Keycloak server URL (e.g., https://keycloak.example.com) */
  url: string;
  /** Keycloak realm name */
  realm: string;
  /** OAuth2 client ID (must have Direct Access Grants enabled) */
  clientid: string;
  /** OAuth2 client secret (for confidential clients) */
  clientsecret?: string;
  /** Optional: Attribute from token to use as account name (default: preferred_username) */
  accountattr?: string;
  /** Request timeout in milliseconds (default: 5000) */
  timeout?: number;
}

export type AuthProviderConfig = FileAuthConfig | LDAPAuthConfig | KeycloakAuthConfig;

/**
 * Type guard for FileAuthConfig
 */
export function isFileAuthConfig(config: AuthProviderConfig): config is FileAuthConfig {
  return config.provider === 'file';
}

/**
 * Type guard for LDAPAuthConfig
 */
export function isLDAPAuthConfig(config: AuthProviderConfig): config is LDAPAuthConfig {
  return config.provider === 'ldap';
}

/**
 * Type guard for KeycloakAuthConfig
 */
export function isKeycloakAuthConfig(config: AuthProviderConfig): config is KeycloakAuthConfig {
  return config.provider === 'keycloak';
}
