/**
 * Authentication module for iauthd-ts
 * Provides modular authentication with multiple backend support
 */

// Types
export type {
  AuthResult,
  AuthProvider,
  AuthProviderConfig,
  FileAuthConfig,
  LDAPAuthConfig,
  KeycloakAuthConfig,
} from './types.js';

export { isFileAuthConfig, isLDAPAuthConfig, isKeycloakAuthConfig } from './types.js';

// Manager
export { AuthManager } from './manager.js';

// Config parsing
export { parseAuthConfig, convertSASLDB } from './config.js';

// Providers
export { FileAuthProvider, LDAPAuthProvider, KeycloakAuthProvider } from './providers/index.js';
