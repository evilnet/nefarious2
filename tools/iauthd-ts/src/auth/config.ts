/**
 * Authentication configuration parser
 * Parses #IAUTH AUTH directives
 */

import type {
  AuthProviderConfig,
  FileAuthConfig,
  LDAPAuthConfig,
  KeycloakAuthConfig,
} from './types.js';

/**
 * Parse an AUTH configuration line
 * Format: provider=<type> key=value key=value ...
 *
 * Examples:
 *   provider=file path=/path/to/users
 *   provider=ldap uri=ldap://server:389 mode=direct userdn=uid=%s,ou=users,dc=example,dc=com
 *   provider=ldap uri=ldaps://server:636 mode=search basedn=ou=users,dc=example,dc=com ...
 */
export function parseAuthConfig(args: string): AuthProviderConfig | null {
  const params = parseKeyValuePairs(args);

  const provider = params.get('provider');
  if (!provider) {
    return null;
  }

  switch (provider) {
    case 'file':
      return parseFileAuthConfig(params);
    case 'ldap':
      return parseLDAPAuthConfig(params);
    case 'keycloak':
      return parseKeycloakAuthConfig(params);
    default:
      console.error(`Unknown auth provider: ${provider}`);
      return null;
  }
}

/**
 * Parse key=value pairs from a string
 * Handles quoted values for values containing spaces
 */
function parseKeyValuePairs(args: string): Map<string, string> {
  const result = new Map<string, string>();

  // Match key=value or key="value with spaces" or key='value with spaces'
  const regex = /(\w+)=(?:"([^"]*)"|'([^']*)'|(\S+))/g;
  let match;

  while ((match = regex.exec(args)) !== null) {
    const key = match[1];
    // Use quoted value if present, otherwise unquoted
    const value = match[2] ?? match[3] ?? match[4];
    result.set(key, value);
  }

  return result;
}

/**
 * Parse file auth provider config
 */
function parseFileAuthConfig(params: Map<string, string>): FileAuthConfig | null {
  const path = params.get('path');
  if (!path) {
    console.error('File auth provider requires path');
    return null;
  }

  const priority = params.has('priority')
    ? parseInt(params.get('priority')!, 10)
    : undefined;

  return {
    provider: 'file',
    path,
    priority,
  };
}

/**
 * Parse LDAP auth provider config
 */
function parseLDAPAuthConfig(params: Map<string, string>): LDAPAuthConfig | null {
  const uri = params.get('uri');
  if (!uri) {
    console.error('LDAP auth provider requires uri');
    return null;
  }

  const mode = params.get('mode') as 'direct' | 'search' | undefined;
  if (!mode || (mode !== 'direct' && mode !== 'search')) {
    console.error('LDAP auth provider requires mode (direct or search)');
    return null;
  }

  const priority = params.has('priority')
    ? parseInt(params.get('priority')!, 10)
    : undefined;

  const timeout = params.has('timeout')
    ? parseInt(params.get('timeout')!, 10)
    : undefined;

  const config: LDAPAuthConfig = {
    provider: 'ldap',
    uri,
    mode,
    priority,
    timeout,
  };

  // Mode-specific options
  if (mode === 'direct') {
    config.userdn = params.get('userdn');
  } else {
    config.basedn = params.get('basedn');
    config.binddn = params.get('binddn');
    config.bindpass = params.get('bindpass');
    config.userfilter = params.get('userfilter');
    config.groupdn = params.get('groupdn');
  }

  // Optional for both modes
  config.accountattr = params.get('accountattr');

  return config;
}

/**
 * Parse Keycloak auth provider config
 */
function parseKeycloakAuthConfig(params: Map<string, string>): KeycloakAuthConfig | null {
  const url = params.get('url');
  if (!url) {
    console.error('Keycloak auth provider requires url');
    return null;
  }

  const realm = params.get('realm');
  if (!realm) {
    console.error('Keycloak auth provider requires realm');
    return null;
  }

  const clientid = params.get('clientid');
  if (!clientid) {
    console.error('Keycloak auth provider requires clientid');
    return null;
  }

  const priority = params.has('priority')
    ? parseInt(params.get('priority')!, 10)
    : undefined;

  const timeout = params.has('timeout')
    ? parseInt(params.get('timeout')!, 10)
    : undefined;

  return {
    provider: 'keycloak',
    url,
    realm,
    clientid,
    clientsecret: params.get('clientsecret'),
    accountattr: params.get('accountattr'),
    timeout,
    priority,
  };
}

/**
 * Convert legacy SASLDB directive to file provider config
 */
export function convertSASLDB(path: string): FileAuthConfig {
  return {
    provider: 'file',
    path,
    priority: 100, // Default priority
  };
}
