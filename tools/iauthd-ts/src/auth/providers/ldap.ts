/**
 * LDAP authentication provider
 * Supports direct bind and search+bind modes
 */

import { Client } from 'ldapts';
import type { AuthProvider, AuthResult, LDAPAuthConfig } from '../types.js';

const DEFAULT_PRIORITY = 100;
const DEFAULT_TIMEOUT = 5000;

export class LDAPAuthProvider implements AuthProvider {
  readonly name = 'ldap';
  readonly priority: number;

  private readonly config: LDAPAuthConfig;
  private healthy = false;

  constructor(config: LDAPAuthConfig) {
    this.config = config;
    this.priority = config.priority ?? DEFAULT_PRIORITY;
  }

  async initialize(): Promise<void> {
    // Validate configuration
    if (!this.config.uri) {
      throw new Error('LDAP provider requires uri');
    }

    if (!this.config.mode) {
      throw new Error('LDAP provider requires mode (direct or search)');
    }

    if (this.config.mode === 'direct' && !this.config.userdn) {
      throw new Error('LDAP direct mode requires userdn template');
    }

    if (this.config.mode === 'search') {
      if (!this.config.basedn) {
        throw new Error('LDAP search mode requires basedn');
      }
      if (!this.config.binddn || !this.config.bindpass) {
        throw new Error('LDAP search mode requires binddn and bindpass');
      }
      if (!this.config.userfilter) {
        throw new Error('LDAP search mode requires userfilter');
      }
    }

    // Test connection with a simple bind/unbind
    try {
      const client = this.createClient();
      await client.bind(
        this.config.binddn || '',
        this.config.bindpass || ''
      );
      await client.unbind();
      this.healthy = true;
    } catch (err) {
      // Connection test failed - provider may still work later
      // Mark as unhealthy but don't throw
      this.healthy = false;
    }
  }

  async authenticate(
    authcid: string,
    password: string,
    _authzid?: string
  ): Promise<AuthResult> {
    try {
      if (this.config.mode === 'direct') {
        return await this.authenticateDirect(authcid, password);
      } else {
        return await this.authenticateSearch(authcid, password);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { success: false, error: `LDAP error: ${message}` };
    }
  }

  /**
   * Direct bind mode: construct DN from template and bind with user's password
   */
  private async authenticateDirect(
    username: string,
    password: string
  ): Promise<AuthResult> {
    const userDN = this.config.userdn!.replace(/%s/g, this.escapeDN(username));
    const client = this.createClient();

    try {
      await client.bind(userDN, password);
      this.healthy = true;

      // Get account name from DN or use username
      const account = this.extractAccountFromDN(userDN, username);

      await client.unbind();
      return { success: true, account };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);

      // LDAP error code 49 is invalid credentials
      if (message.includes('49') || message.toLowerCase().includes('invalid credentials')) {
        return { success: false, error: 'Invalid credentials' };
      }

      // Other errors might indicate server issues
      this.healthy = false;
      return { success: false, error: `LDAP bind failed: ${message}` };
    } finally {
      try {
        await client.unbind();
      } catch {
        // Ignore unbind errors
      }
    }
  }

  /**
   * Search mode: bind as admin, find user, optionally check group, then bind as user
   */
  private async authenticateSearch(
    username: string,
    password: string
  ): Promise<AuthResult> {
    const client = this.createClient();

    try {
      // Step 1: Bind as admin
      await client.bind(this.config.binddn!, this.config.bindpass!);
      this.healthy = true;

      // Step 2: Search for user
      const filter = this.config.userfilter!.replace(/%s/g, this.escapeFilter(username));
      const searchResult = await client.search(this.config.basedn!, {
        scope: 'sub',
        filter,
        attributes: [
          'dn',
          this.config.accountattr || 'uid',
          'sAMAccountName', // Active Directory
          'cn',
        ],
      });

      if (searchResult.searchEntries.length === 0) {
        await client.unbind();
        return { success: false, error: 'User not found' };
      }

      const userEntry = searchResult.searchEntries[0];
      const userDN = userEntry.dn;

      // Step 3: Optional group membership check
      if (this.config.groupdn) {
        const isMember = await this.checkGroupMembership(client, userDN);
        if (!isMember) {
          await client.unbind();
          return { success: false, error: 'User not in required group' };
        }
      }

      // Step 4: Bind as user to verify password
      await client.unbind();

      const userClient = this.createClient();
      try {
        await userClient.bind(userDN, password);
        await userClient.unbind();
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (message.includes('49') || message.toLowerCase().includes('invalid credentials')) {
          return { success: false, error: 'Invalid credentials' };
        }
        return { success: false, error: `LDAP bind failed: ${message}` };
      }

      // Extract account name from search result
      const account = this.extractAccountFromEntry(userEntry, username);

      return { success: true, account };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.healthy = false;
      return { success: false, error: `LDAP search failed: ${message}` };
    } finally {
      try {
        await client.unbind();
      } catch {
        // Ignore unbind errors
      }
    }
  }

  /**
   * Check if user is a member of the configured group
   */
  private async checkGroupMembership(client: Client, userDN: string): Promise<boolean> {
    try {
      const searchResult = await client.search(this.config.groupdn!, {
        scope: 'base',
        filter: '(objectClass=*)',
        attributes: ['member', 'uniqueMember', 'memberUid'],
      });

      if (searchResult.searchEntries.length === 0) {
        return false;
      }

      const groupEntry = searchResult.searchEntries[0];

      // Check member attribute (standard LDAP groups)
      const members = this.getAttrValues(groupEntry, 'member');
      if (members.some((m) => m.toLowerCase() === userDN.toLowerCase())) {
        return true;
      }

      // Check uniqueMember attribute (some LDAP servers)
      const uniqueMembers = this.getAttrValues(groupEntry, 'uniqueMember');
      if (uniqueMembers.some((m) => m.toLowerCase() === userDN.toLowerCase())) {
        return true;
      }

      // Check memberUid attribute (posixGroup)
      const memberUids = this.getAttrValues(groupEntry, 'memberUid');
      const uid = this.extractUidFromDN(userDN);
      if (uid && memberUids.includes(uid)) {
        return true;
      }

      return false;
    } catch {
      return false;
    }
  }

  /**
   * Get attribute values as string array
   */
  private getAttrValues(entry: Record<string, unknown>, attr: string): string[] {
    const value = entry[attr];
    if (!value) return [];
    if (Array.isArray(value)) return value.map(String);
    return [String(value)];
  }

  /**
   * Extract uid from a DN like "uid=john,ou=users,dc=example,dc=com"
   */
  private extractUidFromDN(dn: string): string | null {
    const match = dn.match(/^uid=([^,]+)/i);
    return match ? match[1] : null;
  }

  /**
   * Extract account name from DN
   */
  private extractAccountFromDN(dn: string, fallback: string): string {
    // Try to extract uid or cn from DN
    const uidMatch = dn.match(/^uid=([^,]+)/i);
    if (uidMatch) return uidMatch[1];

    const cnMatch = dn.match(/^cn=([^,]+)/i);
    if (cnMatch) return cnMatch[1];

    return fallback;
  }

  /**
   * Extract account name from LDAP entry
   */
  private extractAccountFromEntry(
    entry: Record<string, unknown>,
    fallback: string
  ): string {
    // Use configured attribute if specified
    if (this.config.accountattr) {
      const value = entry[this.config.accountattr];
      if (value) {
        return Array.isArray(value) ? String(value[0]) : String(value);
      }
    }

    // Try common account name attributes
    for (const attr of ['uid', 'sAMAccountName', 'cn']) {
      const value = entry[attr];
      if (value) {
        return Array.isArray(value) ? String(value[0]) : String(value);
      }
    }

    return fallback;
  }

  /**
   * Create a new LDAP client
   */
  private createClient(): Client {
    return new Client({
      url: this.config.uri,
      timeout: this.config.timeout ?? DEFAULT_TIMEOUT,
      connectTimeout: this.config.timeout ?? DEFAULT_TIMEOUT,
    });
  }

  /**
   * Escape special characters in DN values
   */
  private escapeDN(value: string): string {
    // Escape special DN characters: , + " \ < > ; = (leading/trailing spaces)
    return value
      .replace(/\\/g, '\\\\')
      .replace(/,/g, '\\,')
      .replace(/\+/g, '\\+')
      .replace(/"/g, '\\"')
      .replace(/</g, '\\<')
      .replace(/>/g, '\\>')
      .replace(/;/g, '\\;')
      .replace(/=/g, '\\=')
      .replace(/^ /, '\\ ')
      .replace(/ $/, '\\ ');
  }

  /**
   * Escape special characters in LDAP filter values
   */
  private escapeFilter(value: string): string {
    // Escape special filter characters: * ( ) \ NUL
    return value
      .replace(/\\/g, '\\5c')
      .replace(/\*/g, '\\2a')
      .replace(/\(/g, '\\28')
      .replace(/\)/g, '\\29')
      .replace(/\x00/g, '\\00');
  }

  async reload(): Promise<void> {
    // LDAP config is static, nothing to reload
    // Re-test connection
    try {
      const client = this.createClient();
      if (this.config.mode === 'search') {
        await client.bind(this.config.binddn!, this.config.bindpass!);
      }
      await client.unbind();
      this.healthy = true;
    } catch {
      this.healthy = false;
    }
  }

  async shutdown(): Promise<void> {
    // Nothing to cleanup - we don't pool connections
    this.healthy = false;
  }

  isHealthy(): boolean {
    return this.healthy;
  }
}
