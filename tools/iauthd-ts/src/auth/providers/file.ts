/**
 * Static file authentication provider
 * Wraps the existing SASL users file functionality
 */

import type { AuthProvider, AuthResult, FileAuthConfig } from '../types.js';
import {
  parseUsersFile,
  usersFileModified,
  authenticatePlain,
  type UsersDB,
} from '../../sasl.js';

const DEFAULT_PRIORITY = 100;

export class FileAuthProvider implements AuthProvider {
  readonly name = 'file';
  readonly priority: number;

  private usersDb: UsersDB | null = null;
  private readonly filePath: string;

  constructor(config: FileAuthConfig) {
    this.filePath = config.path;
    this.priority = config.priority ?? DEFAULT_PRIORITY;
  }

  async initialize(): Promise<void> {
    this.usersDb = parseUsersFile(this.filePath);
    if (this.usersDb.users.size === 0) {
      // Not an error - file might not exist or be empty
      // Provider will return failure for all auth attempts
    }
  }

  async authenticate(
    authcid: string,
    password: string,
    _authzid?: string
  ): Promise<AuthResult> {
    if (!this.usersDb) {
      return { success: false, error: 'Users database not loaded' };
    }

    // Check if file was modified and reload if needed
    if (usersFileModified(this.usersDb)) {
      this.usersDb = parseUsersFile(this.filePath);
    }

    const account = authenticatePlain(this.usersDb, authcid, password);

    if (account) {
      return { success: true, account };
    }

    return { success: false, error: 'Invalid credentials' };
  }

  async reload(): Promise<void> {
    this.usersDb = parseUsersFile(this.filePath);
  }

  async shutdown(): Promise<void> {
    this.usersDb = null;
  }

  isHealthy(): boolean {
    return this.usersDb !== null;
  }

  /**
   * Get the number of users loaded
   */
  getUserCount(): number {
    return this.usersDb?.users.size ?? 0;
  }
}
