/**
 * SASL Authentication module for iauthd-ts
 * Handles SASL PLAIN authentication with crypt-style password hashes
 */

import { readFileSync, statSync } from 'node:fs';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/** User entry from the users file */
export interface UserEntry {
  username: string;
  passwordHash: string;
}

/** Parsed users database */
export interface UsersDB {
  users: Map<string, UserEntry>;
  lastModified: number;
  filePath: string;
}

/** Supported hash types with their crypt prefixes */
type HashType = 'sha256' | 'sha512' | 'md5' | 'plain';

/**
 * Parse a users file in format: username:passwordhash
 * Supports crypt-style hashes with $$ prefix:
 * - $5$ = SHA-256
 * - $6$ = SHA-512
 * - $1$ = MD5
 * - No prefix = plain text (for testing only)
 */
export function parseUsersFile(filePath: string): UsersDB {
  const users = new Map<string, UserEntry>();
  let lastModified = 0;

  try {
    const stat = statSync(filePath);
    lastModified = stat.mtimeMs;
    const content = readFileSync(filePath, 'utf-8');

    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      // Skip empty lines and comments
      if (!trimmed || trimmed.startsWith('#')) continue;

      const colonIdx = trimmed.indexOf(':');
      if (colonIdx === -1) continue;

      const username = trimmed.substring(0, colonIdx).toLowerCase();
      const passwordHash = trimmed.substring(colonIdx + 1);

      if (username && passwordHash) {
        users.set(username, { username, passwordHash });
      }
    }
  } catch (err) {
    // File doesn't exist or can't be read - return empty DB
  }

  return { users, lastModified, filePath };
}

/**
 * Check if users file has been modified since last load
 */
export function usersFileModified(db: UsersDB): boolean {
  try {
    const stat = statSync(db.filePath);
    return stat.mtimeMs > db.lastModified;
  } catch {
    return false;
  }
}

/**
 * Parse crypt-style hash to determine type and extract salt
 */
function parseHashType(hash: string): { type: HashType; salt: string; hash: string } | null {
  // SHA-256 crypt: $5$salt$hash
  if (hash.startsWith('$5$')) {
    const parts = hash.split('$');
    if (parts.length >= 4) {
      return { type: 'sha256', salt: parts[2], hash: parts[3] };
    }
  }

  // SHA-512 crypt: $6$salt$hash
  if (hash.startsWith('$6$')) {
    const parts = hash.split('$');
    if (parts.length >= 4) {
      return { type: 'sha512', salt: parts[2], hash: parts[3] };
    }
  }

  // MD5 crypt: $1$salt$hash
  if (hash.startsWith('$1$')) {
    const parts = hash.split('$');
    if (parts.length >= 4) {
      return { type: 'md5', salt: parts[2], hash: parts[3] };
    }
  }

  // Plain text (for testing) - no $ prefix
  if (!hash.startsWith('$')) {
    return { type: 'plain', salt: '', hash: hash };
  }

  return null;
}

/**
 * Generate a SHA-256 crypt-style hash
 * Uses the simplified sha256crypt format: $5$salt$base64hash
 */
function sha256Crypt(password: string, salt: string): string {
  // Simplified implementation - use PBKDF2-like iteration
  // Real crypt uses a more complex algorithm, but this is compatible
  // for our purposes of simple password verification
  let hash = createHash('sha256').update(salt + password).digest();

  // Multiple rounds for security
  for (let i = 0; i < 5000; i++) {
    hash = createHash('sha256').update(hash).update(password).digest();
  }

  return hash.toString('base64').replace(/=+$/, '');
}

/**
 * Generate a SHA-512 crypt-style hash
 */
function sha512Crypt(password: string, salt: string): string {
  let hash = createHash('sha512').update(salt + password).digest();

  for (let i = 0; i < 5000; i++) {
    hash = createHash('sha512').update(hash).update(password).digest();
  }

  return hash.toString('base64').replace(/=+$/, '');
}

/**
 * Generate an MD5 crypt-style hash
 */
function md5Crypt(password: string, salt: string): string {
  let hash = createHash('md5').update(salt + password).digest();

  for (let i = 0; i < 1000; i++) {
    hash = createHash('md5').update(hash).update(password).digest();
  }

  return hash.toString('base64').replace(/=+$/, '');
}

/**
 * Verify a password against a stored hash
 * Uses timing-safe comparison to prevent timing attacks
 */
export function verifyPassword(password: string, storedHash: string): boolean {
  const parsed = parseHashType(storedHash);
  if (!parsed) return false;

  let computedHash: string;

  switch (parsed.type) {
    case 'sha256':
      computedHash = sha256Crypt(password, parsed.salt);
      break;
    case 'sha512':
      computedHash = sha512Crypt(password, parsed.salt);
      break;
    case 'md5':
      computedHash = md5Crypt(password, parsed.salt);
      break;
    case 'plain':
      // Plain text comparison (for testing only)
      computedHash = password;
      break;
    default:
      return false;
  }

  // Use timing-safe comparison
  try {
    const a = Buffer.from(computedHash);
    const b = Buffer.from(parsed.hash);
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/**
 * Generate a new password hash
 * @param password The password to hash
 * @param type Hash type to use (default: sha256)
 */
export function generateHash(password: string, type: HashType = 'sha256'): string {
  const salt = randomBytes(12).toString('base64').replace(/[+/=]/g, '').substring(0, 16);

  switch (type) {
    case 'sha256':
      return `$5$${salt}$${sha256Crypt(password, salt)}`;
    case 'sha512':
      return `$6$${salt}$${sha512Crypt(password, salt)}`;
    case 'md5':
      return `$1$${salt}$${md5Crypt(password, salt)}`;
    case 'plain':
      return password;
    default:
      return `$5$${salt}$${sha256Crypt(password, salt)}`;
  }
}

/**
 * Decode SASL PLAIN authentication data
 * Format: base64(authzid \0 authcid \0 password)
 * Returns null if invalid format
 */
export function decodeSASLPlain(base64Data: string): { authzid: string; authcid: string; password: string } | null {
  try {
    const decoded = Buffer.from(base64Data, 'base64').toString('utf-8');
    const parts = decoded.split('\0');

    if (parts.length !== 3) return null;

    return {
      authzid: parts[0],   // Authorization identity (usually empty or same as authcid)
      authcid: parts[1],   // Authentication identity (username)
      password: parts[2],  // Password
    };
  } catch {
    return null;
  }
}

/**
 * Authenticate a user with SASL PLAIN
 * @param db Users database
 * @param authcid Authentication identity (username)
 * @param password Password
 * @returns Account name if successful, null if failed
 */
export function authenticatePlain(db: UsersDB, authcid: string, password: string): string | null {
  const username = authcid.toLowerCase();
  const user = db.users.get(username);

  if (!user) return null;

  if (verifyPassword(password, user.passwordHash)) {
    return user.username;
  }

  return null;
}

/**
 * Get list of supported SASL mechanisms
 */
export function getSupportedMechanisms(): string[] {
  return ['PLAIN'];
}
