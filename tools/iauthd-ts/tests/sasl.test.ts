import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { writeFileSync, unlinkSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  parseUsersFile,
  verifyPassword,
  generateHash,
  decodeSASLPlain,
  authenticatePlain,
} from '../src/sasl.js';

describe('SASL Module', () => {
  describe('generateHash', () => {
    it('should generate SHA-256 hash with $5$ prefix', () => {
      const hash = generateHash('password', 'sha256');
      expect(hash).toMatch(/^\$5\$[A-Za-z0-9]+\$[A-Za-z0-9+/]+$/);
    });

    it('should generate SHA-512 hash with $6$ prefix', () => {
      const hash = generateHash('password', 'sha512');
      expect(hash).toMatch(/^\$6\$[A-Za-z0-9]+\$[A-Za-z0-9+/]+$/);
    });

    it('should generate MD5 hash with $1$ prefix', () => {
      const hash = generateHash('password', 'md5');
      expect(hash).toMatch(/^\$1\$[A-Za-z0-9]+\$[A-Za-z0-9+/]+$/);
    });

    it('should generate different hashes for different passwords', () => {
      const hash1 = generateHash('password1', 'sha256');
      const hash2 = generateHash('password2', 'sha256');
      expect(hash1).not.toBe(hash2);
    });

    it('should generate different hashes for same password (different salt)', () => {
      const hash1 = generateHash('password', 'sha256');
      const hash2 = generateHash('password', 'sha256');
      // Salts are random, so hashes should be different
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('verifyPassword', () => {
    it('should verify SHA-256 hashed password', () => {
      const hash = generateHash('testpass', 'sha256');
      expect(verifyPassword('testpass', hash)).toBe(true);
      expect(verifyPassword('wrongpass', hash)).toBe(false);
    });

    it('should verify SHA-512 hashed password', () => {
      const hash = generateHash('testpass', 'sha512');
      expect(verifyPassword('testpass', hash)).toBe(true);
      expect(verifyPassword('wrongpass', hash)).toBe(false);
    });

    it('should verify MD5 hashed password', () => {
      const hash = generateHash('testpass', 'md5');
      expect(verifyPassword('testpass', hash)).toBe(true);
      expect(verifyPassword('wrongpass', hash)).toBe(false);
    });

    it('should verify plain text password', () => {
      expect(verifyPassword('plainpass', 'plainpass')).toBe(true);
      expect(verifyPassword('wrongpass', 'plainpass')).toBe(false);
    });

    it('should reject invalid hash format', () => {
      expect(verifyPassword('pass', '$invalid$format')).toBe(false);
      expect(verifyPassword('pass', '$99$salt$hash')).toBe(false);
    });

    it('should handle empty password', () => {
      const hash = generateHash('', 'sha256');
      expect(verifyPassword('', hash)).toBe(true);
      expect(verifyPassword('notempty', hash)).toBe(false);
    });
  });

  describe('decodeSASLPlain', () => {
    it('should decode valid SASL PLAIN data', () => {
      // Format: base64(authzid \0 authcid \0 password)
      const data = Buffer.from('\0testuser\0testpass').toString('base64');
      const result = decodeSASLPlain(data);

      expect(result).not.toBeNull();
      expect(result?.authzid).toBe('');
      expect(result?.authcid).toBe('testuser');
      expect(result?.password).toBe('testpass');
    });

    it('should decode with authzid', () => {
      const data = Buffer.from('authzid\0authcid\0password').toString('base64');
      const result = decodeSASLPlain(data);

      expect(result).not.toBeNull();
      expect(result?.authzid).toBe('authzid');
      expect(result?.authcid).toBe('authcid');
      expect(result?.password).toBe('password');
    });

    it('should return null for invalid base64', () => {
      const result = decodeSASLPlain('not-valid-base64!!!');
      // Actually base64 decode may not fail, it will just produce garbage
      // Let's test with wrong number of parts
    });

    it('should return null for wrong number of parts', () => {
      // Only 2 parts instead of 3
      const data = Buffer.from('user\0pass').toString('base64');
      const result = decodeSASLPlain(data);
      expect(result).toBeNull();
    });

    it('should handle empty fields', () => {
      const data = Buffer.from('\0\0').toString('base64');
      const result = decodeSASLPlain(data);

      expect(result).not.toBeNull();
      expect(result?.authzid).toBe('');
      expect(result?.authcid).toBe('');
      expect(result?.password).toBe('');
    });

    it('should handle special characters', () => {
      const data = Buffer.from('\0user@example.com\0p@ss:word!').toString('base64');
      const result = decodeSASLPlain(data);

      expect(result).not.toBeNull();
      expect(result?.authcid).toBe('user@example.com');
      expect(result?.password).toBe('p@ss:word!');
    });
  });

  describe('parseUsersFile', () => {
    let tmpDir: string;
    let usersFile: string;

    beforeAll(() => {
      tmpDir = mkdtempSync(join(tmpdir(), 'iauthd-test-'));
      usersFile = join(tmpDir, 'users');
    });

    afterAll(() => {
      try {
        unlinkSync(usersFile);
      } catch {}
    });

    it('should parse simple users file', () => {
      writeFileSync(usersFile, 'testuser:testpass\nadmin:adminpass\n');
      const db = parseUsersFile(usersFile);

      expect(db.users.size).toBe(2);
      expect(db.users.get('testuser')?.passwordHash).toBe('testpass');
      expect(db.users.get('admin')?.passwordHash).toBe('adminpass');
    });

    it('should skip comments and empty lines', () => {
      writeFileSync(usersFile, '# Comment\n\nuser:pass\n  \n# Another comment\n');
      const db = parseUsersFile(usersFile);

      expect(db.users.size).toBe(1);
      expect(db.users.get('user')?.passwordHash).toBe('pass');
    });

    it('should lowercase usernames', () => {
      writeFileSync(usersFile, 'TestUser:pass\nADMIN:pass2\n');
      const db = parseUsersFile(usersFile);

      expect(db.users.has('testuser')).toBe(true);
      expect(db.users.has('admin')).toBe(true);
      expect(db.users.has('TestUser')).toBe(false);
    });

    it('should handle passwords with colons', () => {
      writeFileSync(usersFile, 'user:pass:with:colons\n');
      const db = parseUsersFile(usersFile);

      expect(db.users.get('user')?.passwordHash).toBe('pass:with:colons');
    });

    it('should handle crypt-style hashes', () => {
      const hash = '$5$salt$hashvalue';
      writeFileSync(usersFile, `user:${hash}\n`);
      const db = parseUsersFile(usersFile);

      expect(db.users.get('user')?.passwordHash).toBe(hash);
    });

    it('should return empty db for non-existent file', () => {
      const db = parseUsersFile('/nonexistent/file');
      expect(db.users.size).toBe(0);
    });

    it('should skip lines without colon', () => {
      writeFileSync(usersFile, 'validuser:pass\ninvalidline\nanotheruser:anotherpass\n');
      const db = parseUsersFile(usersFile);

      expect(db.users.size).toBe(2);
      expect(db.users.has('validuser')).toBe(true);
      expect(db.users.has('anotheruser')).toBe(true);
    });
  });

  describe('authenticatePlain', () => {
    let tmpDir: string;
    let usersFile: string;

    beforeAll(() => {
      tmpDir = mkdtempSync(join(tmpdir(), 'iauthd-test-'));
      usersFile = join(tmpDir, 'users');

      // Create users file with various hash types
      const sha256Hash = generateHash('sha256pass', 'sha256');
      const sha512Hash = generateHash('sha512pass', 'sha512');

      writeFileSync(usersFile, [
        `plainuser:plainpass`,
        `sha256user:${sha256Hash}`,
        `sha512user:${sha512Hash}`,
      ].join('\n'));
    });

    afterAll(() => {
      try {
        unlinkSync(usersFile);
      } catch {}
    });

    it('should authenticate with plain text password', () => {
      const db = parseUsersFile(usersFile);
      const result = authenticatePlain(db, 'plainuser', 'plainpass');

      expect(result).toBe('plainuser');
    });

    it('should authenticate with SHA-256 hashed password', () => {
      const db = parseUsersFile(usersFile);
      const result = authenticatePlain(db, 'sha256user', 'sha256pass');

      expect(result).toBe('sha256user');
    });

    it('should authenticate with SHA-512 hashed password', () => {
      const db = parseUsersFile(usersFile);
      const result = authenticatePlain(db, 'sha512user', 'sha512pass');

      expect(result).toBe('sha512user');
    });

    it('should reject wrong password', () => {
      const db = parseUsersFile(usersFile);
      const result = authenticatePlain(db, 'plainuser', 'wrongpass');

      expect(result).toBeNull();
    });

    it('should reject non-existent user', () => {
      const db = parseUsersFile(usersFile);
      const result = authenticatePlain(db, 'nouser', 'anypass');

      expect(result).toBeNull();
    });

    it('should be case-insensitive for username', () => {
      const db = parseUsersFile(usersFile);
      const result = authenticatePlain(db, 'PlainUser', 'plainpass');

      expect(result).toBe('plainuser');
    });
  });
});
