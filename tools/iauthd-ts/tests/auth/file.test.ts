/**
 * Tests for FileAuthProvider
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { writeFileSync, unlinkSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { FileAuthProvider } from '../../src/auth/providers/file.js';
import { generateHash } from '../../src/sasl.js';

describe('FileAuthProvider', () => {
  let tempDir: string;
  let usersFile: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'iauthd-test-'));
    usersFile = join(tempDir, 'users');
  });

  afterEach(() => {
    try {
      unlinkSync(usersFile);
    } catch {
      // Ignore if file doesn't exist
    }
  });

  describe('initialization', () => {
    it('should initialize with empty users file', async () => {
      writeFileSync(usersFile, '');
      const provider = new FileAuthProvider({ provider: 'file', path: usersFile });
      await provider.initialize();
      expect(provider.isHealthy()).toBe(true);
      expect(provider.getUserCount()).toBe(0);
    });

    it('should initialize with non-existent file', async () => {
      const provider = new FileAuthProvider({
        provider: 'file',
        path: '/nonexistent/path/users',
      });
      await provider.initialize();
      expect(provider.isHealthy()).toBe(true);
      expect(provider.getUserCount()).toBe(0);
    });

    it('should load users from file', async () => {
      writeFileSync(usersFile, 'testuser:plainpassword\nadmin:adminpass\n');
      const provider = new FileAuthProvider({ provider: 'file', path: usersFile });
      await provider.initialize();
      expect(provider.isHealthy()).toBe(true);
      expect(provider.getUserCount()).toBe(2);
    });

    it('should use default priority of 100', async () => {
      writeFileSync(usersFile, '');
      const provider = new FileAuthProvider({ provider: 'file', path: usersFile });
      expect(provider.priority).toBe(100);
    });

    it('should use custom priority', async () => {
      writeFileSync(usersFile, '');
      const provider = new FileAuthProvider({
        provider: 'file',
        path: usersFile,
        priority: 50,
      });
      expect(provider.priority).toBe(50);
    });
  });

  describe('authentication', () => {
    it('should authenticate valid user with plain password', async () => {
      writeFileSync(usersFile, 'testuser:testpass\n');
      const provider = new FileAuthProvider({ provider: 'file', path: usersFile });
      await provider.initialize();

      const result = await provider.authenticate('testuser', 'testpass');
      expect(result.success).toBe(true);
      expect(result.account).toBe('testuser');
    });

    it('should authenticate with SHA-256 hash', async () => {
      const hash = generateHash('secretpass', 'sha256');
      writeFileSync(usersFile, `testuser:${hash}\n`);
      const provider = new FileAuthProvider({ provider: 'file', path: usersFile });
      await provider.initialize();

      const result = await provider.authenticate('testuser', 'secretpass');
      expect(result.success).toBe(true);
      expect(result.account).toBe('testuser');
    });

    it('should authenticate with SHA-512 hash', async () => {
      const hash = generateHash('secretpass', 'sha512');
      writeFileSync(usersFile, `testuser:${hash}\n`);
      const provider = new FileAuthProvider({ provider: 'file', path: usersFile });
      await provider.initialize();

      const result = await provider.authenticate('testuser', 'secretpass');
      expect(result.success).toBe(true);
      expect(result.account).toBe('testuser');
    });

    it('should reject invalid password', async () => {
      writeFileSync(usersFile, 'testuser:correctpass\n');
      const provider = new FileAuthProvider({ provider: 'file', path: usersFile });
      await provider.initialize();

      const result = await provider.authenticate('testuser', 'wrongpass');
      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid credentials');
    });

    it('should reject unknown user', async () => {
      writeFileSync(usersFile, 'testuser:testpass\n');
      const provider = new FileAuthProvider({ provider: 'file', path: usersFile });
      await provider.initialize();

      const result = await provider.authenticate('unknownuser', 'testpass');
      expect(result.success).toBe(false);
    });

    it('should be case-insensitive for usernames', async () => {
      writeFileSync(usersFile, 'TestUser:testpass\n');
      const provider = new FileAuthProvider({ provider: 'file', path: usersFile });
      await provider.initialize();

      const result = await provider.authenticate('TESTUSER', 'testpass');
      expect(result.success).toBe(true);
    });

    it('should return error if not initialized', async () => {
      const provider = new FileAuthProvider({ provider: 'file', path: usersFile });
      // Don't call initialize

      const result = await provider.authenticate('testuser', 'testpass');
      expect(result.success).toBe(false);
      expect(result.error).toBe('Users database not loaded');
    });
  });

  describe('reload', () => {
    it('should reload users file', async () => {
      writeFileSync(usersFile, 'user1:pass1\n');
      const provider = new FileAuthProvider({ provider: 'file', path: usersFile });
      await provider.initialize();
      expect(provider.getUserCount()).toBe(1);

      // Modify file
      writeFileSync(usersFile, 'user1:pass1\nuser2:pass2\n');
      await provider.reload();
      expect(provider.getUserCount()).toBe(2);
    });

    it('should detect file modifications during auth', async () => {
      writeFileSync(usersFile, 'user1:pass1\n');
      const provider = new FileAuthProvider({ provider: 'file', path: usersFile });
      await provider.initialize();

      // File is automatically reloaded if modified
      // Wait a bit to ensure mtime changes
      await new Promise((r) => setTimeout(r, 100));
      writeFileSync(usersFile, 'user1:newpass\n');

      // Auth should use new password after auto-reload
      const result = await provider.authenticate('user1', 'newpass');
      expect(result.success).toBe(true);
    });
  });

  describe('shutdown', () => {
    it('should mark provider as unhealthy after shutdown', async () => {
      writeFileSync(usersFile, 'testuser:testpass\n');
      const provider = new FileAuthProvider({ provider: 'file', path: usersFile });
      await provider.initialize();
      expect(provider.isHealthy()).toBe(true);

      await provider.shutdown();
      expect(provider.isHealthy()).toBe(false);
    });
  });
});
