/**
 * Tests for AuthManager
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { writeFileSync, unlinkSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { AuthManager } from '../../src/auth/manager.js';
import type { AuthProviderConfig } from '../../src/auth/types.js';

describe('AuthManager', () => {
  let tempDir: string;
  let usersFile1: string;
  let usersFile2: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'iauthd-test-'));
    usersFile1 = join(tempDir, 'users1');
    usersFile2 = join(tempDir, 'users2');
  });

  afterEach(() => {
    try {
      unlinkSync(usersFile1);
      unlinkSync(usersFile2);
    } catch {
      // Ignore if files don't exist
    }
  });

  describe('initialization', () => {
    it('should initialize with no providers', async () => {
      const manager = new AuthManager([]);
      await manager.initialize();
      expect(manager.hasProviders()).toBe(false);
      expect(manager.getProviderCount()).toBe(0);
    });

    it('should initialize single file provider', async () => {
      writeFileSync(usersFile1, 'testuser:testpass\n');
      const configs: AuthProviderConfig[] = [
        { provider: 'file', path: usersFile1 },
      ];
      const manager = new AuthManager(configs);
      await manager.initialize();
      expect(manager.hasProviders()).toBe(true);
      expect(manager.getProviderCount()).toBe(1);
    });

    it('should initialize multiple providers', async () => {
      writeFileSync(usersFile1, 'user1:pass1\n');
      writeFileSync(usersFile2, 'user2:pass2\n');
      const configs: AuthProviderConfig[] = [
        { provider: 'file', path: usersFile1, priority: 50 },
        { provider: 'file', path: usersFile2, priority: 100 },
      ];
      const manager = new AuthManager(configs);
      await manager.initialize();
      expect(manager.getProviderCount()).toBe(2);
    });

    it('should sort providers by priority', async () => {
      writeFileSync(usersFile1, 'user1:pass1\n');
      writeFileSync(usersFile2, 'user2:pass2\n');
      const configs: AuthProviderConfig[] = [
        { provider: 'file', path: usersFile1, priority: 100 },
        { provider: 'file', path: usersFile2, priority: 50 },
      ];
      const manager = new AuthManager(configs);
      await manager.initialize();

      const info = manager.getProviderInfo();
      expect(info[0].priority).toBe(50);
      expect(info[1].priority).toBe(100);
    });
  });

  describe('authentication with fallback chain', () => {
    it('should authenticate against first matching provider', async () => {
      writeFileSync(usersFile1, 'user1:pass1\n');
      writeFileSync(usersFile2, 'user2:pass2\n');
      const configs: AuthProviderConfig[] = [
        { provider: 'file', path: usersFile1, priority: 50 },
        { provider: 'file', path: usersFile2, priority: 100 },
      ];
      const manager = new AuthManager(configs);
      await manager.initialize();

      const result = await manager.authenticate('user1', 'pass1');
      expect(result.success).toBe(true);
      expect(result.account).toBe('user1');
    });

    it('should fallback to second provider if first fails', async () => {
      writeFileSync(usersFile1, 'user1:pass1\n');
      writeFileSync(usersFile2, 'user2:pass2\n');
      const configs: AuthProviderConfig[] = [
        { provider: 'file', path: usersFile1, priority: 50 },
        { provider: 'file', path: usersFile2, priority: 100 },
      ];
      const manager = new AuthManager(configs);
      await manager.initialize();

      // user2 is only in the second file
      const result = await manager.authenticate('user2', 'pass2');
      expect(result.success).toBe(true);
      expect(result.account).toBe('user2');
    });

    it('should fail if no provider matches', async () => {
      writeFileSync(usersFile1, 'user1:pass1\n');
      writeFileSync(usersFile2, 'user2:pass2\n');
      const configs: AuthProviderConfig[] = [
        { provider: 'file', path: usersFile1 },
        { provider: 'file', path: usersFile2 },
      ];
      const manager = new AuthManager(configs);
      await manager.initialize();

      const result = await manager.authenticate('unknownuser', 'anypass');
      expect(result.success).toBe(false);
    });

    it('should return error if not initialized', async () => {
      const manager = new AuthManager([]);
      // Don't call initialize

      const result = await manager.authenticate('user', 'pass');
      expect(result.success).toBe(false);
      expect(result.error).toBe('AuthManager not initialized');
    });

    it('should return error if no providers configured', async () => {
      const manager = new AuthManager([]);
      await manager.initialize();

      const result = await manager.authenticate('user', 'pass');
      expect(result.success).toBe(false);
      expect(result.error).toBe('No auth providers configured');
    });
  });

  describe('provider health', () => {
    it('should report healthy providers', async () => {
      writeFileSync(usersFile1, 'user1:pass1\n');
      const configs: AuthProviderConfig[] = [
        { provider: 'file', path: usersFile1 },
      ];
      const manager = new AuthManager(configs);
      await manager.initialize();

      expect(manager.hasHealthyProviders()).toBe(true);
      const info = manager.getProviderInfo();
      expect(info[0].healthy).toBe(true);
    });
  });

  describe('reload', () => {
    it('should reload all providers', async () => {
      writeFileSync(usersFile1, 'user1:pass1\n');
      const configs: AuthProviderConfig[] = [
        { provider: 'file', path: usersFile1 },
      ];
      const manager = new AuthManager(configs);
      await manager.initialize();

      // Modify file
      writeFileSync(usersFile1, 'user1:newpass\n');
      await manager.reload();

      // Should now use new password
      const result = await manager.authenticate('user1', 'newpass');
      expect(result.success).toBe(true);
    });
  });

  describe('shutdown', () => {
    it('should shutdown all providers', async () => {
      writeFileSync(usersFile1, 'user1:pass1\n');
      const configs: AuthProviderConfig[] = [
        { provider: 'file', path: usersFile1 },
      ];
      const manager = new AuthManager(configs);
      await manager.initialize();

      await manager.shutdown();
      expect(manager.hasProviders()).toBe(false);
    });
  });
});
