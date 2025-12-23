/**
 * Tests for auth configuration parsing
 */

import { describe, it, expect } from 'vitest';
import { parseAuthConfig, convertSASLDB } from '../../src/auth/config.js';

describe('Auth Config Parsing', () => {
  describe('parseAuthConfig', () => {
    it('should return null if provider is missing', () => {
      const result = parseAuthConfig('path=/etc/users');
      expect(result).toBeNull();
    });

    it('should parse file provider config', () => {
      const result = parseAuthConfig('provider=file path=/etc/iauth/users');
      expect(result).toEqual({
        provider: 'file',
        path: '/etc/iauth/users',
        priority: undefined,
      });
    });

    it('should parse file provider with priority', () => {
      const result = parseAuthConfig('provider=file path=/etc/users priority=50');
      expect(result).toEqual({
        provider: 'file',
        path: '/etc/users',
        priority: 50,
      });
    });

    it('should return null for file provider without path', () => {
      const result = parseAuthConfig('provider=file');
      expect(result).toBeNull();
    });

    it('should parse LDAP direct bind config', () => {
      const result = parseAuthConfig(
        'provider=ldap uri=ldap://ldap.example.com:389 mode=direct userdn=uid=%s,ou=users,dc=example,dc=com'
      );
      expect(result).toEqual({
        provider: 'ldap',
        uri: 'ldap://ldap.example.com:389',
        mode: 'direct',
        userdn: 'uid=%s,ou=users,dc=example,dc=com',
        priority: undefined,
        timeout: undefined,
        accountattr: undefined,
      });
    });

    it('should parse LDAP search mode config', () => {
      const result = parseAuthConfig(
        'provider=ldap uri=ldaps://ldap.example.com:636 mode=search ' +
          'basedn=ou=users,dc=example,dc=com ' +
          'binddn=cn=admin,dc=example,dc=com ' +
          'bindpass=secret ' +
          'userfilter=(uid=%s)'
      );
      expect(result).toEqual({
        provider: 'ldap',
        uri: 'ldaps://ldap.example.com:636',
        mode: 'search',
        basedn: 'ou=users,dc=example,dc=com',
        binddn: 'cn=admin,dc=example,dc=com',
        bindpass: 'secret',
        userfilter: '(uid=%s)',
        groupdn: undefined,
        priority: undefined,
        timeout: undefined,
        accountattr: undefined,
      });
    });

    it('should parse LDAP config with groupdn', () => {
      const result = parseAuthConfig(
        'provider=ldap uri=ldaps://ldap.example.com mode=search ' +
          'basedn=ou=users,dc=example,dc=com ' +
          'binddn=cn=admin,dc=example,dc=com ' +
          'bindpass=secret ' +
          'userfilter=(uid=%s) ' +
          'groupdn=cn=ircusers,ou=groups,dc=example,dc=com'
      );
      expect(result?.provider).toBe('ldap');
      if (result?.provider === 'ldap') {
        expect(result.groupdn).toBe('cn=ircusers,ou=groups,dc=example,dc=com');
      }
    });

    it('should parse LDAP config with timeout and priority', () => {
      const result = parseAuthConfig(
        'provider=ldap uri=ldap://server mode=direct userdn=uid=%s,dc=test timeout=10000 priority=25'
      );
      expect(result?.provider).toBe('ldap');
      if (result?.provider === 'ldap') {
        expect(result.timeout).toBe(10000);
        expect(result.priority).toBe(25);
      }
    });

    it('should return null for LDAP without uri', () => {
      const result = parseAuthConfig('provider=ldap mode=direct');
      expect(result).toBeNull();
    });

    it('should return null for LDAP without mode', () => {
      const result = parseAuthConfig('provider=ldap uri=ldap://server');
      expect(result).toBeNull();
    });

    it('should return null for unknown provider', () => {
      const result = parseAuthConfig('provider=unknown');
      expect(result).toBeNull();
    });

    it('should handle quoted values with spaces', () => {
      const result = parseAuthConfig('provider=file path="/path/with spaces/users"');
      expect(result).toEqual({
        provider: 'file',
        path: '/path/with spaces/users',
        priority: undefined,
      });
    });

    it('should handle single-quoted values', () => {
      const result = parseAuthConfig("provider=file path='/path/with spaces/users'");
      expect(result).toEqual({
        provider: 'file',
        path: '/path/with spaces/users',
        priority: undefined,
      });
    });

    it('should parse Keycloak config', () => {
      const result = parseAuthConfig(
        'provider=keycloak url=https://keycloak.example.com realm=myrealm clientid=irc-client'
      );
      expect(result).toEqual({
        provider: 'keycloak',
        url: 'https://keycloak.example.com',
        realm: 'myrealm',
        clientid: 'irc-client',
        clientsecret: undefined,
        accountattr: undefined,
        timeout: undefined,
        priority: undefined,
      });
    });

    it('should parse Keycloak config with clientsecret', () => {
      const result = parseAuthConfig(
        'provider=keycloak url=https://keycloak.example.com realm=myrealm clientid=irc-client clientsecret=mysecret'
      );
      expect(result?.provider).toBe('keycloak');
      if (result?.provider === 'keycloak') {
        expect(result.clientsecret).toBe('mysecret');
      }
    });

    it('should parse Keycloak config with all options', () => {
      const result = parseAuthConfig(
        'provider=keycloak url=https://keycloak.example.com realm=myrealm clientid=irc-client ' +
          'clientsecret=mysecret accountattr=irc_nick timeout=10000 priority=25'
      );
      expect(result?.provider).toBe('keycloak');
      if (result?.provider === 'keycloak') {
        expect(result.url).toBe('https://keycloak.example.com');
        expect(result.realm).toBe('myrealm');
        expect(result.clientid).toBe('irc-client');
        expect(result.clientsecret).toBe('mysecret');
        expect(result.accountattr).toBe('irc_nick');
        expect(result.timeout).toBe(10000);
        expect(result.priority).toBe(25);
      }
    });

    it('should return null for Keycloak without url', () => {
      const result = parseAuthConfig('provider=keycloak realm=test clientid=test');
      expect(result).toBeNull();
    });

    it('should return null for Keycloak without realm', () => {
      const result = parseAuthConfig('provider=keycloak url=https://kc.example.com clientid=test');
      expect(result).toBeNull();
    });

    it('should return null for Keycloak without clientid', () => {
      const result = parseAuthConfig('provider=keycloak url=https://kc.example.com realm=test');
      expect(result).toBeNull();
    });
  });

  describe('convertSASLDB', () => {
    it('should convert SASLDB path to file provider config', () => {
      const result = convertSASLDB('/etc/iauth/users');
      expect(result).toEqual({
        provider: 'file',
        path: '/etc/iauth/users',
        priority: 100,
      });
    });
  });
});
