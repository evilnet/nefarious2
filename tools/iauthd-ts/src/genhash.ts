#!/usr/bin/env node
/**
 * Password hash generator for iauthd-ts SASL users file
 *
 * Usage: npx tsx src/genhash.ts <password> [type]
 *
 * Types:
 *   sha256 (default) - SHA-256 crypt format ($5$)
 *   sha512           - SHA-512 crypt format ($6$)
 *   md5              - MD5 crypt format ($1$)
 */

import { generateHash } from './sasl.js';

const args = process.argv.slice(2);

if (args.length === 0) {
  console.log('Usage: npx tsx src/genhash.ts <password> [type]');
  console.log('');
  console.log('Types:');
  console.log('  sha256 (default) - SHA-256 crypt format ($5$)');
  console.log('  sha512           - SHA-512 crypt format ($6$)');
  console.log('  md5              - MD5 crypt format ($1$)');
  console.log('');
  console.log('Example:');
  console.log('  npx tsx src/genhash.ts mypassword sha256');
  process.exit(1);
}

const password = args[0];
const type = (args[1] || 'sha256') as 'sha256' | 'sha512' | 'md5';

if (!['sha256', 'sha512', 'md5'].includes(type)) {
  console.error(`Invalid hash type: ${type}`);
  console.error('Valid types: sha256, sha512, md5');
  process.exit(1);
}

const hash = generateHash(password, type);
console.log(hash);
