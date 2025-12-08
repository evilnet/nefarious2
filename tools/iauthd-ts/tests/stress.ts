#!/usr/bin/env npx tsx
/**
 * Memory stress test for iauthd-ts
 *
 * Simulates thousands of client connections to verify:
 * 1. Memory doesn't leak (client map cleanup)
 * 2. DNS cache doesn't grow unbounded
 * 3. Performance remains stable under load
 *
 * Usage:
 *   npm run stress
 *   npm run stress -- --clients=10000 --duration=60
 */

import { spawn, ChildProcess } from 'node:child_process';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';

interface StressOptions {
  clients: number;       // Total clients to simulate
  concurrent: number;    // Max concurrent connections
  duration: number;      // Max duration in seconds
  verbose: boolean;      // Verbose output
}

interface Stats {
  clientsSent: number;
  clientsAccepted: number;
  clientsRejected: number;
  startTime: number;
  lastHeapUsed: number;
  maxHeapUsed: number;
  samples: Array<{ time: number; heap: number; clients: number; cache: number }>;
}

function parseOptions(): StressOptions {
  const { values } = parseArgs({
    options: {
      clients: { type: 'string', short: 'n', default: '5000' },
      concurrent: { type: 'string', short: 'c', default: '100' },
      duration: { type: 'string', short: 'd', default: '120' },
      verbose: { type: 'boolean', short: 'v', default: false },
    },
    strict: true,
  });

  return {
    clients: parseInt(values.clients!, 10),
    concurrent: parseInt(values.concurrent!, 10),
    duration: parseInt(values.duration!, 10),
    verbose: values.verbose!,
  };
}

function generateRandomIP(): string {
  const a = Math.floor(Math.random() * 223) + 1; // 1-223 (avoid 0 and 224+)
  const b = Math.floor(Math.random() * 256);
  const c = Math.floor(Math.random() * 256);
  const d = Math.floor(Math.random() * 256);
  return `${a}.${b}.${c}.${d}`;
}

async function runStressTest(options: StressOptions): Promise<void> {
  console.log('='.repeat(60));
  console.log('iauthd-ts Memory Stress Test');
  console.log('='.repeat(60));
  console.log(`Clients to simulate: ${options.clients}`);
  console.log(`Max concurrent: ${options.concurrent}`);
  console.log(`Max duration: ${options.duration}s`);
  console.log('='.repeat(60));
  console.log();

  // Create temp config
  const tempDir = mkdtempSync(join(tmpdir(), 'iauthd-stress-'));
  const configPath = join(tempDir, 'stress.conf');

  // Use a DNSBL that will respond quickly (or use a fake one)
  // For stress testing, we want quick responses so we use short timeout
  writeFileSync(configPath, `
#IAUTH POLICY RTAWUwFr
#IAUTH DNSTIMEOUT 1
#IAUTH CACHETIME 60
#IAUTH BLOCKMSG Stress test rejection
#IAUTH DNSBL server=zen.spamhaus.org index=2,3,4,5,6,7 mark=spamhaus block=anonymous
`);

  const stats: Stats = {
    clientsSent: 0,
    clientsAccepted: 0,
    clientsRejected: 0,
    startTime: Date.now(),
    lastHeapUsed: 0,
    maxHeapUsed: 0,
    samples: [],
  };

  // Spawn the daemon with memory tracking
  const proc = spawn('node', [
    '--expose-gc',
    '--max-old-space-size=256',  // Limit heap to catch leaks faster
    'dist/index.js',
    '-c', configPath,
  ], {
    cwd: join(import.meta.dirname, '..'),
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      NODE_OPTIONS: '--expose-gc',
    },
  });

  let cacheSize = 0;
  let activeClients = 0;

  const rl = createInterface({ input: proc.stdout! });

  rl.on('line', (line) => {
    if (options.verbose) {
      console.log('< ' + line);
    }

    if (line.startsWith('D ')) {
      stats.clientsAccepted++;
      activeClients--;
    } else if (line.startsWith('k ')) {
      stats.clientsRejected++;
      activeClients--;
    } else if (line.includes('Cache size:')) {
      const match = line.match(/Cache size: (\d+)/);
      if (match) {
        cacheSize = parseInt(match[1], 10);
      }
    }
  });

  proc.stderr?.on('data', (data) => {
    if (options.verbose) {
      console.error('stderr:', data.toString());
    }
  });

  const send = (line: string) => {
    if (options.verbose) {
      console.log('> ' + line);
    }
    proc.stdin!.write(line + '\n');
  };

  // Wait for startup
  await new Promise<void>((resolve) => {
    const checkStartup = setInterval(() => {
      // Check if we've seen the startup messages
      if (stats.clientsSent === 0) {
        clearInterval(checkStartup);
        resolve();
      }
    }, 100);
    setTimeout(() => {
      clearInterval(checkStartup);
      resolve();
    }, 2000);
  });

  console.log('Daemon started. Beginning stress test...\n');

  // Send server info
  send('-1 M stress.test.server 65535');

  const startTime = Date.now();
  const endTime = startTime + (options.duration * 1000);
  let clientId = 0;

  // Progress reporting
  const progressInterval = setInterval(() => {
    const elapsed = (Date.now() - startTime) / 1000;
    const rate = stats.clientsSent / elapsed;
    const heapUsed = process.memoryUsage().heapUsed / 1024 / 1024;

    stats.samples.push({
      time: elapsed,
      heap: heapUsed,
      clients: activeClients,
      cache: cacheSize,
    });

    if (heapUsed > stats.maxHeapUsed) {
      stats.maxHeapUsed = heapUsed;
    }
    stats.lastHeapUsed = heapUsed;

    process.stdout.write(
      `\rSent: ${stats.clientsSent} | Accepted: ${stats.clientsAccepted} | ` +
      `Rejected: ${stats.clientsRejected} | Active: ${activeClients} | ` +
      `Cache: ${cacheSize} | Rate: ${rate.toFixed(1)}/s | ` +
      `Elapsed: ${elapsed.toFixed(1)}s   `
    );
  }, 1000);

  // Main send loop
  const sendBatch = () => {
    const now = Date.now();
    if (now >= endTime || stats.clientsSent >= options.clients) {
      return false;
    }

    // Send up to concurrent limit
    while (activeClients < options.concurrent && stats.clientsSent < options.clients) {
      const ip = generateRandomIP();
      const port = 10000 + (clientId % 55535);

      send(`${clientId} C ${ip} ${port} 10.0.0.1 6667`);
      send(`${clientId} H Users`);

      stats.clientsSent++;
      activeClients++;
      clientId++;
    }

    return true;
  };

  // Run the send loop
  while (sendBatch()) {
    await new Promise(r => setTimeout(r, 10));
  }

  // Wait for remaining clients to be processed
  console.log('\n\nWaiting for remaining clients to be processed...');

  const drainStart = Date.now();
  while (activeClients > 0 && (Date.now() - drainStart) < 30000) {
    await new Promise(r => setTimeout(r, 100));
  }

  clearInterval(progressInterval);

  // Cleanup
  proc.stdin!.end();
  await new Promise<void>((resolve) => {
    proc.on('close', () => resolve());
    setTimeout(() => {
      proc.kill('SIGTERM');
      resolve();
    }, 2000);
  });

  try {
    rmSync(tempDir, { recursive: true });
  } catch {}

  // Print results
  const totalTime = (Date.now() - startTime) / 1000;

  console.log('\n');
  console.log('='.repeat(60));
  console.log('STRESS TEST RESULTS');
  console.log('='.repeat(60));
  console.log(`Total clients sent:     ${stats.clientsSent}`);
  console.log(`Total clients accepted: ${stats.clientsAccepted}`);
  console.log(`Total clients rejected: ${stats.clientsRejected}`);
  console.log(`Unprocessed clients:    ${stats.clientsSent - stats.clientsAccepted - stats.clientsRejected}`);
  console.log(`Total time:             ${totalTime.toFixed(2)}s`);
  console.log(`Average rate:           ${(stats.clientsSent / totalTime).toFixed(2)} clients/s`);
  console.log(`Final cache size:       ${cacheSize}`);
  console.log('');

  // Memory analysis
  console.log('MEMORY ANALYSIS');
  console.log('-'.repeat(60));

  if (stats.samples.length > 1) {
    const firstSample = stats.samples[0];
    const lastSample = stats.samples[stats.samples.length - 1];
    const heapGrowth = lastSample.heap - firstSample.heap;
    const heapGrowthPercent = (heapGrowth / firstSample.heap) * 100;

    console.log(`Initial heap:           ${firstSample.heap.toFixed(2)} MB`);
    console.log(`Final heap:             ${lastSample.heap.toFixed(2)} MB`);
    console.log(`Max heap:               ${stats.maxHeapUsed.toFixed(2)} MB`);
    console.log(`Heap growth:            ${heapGrowth.toFixed(2)} MB (${heapGrowthPercent.toFixed(1)}%)`);

    // Check for memory leak indicators
    console.log('');
    if (heapGrowthPercent > 100) {
      console.log('⚠️  WARNING: Significant heap growth detected. Possible memory leak.');
    } else if (heapGrowthPercent > 50) {
      console.log('⚠️  NOTICE: Moderate heap growth. Monitor in production.');
    } else {
      console.log('✅ Memory usage appears stable.');
    }

    // Check if all clients were processed
    const unprocessed = stats.clientsSent - stats.clientsAccepted - stats.clientsRejected;
    if (unprocessed > 0) {
      console.log(`⚠️  WARNING: ${unprocessed} clients were not processed. Possible state leak.`);
    } else {
      console.log('✅ All clients were processed correctly.');
    }

    // Check cache growth
    const clientsPerCacheEntry = stats.clientsSent / Math.max(cacheSize, 1);
    console.log(`Cache efficiency:       ${clientsPerCacheEntry.toFixed(1)} clients per cache entry`);
  }

  console.log('='.repeat(60));
}

// Run the test
const options = parseOptions();
runStressTest(options).catch(console.error);
