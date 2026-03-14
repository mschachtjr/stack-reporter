#!/usr/bin/env node
/**
 * 312 Elements — Dependency Security Monitor
 *
 * A zero-dependency build hook that reports your project's dependencies
 * to 312 Elements for nightly CVE scanning. Runs before your build command.
 *
 * Setup:
 *   npm install --save-dev @312npm/stack-reporter
 *   Then add to your build: "build": "stack-reporter && next build"
 *
 * Domain detection priority:
 *   1. BEACON_DOMAIN env var (explicit override)
 *   2. VERCEL_PROJECT_PRODUCTION_URL (Vercel auto-sets this)
 *   3. "homepage" field in package.json (extract hostname)
 *
 * This script ALWAYS exits 0. It will never break your build.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');

const API_URL = 'https://seo.312elements.com/api/beacon/report';

// ============================================================================
// Domain Detection
// ============================================================================

function detectDomain() {
  // 1. Explicit env var
  if (process.env.BEACON_DOMAIN) {
    return process.env.BEACON_DOMAIN;
  }

  // 2. Vercel production URL
  if (process.env.VERCEL_PROJECT_PRODUCTION_URL) {
    return process.env.VERCEL_PROJECT_PRODUCTION_URL.replace(/^https?:\/\//, '');
  }

  // 3. package.json homepage
  try {
    const pkgPath = path.join(process.cwd(), 'package.json');
    if (fs.existsSync(pkgPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      if (pkg.homepage) {
        try {
          const url = new URL(pkg.homepage);
          return url.hostname;
        } catch {
          // homepage might be a bare domain
          return pkg.homepage.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
        }
      }
    }
  } catch {
    // Ignore parse errors
  }

  return null;
}

// ============================================================================
// Lock File Detection & Parsing
// ============================================================================

function detectLockFile() {
  const cwd = process.cwd();
  const candidates = [
    { file: 'package-lock.json', type: 'npm' },
    { file: 'yarn.lock', type: 'yarn' },
    { file: 'pnpm-lock.yaml', type: 'pnpm' },
  ];

  for (const candidate of candidates) {
    const fullPath = path.join(cwd, candidate.file);
    if (fs.existsSync(fullPath)) {
      return { path: fullPath, type: candidate.type };
    }
  }

  return null;
}

function parseNpmLockFile(filePath) {
  const content = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const deps = [];

  // lockfileVersion 2 and 3 use "packages"
  if (content.packages) {
    for (const [key, value] of Object.entries(content.packages)) {
      // Skip root package
      if (key === '') continue;
      // Skip nested node_modules (transitive deps inside other deps)
      // We want top-level packages only: "node_modules/<name>" or "node_modules/@scope/name"
      const segments = key.split('node_modules/');
      if (segments.length > 2) continue;

      const pkgName = segments[segments.length - 1];
      if (!pkgName || !value.version) continue;

      deps.push({
        name: pkgName,
        version: value.version,
        ecosystem: 'npm',
        dev: !!value.dev,
      });
    }
    return deps;
  }

  // lockfileVersion 1 uses "dependencies"
  if (content.dependencies) {
    function walkV1(depObj, isDev) {
      for (const [name, info] of Object.entries(depObj)) {
        if (info.version) {
          deps.push({
            name,
            version: info.version,
            ecosystem: 'npm',
            dev: isDev || !!info.dev,
          });
        }
        // v1 can have nested dependencies
        if (info.dependencies) {
          walkV1(info.dependencies, isDev || !!info.dev);
        }
      }
    }
    walkV1(content.dependencies, false);
    return deps;
  }

  return deps;
}

function parseYarnLockFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const deps = [];
  const seen = new Set();

  // Yarn classic format: block starts with non-indented line ending in ":"
  // version is indented as '  version "x.y.z"'
  const lines = content.split('\n');
  let currentPkg = null;

  for (const line of lines) {
    // Skip comments and empty lines
    if (line.startsWith('#') || line.trim() === '') {
      currentPkg = null;
      continue;
    }

    // New package block (non-indented, ends with :)
    if (!line.startsWith(' ') && line.endsWith(':')) {
      // Extract package name from header like '"@babel/core@^7.0.0":'
      // or 'accepts@~1.3.8:'
      const header = line.replace(/:$/, '').replace(/"/g, '');
      // Take first entry if multiple (comma-separated)
      const firstEntry = header.split(',')[0].trim();
      // Package name is everything before the last @
      const atIdx = firstEntry.lastIndexOf('@');
      if (atIdx > 0) {
        currentPkg = firstEntry.substring(0, atIdx);
      }
      continue;
    }

    // Version line
    if (currentPkg && line.match(/^\s+version\s+"?([^"]+)"?/)) {
      const match = line.match(/^\s+version\s+"?([^"]+)"?/);
      if (match && !seen.has(currentPkg)) {
        seen.add(currentPkg);
        deps.push({
          name: currentPkg,
          version: match[1],
          ecosystem: 'npm',
          dev: false, // yarn.lock doesn't distinguish dev deps
        });
      }
      currentPkg = null;
    }
  }

  return deps;
}

/**
 * Get the set of direct dependency names from package.json.
 * Only these packages are actionable by the user — transitive deps
 * are controlled by upstream maintainers and shouldn't trigger alerts.
 */
function getDirectDependencyNames() {
  try {
    const pkgPath = path.join(process.cwd(), 'package.json');
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    return new Set([
      ...Object.keys(pkg.dependencies || {}),
      ...Object.keys(pkg.devDependencies || {}),
    ]);
  } catch {
    return null; // If package.json can't be read, skip filtering
  }
}

function parseLockFile(lockFile) {
  let deps;
  switch (lockFile.type) {
    case 'npm':
      deps = parseNpmLockFile(lockFile.path);
      break;
    case 'yarn':
      deps = parseYarnLockFile(lockFile.path);
      break;
    case 'pnpm':
      console.log('[beacon] pnpm-lock.yaml detected but not yet supported. Skipping.');
      return [];
    default:
      return [];
  }

  // Filter to direct dependencies only
  const directNames = getDirectDependencyNames();
  if (directNames) {
    return deps.filter(d => directNames.has(d.name));
  }
  return deps;
}

// ============================================================================
// Framework Config Detection
// ============================================================================

/**
 * Detect the primary framework from package.json dependencies.
 * Returns the framework name or null if no known framework is found.
 */
function detectFramework() {
  try {
    const pkgPath = path.join(process.cwd(), 'package.json');
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    const allDeps = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
    };

    if (allDeps['next']) return 'nextjs';
    if (allDeps['gatsby']) return 'gatsby';
    if (allDeps['@remix-run/react']) return 'remix';
    if (allDeps['nuxt']) return 'nuxt';
    if (allDeps['@angular/core']) return 'angular';

    return null;
  } catch {
    return null;
  }
}

/**
 * Read Next.js config and extract security-relevant flags.
 * Uses regex to parse next.config.{ts,js,mjs} — no TypeScript compiler needed.
 */
function detectNextJsConfig() {
  const cwd = process.cwd();
  const candidates = ['next.config.ts', 'next.config.mjs', 'next.config.js'];
  const config = {};

  for (const filename of candidates) {
    const filePath = path.join(cwd, filename);
    if (!fs.existsSync(filePath)) continue;

    try {
      const content = fs.readFileSync(filePath, 'utf8');

      // Detect PPR: experimental.ppr = 'incremental' | true
      // Matches patterns like:
      //   ppr: 'incremental'
      //   ppr: true
      //   ppr: "incremental"
      if (/\bppr\s*:\s*(?:['"]incremental['"]|true)\b/.test(content)) {
        config.ppr = true;
      } else {
        config.ppr = false;
      }

      // Detect serverActions (enabled by default in Next.js 14+, but can be explicitly set)
      if (/\bserverActions\s*:\s*true\b/.test(content)) {
        config.serverActions = true;
      }

      break; // Found a config file, stop looking
    } catch {
      // Parse error — skip this file
    }
  }

  return Object.keys(config).length > 0 ? config : null;
}

/**
 * Collect runtime config for the detected framework.
 * Returns a config object or null if no framework-specific config is found.
 */
function detectConfig() {
  const framework = detectFramework();
  if (!framework) return null;

  const config = {};

  if (framework === 'nextjs') {
    const nextConfig = detectNextJsConfig();
    if (nextConfig) {
      config.nextjs = nextConfig;
    }
  }

  // Other frameworks can be added here as needed

  return Object.keys(config).length > 0 ? config : null;
}

// ============================================================================
// API Report
// ============================================================================

function postReport(domain, dependencies, config) {
  return new Promise((resolve) => {
    const payload = { domain, dependencies };
    if (config) payload.config = config;
    const body = JSON.stringify(payload);
    const url = new URL(API_URL);

    const options = {
      hostname: url.hostname,
      port: 443,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
      timeout: 15000,
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          resolve({ status: res.statusCode, body: parsed });
        } catch {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });

    req.on('error', (err) => {
      resolve({ status: 0, error: err.message });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ status: 0, error: 'Request timed out' });
    });

    req.write(body);
    req.end();
  });
}

// ============================================================================
// Main
// ============================================================================

async function main() {
  // Detect domain
  const domain = detectDomain();
  if (!domain) {
    console.log('[beacon] Could not detect site domain. Set BEACON_DOMAIN env var or add "homepage" to package.json.');
    return;
  }

  // Detect and parse lock file
  const lockFile = detectLockFile();
  if (!lockFile) {
    console.log('[beacon] No lock file found (package-lock.json, yarn.lock, or pnpm-lock.yaml).');
    return;
  }

  let deps;
  try {
    deps = parseLockFile(lockFile);
  } catch (err) {
    console.log(`[beacon] Failed to parse ${path.basename(lockFile.path)}: ${err.message}`);
    return;
  }

  if (deps.length === 0) {
    console.log(`[beacon] No dependencies found in ${path.basename(lockFile.path)}.`);
    return;
  }

  // Detect framework config (for config-based vuln suppression)
  const config = detectConfig();
  if (config) {
    console.log(`[beacon] Detected framework config: ${JSON.stringify(config)}`);
  }

  // Report
  console.log(`[beacon] Reporting ${deps.length} direct dependencies for ${domain}...`);
  const result = await postReport(domain, deps, config);

  if (result.error) {
    console.log(`[beacon] Report failed: ${result.error}. Build continues.`);
  } else if (result.status === 200) {
    console.log(`[beacon] Report accepted: ${deps.length} direct dependencies tracked.`);
  } else if (result.status === 404) {
    console.log(`[beacon] Domain "${domain}" not registered. Sign up at https://seo.312elements.com to enable CVE monitoring.`);
  } else {
    console.log(`[beacon] Unexpected response (${result.status}). Build continues.`);
  }
}

main().catch((err) => {
  console.log(`[beacon] Unexpected error: ${err.message}. Build continues.`);
});
