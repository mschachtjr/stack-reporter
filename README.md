# @312npm/stack-reporter

## The problem

`npm audit` only runs when you do — during installs or CI builds. Between deploys, new vulnerabilities are disclosed against packages already in your `node_modules`. Unless someone on your team remembers to check, you won't know until the next build, which could be days or weeks later. By then, the vulnerability may have been public long enough for active exploitation.

## What this does

This package reports your dependency list to [312 Elements](https://seo.312elements.com) once per build. We then scan those dependencies against the [OSV.dev](https://osv.dev) vulnerability database **every night at 3 AM**. If a new CVE is disclosed against any package in your stack, you get an email with the affected package, severity, and fix — whether you deploy that day or not.

Think of it as `npm audit` running on autopilot. Zero config, zero maintenance, zero risk to your build.

## How it works

1. **This package (client-side):** Reads your lock file and sends package names + versions to the 312 Elements API. No source code, secrets, or environment variables are transmitted. Always exits 0 — it will never break your build.

2. **312 Elements (server-side):** Scans all reported dependencies nightly against the OSV.dev CVE database. If a vulnerability is found, you receive an email with the affected package, severity, and remediation steps.

## Install

```bash
npm install --save-dev @312npm/stack-reporter
```

Add to your build command in `package.json`:

```json
{
  "scripts": {
    "build": "stack-reporter && next build"
  }
}
```

## Domain detection

Your site's domain is detected automatically (no config needed):

1. `BEACON_DOMAIN` environment variable (explicit override)
2. `VERCEL_PROJECT_PRODUCTION_URL` (Vercel sets this automatically)
3. `homepage` field in package.json

## What gets sent

On each build, the script sends a JSON payload containing:
- Your site's domain (auto-detected)
- A list of dependencies: package name, version, ecosystem (npm), and dev/prod flag

That's it. No source code, no environment variables, no file contents.

## Lock file support

- `package-lock.json` (npm v1, v2, v3)
- `yarn.lock` (classic)
- `pnpm-lock.yaml` (detected, not yet parsed)

## Requirements

- Node.js >= 16
- A 312 Elements account at [seo.312elements.com](https://seo.312elements.com)
