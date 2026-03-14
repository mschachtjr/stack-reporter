# @312npm/stack-reporter

Reports your project's dependency list to [312 Elements](https://seo.312elements.com) on every build. We scan your dependencies nightly against the [OSV.dev](https://osv.dev) vulnerability database and email you when a package in your stack has a known CVE.

## How it works

This is a two-part system:

1. **This package (client-side):** Reads your lock file and sends package names + versions to the 312 Elements API on each build. No source code, secrets, or environment variables are sent. Always exits 0 — will never break your build.

2. **312 Elements (server-side):** Runs a nightly scan of all reported dependencies against the OSV.dev CVE database. If a vulnerability is found, you receive an email with the affected package, severity, and how to fix it.

This is a companion to `npm audit` — it provides ongoing, passive monitoring so you don't have to remember to check manually.

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
