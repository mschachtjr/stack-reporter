#!/usr/bin/env node
/**
 * Post-install script — prints setup instructions.
 * Does NOT modify package.json automatically (that would be surprising).
 */

'use strict';

console.log('');
console.log('\x1b[36m@312npm/stack-reporter\x1b[0m installed successfully.');
console.log('');
console.log('Add \x1b[33mstack-reporter\x1b[0m to your build command in package.json:');
console.log('');
console.log('  "build": "stack-reporter && <your-existing-build-command>"');
console.log('');
console.log('The script auto-detects your domain and lock file.');
console.log('No environment variables needed.');
console.log('');
